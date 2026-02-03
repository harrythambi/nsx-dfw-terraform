#!/usr/bin/env python3
"""
NSX-T DFW Configuration Exporter

Extracts existing NSX-T DFW configurations (security groups, services,
security policies/rules) and converts them to YAML format compatible
with the Terraform modules.

Usage:
    python scripts/nsx_exporter.py \
        --host nsx-manager.example.com \
        --username admin \
        --password 'password' \
        --output data/

    # With options
    python scripts/nsx_exporter.py \
        --host nsx-manager.example.com \
        --username admin \
        --password 'password' \
        --output data/ \
        --domain default \
        --skip-predefined-services \
        --include-disabled-rules
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, quote_plus

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("ERROR: requests is required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

# Disable SSL warnings for self-signed certificates
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NSXExporter:
    """Exports NSX-T DFW configurations to YAML format."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "default",
        verify_ssl: bool = False,
    ):
        """Initialize the NSX exporter.

        Args:
            host: NSX Manager hostname or IP
            username: NSX API username
            password: NSX API password
            domain: NSX domain (default: "default")
            verify_ssl: Whether to verify SSL certificates
        """
        self.host = host
        self.base_url = f"https://{host}"
        self.username = username
        self.password = password
        self.domain = domain
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self._xsrf_token: Optional[str] = None

        # Caches for path resolution
        self._group_cache: Dict[str, dict] = {}
        self._service_cache: Dict[str, dict] = {}
        self._vm_cache: Dict[str, str] = {}  # bios_id -> display_name
        self._segment_cache: Dict[str, str] = {}  # path -> display_name

        # Authenticate and establish session
        self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate with NSX Manager.

        Tries session-based authentication first, falls back to basic auth.
        """
        # Try session-based authentication first
        try:
            self._session_auth()
            return
        except requests.exceptions.HTTPError as e:
            print(f"  Session auth failed ({e}), trying basic auth...")

        # Fall back to basic authentication
        self._basic_auth()

    def _session_auth(self) -> None:
        """Authenticate using session-based authentication."""
        url = f"{self.base_url}/api/session/create"

        # URL-encode the credentials and send as form data
        data = f"j_username={quote_plus(self.username)}&j_password={quote_plus(self.password)}"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        response = self.session.post(url, data=data, headers=headers)
        response.raise_for_status()

        # Extract x-xsrf-token from response headers
        self._xsrf_token = response.headers.get("x-xsrf-token")
        if not self._xsrf_token:
            raise ValueError("Failed to get x-xsrf-token from session creation response")

    def _basic_auth(self) -> None:
        """Configure basic authentication for all requests using Base64 encoding."""
        # Encode credentials as Base64
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode("ascii")).decode("utf-8")
        self.session.headers["Authorization"] = f"Basic {encoded}"

    def _api_get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """Make a GET request to the NSX API.

        Args:
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            JSON response as dictionary
        """
        url = urljoin(self.base_url, endpoint)
        headers = {}
        if self._xsrf_token:
            headers["x-xsrf-token"] = self._xsrf_token
        response = self.session.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()

    def _get_all_paginated(self, endpoint: str, result_key: str = "results") -> list:
        """Get all results from a paginated API endpoint.

        Args:
            endpoint: API endpoint path
            result_key: Key containing results in response

        Returns:
            List of all results across all pages
        """
        all_results = []
        cursor = None

        while True:
            params = {}
            if cursor:
                params["cursor"] = cursor

            response = self._api_get(endpoint, params)
            results = response.get(result_key, [])
            all_results.extend(results)

            cursor = response.get("cursor")
            if not cursor:
                break

        return all_results

    # =========================================================================
    # API Methods
    # =========================================================================

    def get_groups(self) -> List[dict]:
        """Get all security groups from the NSX domain.

        Returns:
            List of group objects from the API
        """
        endpoint = f"/policy/api/v1/infra/domains/{self.domain}/groups"
        groups = self._get_all_paginated(endpoint)

        # Cache for path resolution
        for group in groups:
            self._group_cache[group.get("path", "")] = group
            self._group_cache[group.get("id", "")] = group

        return groups

    def get_services(self) -> List[dict]:
        """Get all services from NSX.

        Returns:
            List of service objects from the API
        """
        endpoint = "/policy/api/v1/infra/services"
        services = self._get_all_paginated(endpoint)

        # Cache for path resolution
        for service in services:
            self._service_cache[service.get("path", "")] = service
            self._service_cache[service.get("id", "")] = service

        return services

    def get_policies(self) -> List[dict]:
        """Get all security policies from the NSX domain.

        Returns:
            List of policy objects from the API (with rules included)
        """
        endpoint = f"/policy/api/v1/infra/domains/{self.domain}/security-policies"
        policies = self._get_all_paginated(endpoint)

        # Fetch rules for each policy (rules are not included in the main response)
        for policy in policies:
            policy_id = policy.get("id", "")
            if policy_id:
                rules_endpoint = f"/policy/api/v1/infra/domains/{self.domain}/security-policies/{policy_id}/rules"
                try:
                    rules = self._get_all_paginated(rules_endpoint)
                    policy["rules"] = rules
                except Exception:
                    policy["rules"] = []

        return policies

    def get_vms(self) -> List[dict]:
        """Get all VMs for display name resolution.

        Returns:
            List of VM objects from the API
        """
        endpoint = "/policy/api/v1/infra/realized-state/virtual-machines"
        vms = self._get_all_paginated(endpoint)

        # Cache bios_uuid -> display_name mapping
        # The BIOS UUID is what NSX uses in ExternalIDExpression for VMs
        for vm in vms:
            display_name = vm.get("display_name", "")
            if not display_name:
                continue

            # Extract biosUuid from compute_ids array
            compute_ids = vm.get("compute_ids", [])
            for cid in compute_ids:
                if cid.startswith("biosUuid:"):
                    bios_uuid = cid.split(":", 1)[1]
                    self._vm_cache[bios_uuid] = display_name
                    break

            # Also cache by external_id as fallback
            external_id = vm.get("external_id", "")
            if external_id:
                self._vm_cache[external_id] = display_name

        return vms

    def get_segments(self) -> List[dict]:
        """Get all segments for path resolution.

        Returns:
            List of segment objects from the API
        """
        endpoint = "/policy/api/v1/infra/segments"
        segments = self._get_all_paginated(endpoint)

        # Cache path -> display_name mapping
        for segment in segments:
            path = segment.get("path", "")
            display_name = segment.get("display_name", "")
            if path and display_name:
                self._segment_cache[path] = display_name

        return segments

    # =========================================================================
    # Path Resolution
    # =========================================================================

    def resolve_group_path_to_name(self, path: str) -> str:
        """Resolve a group path to its display name or ID.

        Args:
            path: NSX group path (e.g., /infra/domains/default/groups/my-group)

        Returns:
            Group name suitable for YAML reference
        """
        if not path or path.upper() == "ANY":
            return path

        # Check cache first
        if path in self._group_cache:
            group = self._group_cache[path]
            # Prefer name over id for cleaner YAML
            return group.get("id", group.get("display_name", path))

        # Extract ID from path as fallback
        match = re.search(r"/groups/([^/]+)$", path)
        if match:
            return match.group(1)

        return path

    def resolve_service_path_to_name(self, path: str) -> str:
        """Resolve a service path to its display name or ID.

        Args:
            path: NSX service path (e.g., /infra/services/my-service)

        Returns:
            Service name suitable for YAML reference
        """
        if not path or path.upper() == "ANY":
            return path

        # Check cache first
        if path in self._service_cache:
            service = self._service_cache[path]
            # Use id for consistency (predefined services use consistent IDs)
            return service.get("id", service.get("display_name", path))

        # Extract ID from path as fallback
        match = re.search(r"/services/([^/]+)$", path)
        if match:
            return match.group(1)

        return path

    def resolve_vm_bios_id_to_name(self, bios_id: str) -> Optional[str]:
        """Resolve a VM BIOS ID to its display name.

        Args:
            bios_id: VM BIOS UUID

        Returns:
            VM display name or None if not found
        """
        return self._vm_cache.get(bios_id)

    def resolve_segment_path_to_name(self, path: str) -> Optional[str]:
        """Resolve a segment path to its display name.

        Args:
            path: NSX segment path

        Returns:
            Segment display name or None if not found
        """
        return self._segment_cache.get(path)

    def is_predefined_service(self, service: dict) -> bool:
        """Check if a service is a predefined NSX system service.

        Args:
            service: Service object from API

        Returns:
            True if this is a predefined service
        """
        return service.get("_system_owned", False) or service.get("is_default", False)

    # =========================================================================
    # Transformation Methods
    # =========================================================================

    def transform_group(self, api_group: dict) -> Optional[dict]:
        """Transform an API group object to YAML format.

        Args:
            api_group: Group object from NSX API

        Returns:
            Dictionary in YAML format or None if should be skipped
        """
        # Skip system-owned groups
        if api_group.get("_system_owned", False):
            return None

        result: dict[str, Any] = {
            "name": api_group.get("id", api_group.get("display_name")),
            "display_name": api_group.get("display_name"),
        }

        if api_group.get("description"):
            result["description"] = api_group["description"]

        # Process expression (criteria/members)
        expression = api_group.get("expression", [])
        members: Dict[str, list] = {}
        criteria: List[dict] = []

        for expr in expression:
            resource_type = expr.get("resource_type", "")

            if resource_type == "ExternalIDExpression":
                # VM members by BIOS ID
                external_ids = expr.get("external_ids", [])
                member_type = expr.get("member_type", "VirtualMachine")

                if member_type == "VirtualMachine":
                    vm_names = []
                    for bios_id in external_ids:
                        vm_name = self.resolve_vm_bios_id_to_name(bios_id)
                        if vm_name:
                            vm_names.append(vm_name)
                        else:
                            # Keep the BIOS ID if we can't resolve it
                            vm_names.append(bios_id)
                    if vm_names:
                        members.setdefault("virtual_machines", []).extend(vm_names)

            elif resource_type == "PathExpression":
                # Static members by path (segments, groups, etc.)
                member_paths = expr.get("member_paths", [])
                for path in member_paths:
                    if "/segments/" in path:
                        seg_name = self.resolve_segment_path_to_name(path)
                        if seg_name:
                            members.setdefault("segments", []).append(seg_name)
                        else:
                            # Extract name from path
                            match = re.search(r"/segments/([^/]+)$", path)
                            if match:
                                members.setdefault("segments", []).append(match.group(1))
                    elif "/groups/" in path:
                        group_name = self.resolve_group_path_to_name(path)
                        members.setdefault("groups", []).append(group_name)
                    else:
                        # Other path types - keep as-is for now
                        members.setdefault("paths", []).append(path)

            elif resource_type == "IPAddressExpression":
                # IP address criteria
                ip_addresses = expr.get("ip_addresses", [])
                if ip_addresses:
                    criteria.append({"ip_addresses": ip_addresses})

            elif resource_type == "MACAddressExpression":
                # MAC address criteria
                mac_addresses = expr.get("mac_addresses", [])
                if mac_addresses:
                    criteria.append({"mac_addresses": mac_addresses})

            elif resource_type == "Condition":
                # Condition-based criteria (tags, names, etc.)
                condition = self._transform_condition(expr)
                if condition:
                    # Find existing criteria block with conditions or create new one
                    found = False
                    for c in criteria:
                        if "conditions" in c:
                            c["conditions"].append(condition)
                            found = True
                            break
                    if not found:
                        criteria.append({"conditions": [condition]})

            elif resource_type == "NestedExpression":
                # Nested expression - recurse
                nested_expressions = expr.get("expressions", [])
                for nested_expr in nested_expressions:
                    nested_type = nested_expr.get("resource_type", "")
                    if nested_type == "Condition":
                        condition = self._transform_condition(nested_expr)
                        if condition:
                            found = False
                            for c in criteria:
                                if "conditions" in c:
                                    c["conditions"].append(condition)
                                    found = True
                                    break
                            if not found:
                                criteria.append({"conditions": [condition]})

            elif resource_type == "ConjunctionOperator":
                # Conjunction between expressions - skip for now
                # The YAML format handles this implicitly with criteria blocks
                pass

        # Add members if any
        if members:
            result["members"] = members

        # Add criteria if any
        if criteria:
            result["criteria"] = criteria

        # Process tags
        tags = api_group.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    def _transform_condition(self, condition: dict) -> Optional[dict]:
        """Transform an API condition to YAML format.

        Args:
            condition: Condition object from NSX API

        Returns:
            Dictionary in YAML format or None if invalid
        """
        key = condition.get("key", "Tag")
        value = condition.get("value", "")
        operator = condition.get("operator", "EQUALS")
        member_type = condition.get("member_type", "VirtualMachine")

        if not value:
            return None

        result: dict[str, Any] = {"value": value}

        # Only include non-default values
        if member_type != "VirtualMachine":
            result["member_type"] = member_type

        if key != "Tag":
            result["key"] = key

        if operator != "EQUALS":
            result["operator"] = operator

        return result

    def transform_service(self, api_service: dict) -> Optional[dict]:
        """Transform an API service object to YAML format.

        Args:
            api_service: Service object from NSX API

        Returns:
            Dictionary in YAML format or None if should be skipped
        """
        # Skip predefined services
        if self.is_predefined_service(api_service):
            return None

        result: dict[str, Any] = {
            "name": api_service.get("id", api_service.get("display_name")),
            "display_name": api_service.get("display_name"),
        }

        if api_service.get("description"):
            result["description"] = api_service["description"]

        # Process service entries
        service_entries = api_service.get("service_entries", [])
        ports: List[str] = []
        l4_entries: List[dict] = []
        icmp_entries: List[dict] = []
        ip_protocol_entries: List[dict] = []
        igmp_entries: List[dict] = []
        ether_type_entries: List[dict] = []
        algorithm_entries: List[dict] = []
        nested_services: List[str] = []

        for entry in service_entries:
            resource_type = entry.get("resource_type", "")

            if resource_type == "L4PortSetServiceEntry":
                transformed = self._transform_l4_entry(entry)
                if transformed:
                    if transformed.get("_simple"):
                        # Use simplified ports format
                        ports.append(transformed["_simple"])
                    else:
                        l4_entries.append(transformed)

            elif resource_type == "ICMPTypeServiceEntry":
                transformed = self._transform_icmp_entry(entry)
                if transformed:
                    icmp_entries.append(transformed)

            elif resource_type == "IPProtocolServiceEntry":
                transformed = self._transform_ip_protocol_entry(entry)
                if transformed:
                    ip_protocol_entries.append(transformed)

            elif resource_type == "IGMPTypeServiceEntry":
                transformed = self._transform_igmp_entry(entry)
                if transformed:
                    igmp_entries.append(transformed)

            elif resource_type == "EtherTypeServiceEntry":
                transformed = self._transform_ether_type_entry(entry)
                if transformed:
                    ether_type_entries.append(transformed)

            elif resource_type == "ALGTypeServiceEntry":
                transformed = self._transform_algorithm_entry(entry)
                if transformed:
                    algorithm_entries.append(transformed)

            elif resource_type == "NestedServiceServiceEntry":
                # Nested service reference
                nested_path = entry.get("nested_service_path", "")
                if nested_path:
                    service_name = self.resolve_service_path_to_name(nested_path)
                    nested_services.append(service_name)

        # Add entries to result
        if ports:
            result["ports"] = ports

        if l4_entries:
            result["l4_port_set_entries"] = l4_entries

        if icmp_entries:
            result["icmp_entries"] = icmp_entries

        if ip_protocol_entries:
            result["ip_protocol_entries"] = ip_protocol_entries

        if igmp_entries:
            result["igmp_entries"] = igmp_entries

        if ether_type_entries:
            result["ether_type_entries"] = ether_type_entries

        if algorithm_entries:
            result["algorithm_entries"] = algorithm_entries

        if nested_services:
            result["members"] = {"services": nested_services}

        # Process tags
        tags = api_service.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    def _transform_l4_entry(self, entry: dict) -> Optional[dict]:
        """Transform an L4 port set entry to YAML format.

        Args:
            entry: L4PortSetServiceEntry from NSX API

        Returns:
            Dictionary in YAML format with optional _simple key for ports format
        """
        protocol = entry.get("l4_protocol", "TCP")
        dest_ports = entry.get("destination_ports", [])
        source_ports = entry.get("source_ports", [])
        display_name = entry.get("display_name", "")

        # Try to use simplified format: "port/protocol"
        if len(dest_ports) == 1 and not source_ports:
            port = dest_ports[0]
            simple = f"{port}/{protocol.lower()}"
            return {"_simple": simple}

        # Use verbose format
        result: dict[str, Any] = {"protocol": protocol}

        if display_name:
            result["display_name"] = display_name

        if dest_ports:
            result["destination_ports"] = dest_ports

        if source_ports:
            result["source_ports"] = source_ports

        if entry.get("description"):
            result["description"] = entry["description"]

        return result

    def _transform_icmp_entry(self, entry: dict) -> dict:
        """Transform an ICMP entry to YAML format."""
        result: dict[str, Any] = {}

        if entry.get("display_name"):
            result["display_name"] = entry["display_name"]

        result["protocol"] = entry.get("protocol", "ICMPv4")

        if entry.get("icmp_type") is not None:
            result["icmp_type"] = entry["icmp_type"]

        if entry.get("icmp_code") is not None:
            result["icmp_code"] = entry["icmp_code"]

        if entry.get("description"):
            result["description"] = entry["description"]

        return result

    def _transform_ip_protocol_entry(self, entry: dict) -> dict:
        """Transform an IP protocol entry to YAML format."""
        result: dict[str, Any] = {}

        if entry.get("display_name"):
            result["display_name"] = entry["display_name"]

        result["protocol"] = entry.get("protocol_number", 0)

        if entry.get("description"):
            result["description"] = entry["description"]

        return result

    def _transform_igmp_entry(self, entry: dict) -> dict:
        """Transform an IGMP entry to YAML format."""
        result: dict[str, Any] = {}

        if entry.get("display_name"):
            result["display_name"] = entry["display_name"]

        if entry.get("description"):
            result["description"] = entry["description"]

        return result

    def _transform_ether_type_entry(self, entry: dict) -> dict:
        """Transform an EtherType entry to YAML format."""
        result: dict[str, Any] = {}

        if entry.get("display_name"):
            result["display_name"] = entry["display_name"]

        result["ether_type"] = entry.get("ether_type", 0)

        if entry.get("description"):
            result["description"] = entry["description"]

        return result

    def _transform_algorithm_entry(self, entry: dict) -> dict:
        """Transform an ALG entry to YAML format."""
        result: dict[str, Any] = {}

        if entry.get("display_name"):
            result["display_name"] = entry["display_name"]

        result["algorithm"] = entry.get("alg", "")
        result["destination_port"] = entry.get("destination_ports", [""])[0]

        if entry.get("source_ports"):
            result["source_ports"] = entry["source_ports"]

        if entry.get("description"):
            result["description"] = entry["description"]

        return result

    def transform_policy(
        self, api_policy: dict, include_disabled_rules: bool = False
    ) -> Optional[dict]:
        """Transform an API policy object to YAML format.

        Args:
            api_policy: Policy object from NSX API
            include_disabled_rules: Whether to include disabled rules

        Returns:
            Dictionary in YAML format or None if should be skipped
        """
        # Skip system-owned policies
        if api_policy.get("_system_owned", False):
            return None

        result: dict[str, Any] = {
            "name": api_policy.get("id", api_policy.get("display_name")),
            "display_name": api_policy.get("display_name"),
        }

        if api_policy.get("description"):
            result["description"] = api_policy["description"]

        # Category
        category = api_policy.get("category", "Application")
        result["category"] = category

        # Process rules
        rules = api_policy.get("rules", [])
        transformed_rules: List[dict] = []

        for rule in rules:
            # Skip disabled rules unless requested
            if rule.get("disabled", False) and not include_disabled_rules:
                continue

            transformed_rule = self._transform_rule(rule)
            if transformed_rule:
                transformed_rules.append(transformed_rule)

        if transformed_rules:
            result["rules"] = transformed_rules

        # Process tags
        tags = api_policy.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    def _transform_rule(self, api_rule: dict) -> Optional[dict]:
        """Transform an API rule to YAML format.

        Args:
            api_rule: Rule object from NSX API

        Returns:
            Dictionary in YAML format or None if invalid
        """
        result: dict[str, Any] = {"display_name": api_rule.get("display_name", "unnamed")}

        if api_rule.get("description"):
            result["description"] = api_rule["description"]

        # Action is required
        action = api_rule.get("action", "ALLOW")
        result["action"] = action

        # Source groups
        source_groups = api_rule.get("source_groups", [])
        if source_groups and source_groups != ["ANY"]:
            resolved_sources = []
            for path in source_groups:
                if path.upper() == "ANY":
                    continue
                name = self.resolve_group_path_to_name(path)
                resolved_sources.append(name)
            if resolved_sources:
                result["source_groups"] = resolved_sources

        # Source exclusion
        if api_rule.get("sources_excluded", False):
            result["sources_excluded"] = True

        # Destination groups
        dest_groups = api_rule.get("destination_groups", [])
        if dest_groups and dest_groups != ["ANY"]:
            resolved_dests = []
            for path in dest_groups:
                if path.upper() == "ANY":
                    continue
                name = self.resolve_group_path_to_name(path)
                resolved_dests.append(name)
            if resolved_dests:
                result["destination_groups"] = resolved_dests

        # Destination exclusion
        if api_rule.get("destinations_excluded", False):
            result["destinations_excluded"] = True

        # Services
        services = api_rule.get("services", [])
        if services and services != ["ANY"]:
            resolved_services = []
            for path in services:
                if path.upper() == "ANY":
                    continue
                name = self.resolve_service_path_to_name(path)
                resolved_services.append(name)
            if resolved_services:
                result["services"] = resolved_services

        # Direction (only include if not default)
        direction = api_rule.get("direction", "IN_OUT")
        if direction != "IN_OUT":
            result["direction"] = direction

        # Logging
        if api_rule.get("logged", False):
            result["logged"] = True

        # Disabled
        if api_rule.get("disabled", False):
            result["disabled"] = True

        # Log label
        if api_rule.get("log_label"):
            result["log_label"] = api_rule["log_label"]

        # Notes
        if api_rule.get("notes"):
            result["notes"] = api_rule["notes"]

        # IP version (only include if not default)
        ip_version = api_rule.get("ip_version", "IPV4_IPV6")
        if ip_version != "IPV4_IPV6":
            result["ip_version"] = ip_version

        # Rule-level tags
        tags = api_rule.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    # =========================================================================
    # Export Methods
    # =========================================================================

    def export_all(
        self,
        output_dir: str,
        skip_predefined_services: bool = True,
        include_disabled_rules: bool = False,
    ) -> dict:
        """Export all DFW configurations to YAML files.

        Args:
            output_dir: Directory to write YAML files
            skip_predefined_services: Skip predefined NSX services
            include_disabled_rules: Include disabled rules in export

        Returns:
            Dictionary with counts of exported items
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        counts = {"groups": 0, "services": 0, "policies": 0, "rules": 0}

        # Pre-fetch VMs and segments for name resolution
        print("Fetching VMs for name resolution...")
        self.get_vms()
        print(f"  Cached {len(self._vm_cache)} VMs")

        print("Fetching segments for name resolution...")
        self.get_segments()
        print(f"  Cached {len(self._segment_cache)} segments")

        # Export groups
        print("\nExporting security groups...")
        groups = self.get_groups()
        transformed_groups = []
        for group in groups:
            transformed = self.transform_group(group)
            if transformed:
                transformed_groups.append(transformed)
                counts["groups"] += 1

        if transformed_groups:
            groups_file = output_path / "security_groups.yaml"
            self._write_yaml(
                groups_file,
                {"security_groups": transformed_groups},
                header=self._get_groups_header(),
            )
            print(f"  Wrote {counts['groups']} groups to {groups_file}")

        # Export services
        print("\nExporting services...")
        services = self.get_services()
        transformed_services = []
        for service in services:
            if skip_predefined_services and self.is_predefined_service(service):
                continue
            transformed = self.transform_service(service)
            if transformed:
                transformed_services.append(transformed)
                counts["services"] += 1

        if transformed_services:
            services_file = output_path / "services.yaml"
            self._write_yaml(
                services_file,
                {"services": transformed_services},
                header=self._get_services_header(),
            )
            print(f"  Wrote {counts['services']} services to {services_file}")

        # Export policies
        print("\nExporting security policies...")
        policies = self.get_policies()
        transformed_policies = []
        for policy in policies:
            transformed = self.transform_policy(policy, include_disabled_rules)
            if transformed:
                transformed_policies.append(transformed)
                counts["policies"] += 1
                counts["rules"] += len(transformed.get("rules", []))

        if transformed_policies:
            policies_file = output_path / "security_policies.yaml"
            self._write_yaml(
                policies_file,
                {"security_policies": transformed_policies},
                header=self._get_policies_header(),
            )
            print(f"  Wrote {counts['policies']} policies ({counts['rules']} rules) to {policies_file}")

        return counts

    def _write_yaml(self, path: Path, data: dict, header: str = "") -> None:
        """Write data to a YAML file with optional header.

        Args:
            path: Output file path
            data: Data to write
            header: Optional comment header
        """
        # Custom YAML representer for clean output
        def str_representer(dumper, data):
            if "\n" in data:
                return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
            return dumper.represent_scalar("tag:yaml.org,2002:str", data)

        yaml.add_representer(str, str_representer)

        with open(path, "w") as f:
            if header:
                f.write(header)
                f.write("\n")
            yaml.dump(
                data,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
                width=120,
            )

    def _get_groups_header(self) -> str:
        """Get the header comment for security_groups.yaml."""
        return """# =============================================================================
# NSX-T Security Groups Configuration
# =============================================================================
# Exported from NSX-T Manager
#
# MEMBERSHIP TYPES:
#   members:   Static membership - list objects by display name
#     virtual_machines: [vm1, vm2]
#     segments: [seg1, seg2]
#     groups: [group1, group2]    (nested groups)
#
#   criteria:  Dynamic membership - match by tags, IPs, conditions
#     conditions: [{value: "scope|tag", member_type: VirtualMachine}]
#     ip_addresses: [10.0.0.0/8, 192.168.0.0/16]
# =============================================================================
"""

    def _get_services_header(self) -> str:
        """Get the header comment for services.yaml."""
        return """# =============================================================================
# NSX-T Services Configuration
# =============================================================================
# Exported from NSX-T Manager (custom services only, predefined excluded)
#
# FORMATS:
#   ports:           Simple "port/protocol" format (e.g., "80/tcp", "53/udp")
#   l4_port_set_entries: Verbose format for complex cases
#   icmp_entries:    ICMP type/code definitions
#   ip_protocol_entries: Raw IP protocol numbers
#   members.services:    Nested service groups (reference other services)
#
# PREDEFINED SERVICES:
#   Reference built-in NSX services by name: DNS, NTP, HTTP, HTTPS, SSH, etc.
# =============================================================================
"""

    def _get_policies_header(self) -> str:
        """Get the header comment for security_policies.yaml."""
        return """# =============================================================================
# NSX-T Security Policies Configuration
# =============================================================================
# Exported from NSX-T Manager
#
# RULE FIELDS:
#   source_groups:         Source group names (omit for ANY)
#   sources_excluded:      true = NOT these sources (negate)
#   destination_groups:    Destination group names (omit for ANY)
#   destinations_excluded: true = NOT these destinations (negate)
#   services:              Service names (omit for ANY)
#   action:                ALLOW, DROP, or REJECT
#   logged:                Enable logging
#   direction:             IN_OUT (default), IN, or OUT
#
# CATEGORIES (evaluation order):
#   Emergency, Infrastructure, Environment, Application
# =============================================================================
"""


def main():
    """Main entry point for the NSX exporter."""
    parser = argparse.ArgumentParser(
        description="Export NSX-T DFW configurations to YAML format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage
    %(prog)s --host nsx.example.com --username admin --output data/

    # With all options
    %(prog)s \\
        --host nsx.example.com \\
        --username admin \\
        --password 'secret' \\
        --output exported/ \\
        --domain default \\
        --skip-predefined-services \\
        --include-disabled-rules

Environment Variables:
    NSX_HOST      NSX Manager hostname
    NSX_USERNAME  API username
    NSX_PASSWORD  API password
""",
    )

    parser.add_argument(
        "--host",
        default=os.environ.get("NSX_HOST"),
        help="NSX Manager hostname or IP (or set NSX_HOST env var)",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("NSX_USERNAME"),
        help="NSX API username (or set NSX_USERNAME env var)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("NSX_PASSWORD"),
        help="NSX API password (or set NSX_PASSWORD env var, or enter interactively)",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="Read NSX API password from file (avoids shell escaping issues)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="data",
        help="Output directory for YAML files (default: data)",
    )
    parser.add_argument(
        "--domain",
        default="default",
        help="NSX domain (default: default)",
    )
    parser.add_argument(
        "--skip-predefined-services",
        action="store_true",
        default=True,
        help="Skip predefined NSX services (default: true)",
    )
    parser.add_argument(
        "--include-predefined-services",
        action="store_true",
        help="Include predefined NSX services",
    )
    parser.add_argument(
        "--include-disabled-rules",
        action="store_true",
        help="Include disabled rules in export",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: false)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Validate required arguments
    if not args.host:
        parser.error("--host is required (or set NSX_HOST environment variable)")

    if not args.username:
        parser.error("--username is required (or set NSX_USERNAME environment variable)")

    # Get password from file, argument, or interactively
    password = None
    if args.password_file:
        password = args.password_file.read_text().strip()
    elif args.password:
        password = args.password
    else:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    # Handle --include-predefined-services flag
    skip_predefined = args.skip_predefined_services
    if args.include_predefined_services:
        skip_predefined = False

    print(f"NSX-T DFW Configuration Exporter")
    print(f"================================")
    print(f"Host: {args.host}")
    print(f"Domain: {args.domain}")
    print(f"Output: {args.output}")
    print(f"Skip predefined services: {skip_predefined}")
    print(f"Include disabled rules: {args.include_disabled_rules}")
    print()

    try:
        exporter = NSXExporter(
            host=args.host,
            username=args.username,
            password=password,
            domain=args.domain,
            verify_ssl=args.verify_ssl,
        )

        counts = exporter.export_all(
            output_dir=args.output,
            skip_predefined_services=skip_predefined,
            include_disabled_rules=args.include_disabled_rules,
        )

        print()
        print("=" * 50)
        print("Export Summary")
        print("=" * 50)
        print(f"Security Groups: {counts['groups']}")
        print(f"Services:        {counts['services']}")
        print(f"Policies:        {counts['policies']}")
        print(f"Rules:           {counts['rules']}")
        print()
        print("Export completed successfully!")

    except requests.exceptions.ConnectionError as e:
        print(f"ERROR: Failed to connect to NSX Manager at {args.host}")
        print(f"       {e}")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: NSX API request failed: {e}")
        if e.response is not None:
            try:
                error_detail = e.response.json()
                print(f"       {json.dumps(error_detail, indent=2)}")
            except Exception:
                print(f"       {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
