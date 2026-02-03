#!/usr/bin/env python3
"""
NSX-T DFW Configuration Exporter
================================

This script extracts existing NSX-T Distributed Firewall (DFW) configurations
from an NSX Manager and converts them to YAML format compatible with the
Terraform modules in this repository.

PURPOSE:
    - Export security groups, services, and security policies from NSX-T
    - Convert NSX API responses to human-readable YAML format
    - Resolve internal NSX paths/IDs to friendly display names
    - Generate Terraform-compatible configuration files

AUTHENTICATION:
    The script supports two authentication methods:
    1. Session-based authentication (POST to /api/session/create)
    2. Basic authentication with Base64-encoded credentials (fallback)

    Session auth is tried first; if it fails, basic auth is used automatically.

OUTPUT FILES:
    - security_groups.yaml  : Security group definitions (WHO)
    - services.yaml         : Custom service definitions (WHAT) - predefined excluded
    - security_policies.yaml: Firewall policies and rules (HOW)
    - imports.tf            : Terraform import blocks (optional, --generate-imports)

USAGE:
    # Basic usage with interactive password prompt
    python scripts/nsx_exporter.py \\
        --host nsx-manager.example.com \\
        --username admin \\
        --output data/

    # With password file (recommended for special characters like !)
    python scripts/nsx_exporter.py \\
        --host nsx-manager.example.com \\
        --username admin \\
        --password-file /path/to/password.txt \\
        --output data/

    # Using environment variables
    export NSX_HOST=nsx-manager.example.com
    export NSX_USERNAME=admin
    export NSX_PASSWORD='MyP@ssw0rd!'
    python scripts/nsx_exporter.py --output data/

    # Include disabled rules and predefined services
    python scripts/nsx_exporter.py \\
        --host nsx-manager.example.com \\
        --username admin \\
        --password-file /path/to/password.txt \\
        --output data/ \\
        --include-predefined-services \\
        --include-disabled-rules

REQUIREMENTS:
    - Python 3.9+
    - requests library (pip install requests)
    - PyYAML library (pip install pyyaml)

API ENDPOINTS USED:
    - GET /policy/api/v1/infra/domains/{domain}/groups         - Security groups
    - GET /policy/api/v1/infra/services                        - Services
    - GET /policy/api/v1/infra/domains/{domain}/security-policies - Policies
    - GET /policy/api/v1/infra/domains/{domain}/security-policies/{id}/rules - Rules
    - GET /policy/api/v1/infra/realized-state/virtual-machines - VMs (for name resolution)
    - GET /policy/api/v1/infra/segments                        - Segments (for name resolution)

NOTES:
    - System-owned objects (_system_owned: true) are automatically skipped
    - Predefined services are skipped by default (use --include-predefined-services to include)
    - Disabled rules are skipped by default (use --include-disabled-rules to include)
    - VM BIOS UUIDs are resolved to display names for readability
    - NSX paths are resolved to IDs/names for Terraform compatibility
"""

from __future__ import annotations

# =============================================================================
# IMPORTS
# =============================================================================

import argparse      # Command-line argument parsing
import base64        # Base64 encoding for HTTP Basic authentication
import getpass       # Secure password input from terminal
import json          # JSON parsing for API error responses
import os            # Environment variable access
import re            # Regular expressions for path parsing
import sys           # System exit codes
from pathlib import Path                          # Cross-platform path handling
from typing import Any, Dict, List, Optional      # Type hints for better code clarity
from urllib.parse import urljoin, quote_plus      # URL manipulation utilities

# -----------------------------------------------------------------------------
# External Dependencies (with graceful error handling)
# -----------------------------------------------------------------------------

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

# Disable SSL warnings for self-signed certificates (common in lab environments)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# NSX EXPORTER CLASS
# =============================================================================

class NSXExporter:
    """
    Exports NSX-T DFW configurations to YAML format.

    This class handles:
    - Authentication with NSX Manager (session-based or basic auth)
    - Fetching security groups, services, and policies via REST API
    - Resolving internal NSX paths to human-readable names
    - Transforming API responses to Terraform-compatible YAML format

    Architecture:
        NSX Manager API --> NSXExporter --> YAML Files

    The exporter maintains internal caches for efficient path resolution:
        - _group_cache:   Maps group paths/IDs to group objects
        - _service_cache: Maps service paths/IDs to service objects
        - _vm_cache:      Maps VM BIOS UUIDs to display names
        - _segment_cache: Maps segment paths to display names

    Example:
        exporter = NSXExporter(
            host="nsx.example.com",
            username="admin",
            password="secret"
        )
        counts = exporter.export_all(output_dir="./exported")
        print(f"Exported {counts['groups']} groups")
    """

    # =========================================================================
    # INITIALIZATION & AUTHENTICATION
    # =========================================================================

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "default",
        verify_ssl: bool = False,
    ):
        """
        Initialize the NSX exporter and authenticate with NSX Manager.

        Args:
            host:       NSX Manager hostname or IP address
                        Example: "nsx-manager.example.com" or "192.168.1.100"
            username:   API username with read access to NSX objects
                        Example: "admin" or "audit-user"
            password:   API password (supports special characters)
            domain:     NSX domain for security policies (default: "default")
                        Most deployments use "default" unless multi-tenancy is configured
            verify_ssl: Whether to verify SSL certificates
                        Set to False for self-signed certs (common in labs)

        Raises:
            requests.exceptions.HTTPError: If authentication fails
            ValueError: If session token cannot be obtained
        """
        # Store connection parameters
        self.host = host
        self.base_url = f"https://{host}"
        self.username = username
        self.password = password
        self.domain = domain
        self.verify_ssl = verify_ssl

        # Initialize HTTP session with SSL settings
        self.session = requests.Session()
        self.session.verify = verify_ssl

        # XSRF token for session-based authentication (populated during auth)
        self._xsrf_token: Optional[str] = None

        # ---------------------------------------------------------------------
        # Path Resolution Caches
        # ---------------------------------------------------------------------
        # These caches store NSX objects for efficient path-to-name resolution.
        # They're populated when fetching groups/services and used when
        # transforming policies (which reference groups/services by path).

        self._group_cache: Dict[str, dict] = {}    # path/id -> group object
        self._service_cache: Dict[str, dict] = {}  # path/id -> service object
        self._vm_cache: Dict[str, str] = {}        # bios_uuid -> display_name
        self._segment_cache: Dict[str, str] = {}   # path -> display_name

        # Authenticate with NSX Manager
        self._authenticate()

    def _authenticate(self) -> None:
        """
        Authenticate with NSX Manager using the best available method.

        Authentication Strategy:
            1. Try session-based authentication first (more secure, supports XSRF)
            2. Fall back to basic authentication if session auth fails

        Session-based auth is preferred because:
            - Single authentication, token reused for all requests
            - Supports XSRF protection
            - Better for environments with strict security policies

        Basic auth fallback handles:
            - Older NSX versions
            - Environments where session auth is disabled
            - API configurations that only support basic auth
        """
        # Try session-based authentication first
        try:
            self._session_auth()
            return  # Success - no need for fallback
        except requests.exceptions.HTTPError as e:
            print(f"  Session auth failed ({e}), trying basic auth...")

        # Fall back to basic authentication
        self._basic_auth()

    def _session_auth(self) -> None:
        """
        Authenticate using NSX session-based authentication.

        Process:
            1. POST credentials to /api/session/create
            2. Extract JSESSIONID cookie (stored automatically in session)
            3. Extract x-xsrf-token header for subsequent requests

        The x-xsrf-token must be included in all subsequent API requests
        to prevent cross-site request forgery attacks.

        Raises:
            requests.exceptions.HTTPError: If authentication fails (401/403)
            ValueError: If x-xsrf-token is not in response headers
        """
        url = f"{self.base_url}/api/session/create"

        # URL-encode credentials (handles special characters like !, @, #)
        # Format: j_username=admin&j_password=MyP%40ss
        data = f"j_username={quote_plus(self.username)}&j_password={quote_plus(self.password)}"

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        response = self.session.post(url, data=data, headers=headers)
        response.raise_for_status()  # Raises HTTPError for 4xx/5xx responses

        # Extract x-xsrf-token from response headers
        # This token must be included in all subsequent requests
        self._xsrf_token = response.headers.get("x-xsrf-token")
        if not self._xsrf_token:
            raise ValueError("Failed to get x-xsrf-token from session creation response")

        # Note: JSESSIONID cookie is automatically stored in self.session

    def _basic_auth(self) -> None:
        """
        Configure HTTP Basic authentication with Base64-encoded credentials.

        Process:
            1. Combine username:password
            2. Base64 encode the combined string
            3. Set Authorization header: "Basic <encoded>"

        This method sets the Authorization header on the session,
        which will be included in all subsequent requests.

        Example:
            admin:VMware1! -> YWRtaW46Vk13YXJlMSE= -> "Basic YWRtaW46Vk13YXJlMSE="
        """
        # Combine credentials in standard format
        credentials = f"{self.username}:{self.password}"

        # Base64 encode (must be ASCII bytes, then decode back to string)
        encoded = base64.b64encode(credentials.encode("ascii")).decode("utf-8")

        # Set Authorization header for all future requests
        self.session.headers["Authorization"] = f"Basic {encoded}"

    # =========================================================================
    # LOW-LEVEL API METHODS
    # =========================================================================

    def _api_get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """
        Make a GET request to the NSX Policy API.

        This is the core method for all API communication. It:
            - Constructs the full URL from base_url and endpoint
            - Adds x-xsrf-token header if using session auth
            - Handles HTTP errors with descriptive exceptions

        Args:
            endpoint: API endpoint path (e.g., "/policy/api/v1/infra/services")
            params:   Optional query parameters (e.g., {"cursor": "abc123"})

        Returns:
            Parsed JSON response as a dictionary

        Raises:
            requests.exceptions.HTTPError: For 4xx/5xx responses

        Example:
            response = self._api_get("/policy/api/v1/infra/services")
            services = response.get("results", [])
        """
        url = urljoin(self.base_url, endpoint)

        # Add XSRF token if using session authentication
        headers = {}
        if self._xsrf_token:
            headers["x-xsrf-token"] = self._xsrf_token

        response = self.session.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()

    def _get_all_paginated(self, endpoint: str, result_key: str = "results") -> list:
        """
        Fetch all results from a paginated NSX API endpoint.

        NSX API uses cursor-based pagination for large result sets.
        This method automatically follows pagination cursors until
        all results are retrieved.

        Pagination Flow:
            1. Make initial request
            2. If response contains "cursor", make another request with cursor
            3. Repeat until no more cursors

        Args:
            endpoint:   API endpoint path
            result_key: Key in response containing the results array
                        (usually "results", but some endpoints differ)

        Returns:
            Combined list of all results across all pages

        Example:
            # Fetch all VMs (may be thousands across multiple pages)
            vms = self._get_all_paginated(
                "/policy/api/v1/infra/realized-state/virtual-machines"
            )
        """
        all_results = []
        cursor = None

        while True:
            # Build params dict with cursor if we have one
            params = {}
            if cursor:
                params["cursor"] = cursor

            # Fetch this page
            response = self._api_get(endpoint, params)
            results = response.get(result_key, [])
            all_results.extend(results)

            # Check for next page
            cursor = response.get("cursor")
            if not cursor:
                break  # No more pages

        return all_results

    # =========================================================================
    # HIGH-LEVEL API METHODS (Data Fetching)
    # =========================================================================

    def get_groups(self) -> List[dict]:
        """
        Fetch all security groups from the NSX domain.

        Security groups define WHO is affected by firewall rules.
        Groups can contain:
            - Virtual machines (by BIOS UUID or tag)
            - Segments (network segments)
            - IP addresses/ranges
            - Other groups (nested groups)

        API Endpoint:
            GET /policy/api/v1/infra/domains/{domain}/groups

        Side Effects:
            Populates self._group_cache for path resolution

        Returns:
            List of group objects from the API
            Each group has: id, display_name, expression, tags, etc.
        """
        endpoint = f"/policy/api/v1/infra/domains/{self.domain}/groups"
        groups = self._get_all_paginated(endpoint)

        # Cache groups for path resolution when processing policies
        # Groups are referenced by path in rules, we need to resolve to names
        for group in groups:
            self._group_cache[group.get("path", "")] = group
            self._group_cache[group.get("id", "")] = group

        return groups

    def get_services(self) -> List[dict]:
        """
        Fetch all services from NSX (both custom and predefined).

        Services define WHAT traffic (ports/protocols) is matched by rules.
        Service types include:
            - L4 port sets (TCP/UDP ports)
            - ICMP types
            - IP protocols (GRE, ESP, etc.)
            - ALG services (FTP, TFTP)
            - Nested service groups

        API Endpoint:
            GET /policy/api/v1/infra/services

        Note:
            This returns ALL services including NSX predefined services.
            Use is_predefined_service() to filter them out if needed.

        Side Effects:
            Populates self._service_cache for path resolution

        Returns:
            List of service objects from the API
        """
        endpoint = "/policy/api/v1/infra/services"
        services = self._get_all_paginated(endpoint)

        # Cache services for path resolution when processing rules
        for service in services:
            self._service_cache[service.get("path", "")] = service
            self._service_cache[service.get("id", "")] = service

        return services

    def get_policies(self) -> List[dict]:
        """
        Fetch all security policies and their rules from the NSX domain.

        Security policies define HOW traffic is handled (ALLOW/DROP/REJECT).
        Each policy contains multiple rules that are evaluated in order.

        IMPORTANT: Rules are NOT included in the main policies response!
        This method makes additional API calls to fetch rules for each policy.

        API Endpoints:
            GET /policy/api/v1/infra/domains/{domain}/security-policies
            GET /policy/api/v1/infra/domains/{domain}/security-policies/{id}/rules

        Policy Categories (evaluation order):
            1. Ethernet      - Layer 2 rules
            2. Emergency     - Break-glass rules
            3. Infrastructure- Core services (DNS, NTP, AD)
            4. Environment   - Environment isolation
            5. Application   - Application-specific rules

        Returns:
            List of policy objects with "rules" key populated
        """
        endpoint = f"/policy/api/v1/infra/domains/{self.domain}/security-policies"
        policies = self._get_all_paginated(endpoint)

        # Fetch rules for each policy (rules are NOT in the main response)
        for policy in policies:
            policy_id = policy.get("id", "")
            if policy_id:
                rules_endpoint = f"/policy/api/v1/infra/domains/{self.domain}/security-policies/{policy_id}/rules"
                try:
                    rules = self._get_all_paginated(rules_endpoint)
                    policy["rules"] = rules
                except Exception:
                    # If rules fetch fails, continue with empty rules
                    policy["rules"] = []

        return policies

    def get_vms(self) -> List[dict]:
        """
        Fetch all VMs from NSX realized state for name resolution.

        VMs are referenced in security groups by their BIOS UUID, but
        we want human-readable display names in the exported YAML.

        This method builds a cache mapping BIOS UUIDs to display names.

        API Endpoint:
            GET /policy/api/v1/infra/realized-state/virtual-machines

        BIOS UUID Location:
            The BIOS UUID is in the compute_ids array as "biosUuid:xxxx"
            Example: ["biosUuid:4208c71b-4ce4-ad18-5f5d-9ccb26c5f488", ...]

        Side Effects:
            Populates self._vm_cache with bios_uuid -> display_name mappings

        Returns:
            List of VM objects from the API
        """
        endpoint = "/policy/api/v1/infra/realized-state/virtual-machines"
        vms = self._get_all_paginated(endpoint)

        # Build bios_uuid -> display_name mapping
        # This is used when resolving ExternalIDExpression in groups
        for vm in vms:
            display_name = vm.get("display_name", "")
            if not display_name:
                continue

            # Extract biosUuid from compute_ids array
            # Format: ["moIdOnHost:123", "biosUuid:xxxx-xxxx-xxxx", ...]
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
        """
        Fetch all segments from NSX for path resolution.

        Segments (network segments) are referenced by path in security groups.
        This method builds a cache mapping paths to display names.

        API Endpoint:
            GET /policy/api/v1/infra/segments

        Side Effects:
            Populates self._segment_cache with path -> display_name mappings

        Returns:
            List of segment objects from the API
        """
        endpoint = "/policy/api/v1/infra/segments"
        segments = self._get_all_paginated(endpoint)

        # Build path -> display_name mapping
        for segment in segments:
            path = segment.get("path", "")
            display_name = segment.get("display_name", "")
            if path and display_name:
                self._segment_cache[path] = display_name

        return segments

    # =========================================================================
    # PATH RESOLUTION METHODS
    # =========================================================================
    # These methods convert NSX internal paths/IDs to human-readable names.
    # This makes the exported YAML more readable and Terraform-compatible.

    def resolve_group_path_to_name(self, path: str) -> str:
        """
        Resolve a group path to its ID or display name.

        NSX rules reference groups by full path:
            /infra/domains/default/groups/my-group-id

        We want just the group name for YAML readability:
            my-group-id

        Resolution order:
            1. Check cache for full object, return ID
            2. Extract ID from path using regex
            3. Return original path as fallback

        Args:
            path: Full NSX path or "ANY"
                  Example: "/infra/domains/default/groups/web-servers"

        Returns:
            Group name/ID suitable for YAML
            Example: "web-servers"
        """
        if not path or path.upper() == "ANY":
            return path

        # Check cache first (populated by get_groups())
        if path in self._group_cache:
            group = self._group_cache[path]
            return group.get("id", group.get("display_name", path))

        # Extract ID from path as fallback
        # Path format: /infra/domains/default/groups/<group-id>
        match = re.search(r"/groups/([^/]+)$", path)
        if match:
            return match.group(1)

        return path  # Return original if nothing else works

    def resolve_service_path_to_name(self, path: str) -> str:
        """
        Resolve a service path to its ID or display name.

        NSX rules reference services by full path:
            /infra/services/DNS  (predefined)
            /infra/services/my-custom-service  (custom)

        We want just the service name:
            DNS
            my-custom-service

        Args:
            path: Full NSX path or "ANY"

        Returns:
            Service name/ID suitable for YAML
        """
        if not path or path.upper() == "ANY":
            return path

        # Check cache first
        if path in self._service_cache:
            service = self._service_cache[path]
            return service.get("id", service.get("display_name", path))

        # Extract ID from path as fallback
        # Path format: /infra/services/<service-id>
        match = re.search(r"/services/([^/]+)$", path)
        if match:
            return match.group(1)

        return path

    def resolve_vm_bios_id_to_name(self, bios_id: str) -> Optional[str]:
        """
        Resolve a VM BIOS UUID to its display name.

        Security groups reference VMs by BIOS UUID in ExternalIDExpression.
        We want display names for readability:
            4208c71b-4ce4-ad18-5f5d-9ccb26c5f488 -> web-server-01

        Args:
            bios_id: VM BIOS UUID

        Returns:
            VM display name, or None if not found in cache
        """
        return self._vm_cache.get(bios_id)

    def resolve_segment_path_to_name(self, path: str) -> Optional[str]:
        """
        Resolve a segment path to its display name.

        Args:
            path: Full NSX segment path

        Returns:
            Segment display name, or None if not found in cache
        """
        return self._segment_cache.get(path)

    def is_predefined_service(self, service: dict) -> bool:
        """
        Check if a service is a predefined NSX system service.

        Predefined services (DNS, HTTP, SSH, etc.) are built into NSX
        and shouldn't be exported to custom services.yaml.

        Detection:
            - _system_owned: true  (most reliable)
            - is_default: true     (alternative flag)

        Args:
            service: Service object from API

        Returns:
            True if this is a predefined/system service
        """
        return service.get("_system_owned", False) or service.get("is_default", False)

    # =========================================================================
    # TRANSFORMATION METHODS
    # =========================================================================
    # These methods convert NSX API responses to YAML-compatible dictionaries.
    # The output format matches what the Terraform modules expect.

    def transform_group(self, api_group: dict) -> Optional[dict]:
        """
        Transform an NSX API group object to YAML format.

        NSX Group Structure:
            - id, display_name, description
            - expression: Array of membership criteria
            - tags: Resource tags

        Expression Types Handled:
            - ExternalIDExpression: VMs by BIOS UUID
            - PathExpression: Segments, groups by path
            - IPAddressExpression: IP addresses/ranges
            - MACAddressExpression: MAC addresses
            - Condition: Tag-based or attribute matching
            - NestedExpression: Complex nested criteria

        Output YAML Format:
            name: group-id
            display_name: "Human Readable Name"
            description: "Optional description"
            members:
              virtual_machines: [vm1, vm2]
              segments: [seg1, seg2]
              groups: [nested-group1]
            criteria:
              - conditions:
                  - value: "scope|tag"
              - ip_addresses: [10.0.0.0/8]
            tags:
              - scope: managed-by
                tag: terraform

        Args:
            api_group: Group object from NSX API

        Returns:
            Dictionary in YAML format, or None if group should be skipped
        """
        # Skip system-owned groups (NSX internal groups)
        if api_group.get("_system_owned", False):
            return None

        # Initialize result with basic fields
        result: dict[str, Any] = {
            "name": api_group.get("id", api_group.get("display_name")),
            "display_name": api_group.get("display_name"),
        }

        if api_group.get("description"):
            result["description"] = api_group["description"]

        # Process expression array (membership criteria)
        expression = api_group.get("expression", [])
        members: Dict[str, list] = {}   # Static members (VMs, segments, groups)
        criteria: List[dict] = []        # Dynamic criteria (tags, IPs, conditions)

        for expr in expression:
            resource_type = expr.get("resource_type", "")

            # -----------------------------------------------------------------
            # ExternalIDExpression: VMs referenced by BIOS UUID
            # -----------------------------------------------------------------
            if resource_type == "ExternalIDExpression":
                external_ids = expr.get("external_ids", [])
                member_type = expr.get("member_type", "VirtualMachine")

                if member_type == "VirtualMachine":
                    vm_names = []
                    for bios_id in external_ids:
                        # Try to resolve BIOS UUID to display name
                        vm_name = self.resolve_vm_bios_id_to_name(bios_id)
                        if vm_name:
                            vm_names.append(vm_name)
                        else:
                            # Keep BIOS UUID if can't resolve (manual cleanup needed)
                            vm_names.append(bios_id)
                    if vm_names:
                        members.setdefault("virtual_machines", []).extend(vm_names)

            # -----------------------------------------------------------------
            # PathExpression: Segments, groups, or other objects by path
            # -----------------------------------------------------------------
            elif resource_type == "PathExpression":
                member_paths = expr.get("member_paths", [])
                for path in member_paths:
                    if "/segments/" in path:
                        # Segment reference
                        seg_name = self.resolve_segment_path_to_name(path)
                        if seg_name:
                            members.setdefault("segments", []).append(seg_name)
                        else:
                            # Extract name from path
                            match = re.search(r"/segments/([^/]+)$", path)
                            if match:
                                members.setdefault("segments", []).append(match.group(1))
                    elif "/groups/" in path:
                        # Nested group reference
                        group_name = self.resolve_group_path_to_name(path)
                        members.setdefault("groups", []).append(group_name)
                    else:
                        # Other path types - keep as-is
                        members.setdefault("paths", []).append(path)

            # -----------------------------------------------------------------
            # IPAddressExpression: IP addresses or CIDR ranges
            # -----------------------------------------------------------------
            elif resource_type == "IPAddressExpression":
                ip_addresses = expr.get("ip_addresses", [])
                if ip_addresses:
                    criteria.append({"ip_addresses": ip_addresses})

            # -----------------------------------------------------------------
            # MACAddressExpression: MAC addresses
            # -----------------------------------------------------------------
            elif resource_type == "MACAddressExpression":
                mac_addresses = expr.get("mac_addresses", [])
                if mac_addresses:
                    criteria.append({"mac_addresses": mac_addresses})

            # -----------------------------------------------------------------
            # Condition: Tag-based or attribute matching
            # -----------------------------------------------------------------
            elif resource_type == "Condition":
                condition = self._transform_condition(expr)
                if condition:
                    # Group conditions together in a single criteria block
                    found = False
                    for c in criteria:
                        if "conditions" in c:
                            c["conditions"].append(condition)
                            found = True
                            break
                    if not found:
                        criteria.append({"conditions": [condition]})

            # -----------------------------------------------------------------
            # NestedExpression: Complex nested criteria
            # -----------------------------------------------------------------
            elif resource_type == "NestedExpression":
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

            # ConjunctionOperator is skipped - YAML format handles implicitly

        # Add members and criteria to result if present
        if members:
            result["members"] = members

        if criteria:
            result["criteria"] = criteria

        # Process resource tags
        tags = api_group.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    def _transform_condition(self, condition: dict) -> Optional[dict]:
        """
        Transform an NSX condition to YAML format.

        Conditions are used for tag-based or attribute-based matching.

        NSX Condition Fields:
            - key: "Tag", "Name", "OSName", "ComputerName"
            - value: The value to match (e.g., "scope|tag" for tags)
            - operator: "EQUALS", "CONTAINS", "STARTSWITH", etc.
            - member_type: "VirtualMachine", "Segment", etc.

        Output Format (minimal - only non-default values):
            value: "production|environment"
            # key, operator, member_type only if not default

        Args:
            condition: Condition object from NSX API

        Returns:
            Dictionary in YAML format, or None if invalid
        """
        key = condition.get("key", "Tag")
        value = condition.get("value", "")
        operator = condition.get("operator", "EQUALS")
        member_type = condition.get("member_type", "VirtualMachine")

        if not value:
            return None

        # Start with required field
        result: dict[str, Any] = {"value": value}

        # Only include non-default values to keep YAML clean
        if member_type != "VirtualMachine":
            result["member_type"] = member_type

        if key != "Tag":
            result["key"] = key

        if operator != "EQUALS":
            result["operator"] = operator

        return result

    def transform_service(self, api_service: dict) -> Optional[dict]:
        """
        Transform an NSX API service object to YAML format.

        Service Entry Types:
            - L4PortSetServiceEntry: TCP/UDP ports
            - ICMPTypeServiceEntry: ICMP type/code
            - IPProtocolServiceEntry: IP protocol numbers
            - IGMPTypeServiceEntry: IGMP
            - EtherTypeServiceEntry: Layer 2 protocols
            - ALGTypeServiceEntry: Application Layer Gateway
            - NestedServiceServiceEntry: Reference to another service

        Output YAML Format:
            name: my-service
            display_name: "My Service"
            description: "Optional description"
            ports:           # Simplified format when possible
              - 80/tcp
              - 443/tcp
            icmp_entries:    # ICMP-specific
              - protocol: ICMPv4
                icmp_type: 8
            members:         # Nested services
              services:
                - DNS
                - NTP

        Args:
            api_service: Service object from NSX API

        Returns:
            Dictionary in YAML format, or None if should be skipped
        """
        # Skip predefined NSX services
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

        # Collectors for different entry types
        ports: List[str] = []                    # Simplified "port/protocol" format
        l4_entries: List[dict] = []              # Verbose L4 entries
        icmp_entries: List[dict] = []            # ICMP entries
        ip_protocol_entries: List[dict] = []     # IP protocol entries
        igmp_entries: List[dict] = []            # IGMP entries
        ether_type_entries: List[dict] = []      # EtherType entries
        algorithm_entries: List[dict] = []       # ALG entries
        nested_services: List[str] = []          # Nested service references

        for entry in service_entries:
            resource_type = entry.get("resource_type", "")

            if resource_type == "L4PortSetServiceEntry":
                transformed = self._transform_l4_entry(entry)
                if transformed:
                    if transformed.get("_simple"):
                        # Use simplified "port/protocol" format
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
                nested_path = entry.get("nested_service_path", "")
                if nested_path:
                    service_name = self.resolve_service_path_to_name(nested_path)
                    nested_services.append(service_name)

        # Add entries to result (only if non-empty)
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

        # Process resource tags
        tags = api_service.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    def _transform_l4_entry(self, entry: dict) -> Optional[dict]:
        """
        Transform an L4 port set entry to YAML format.

        Tries to use simplified "port/protocol" format when possible:
            80/tcp, 443/tcp, 53/udp

        Falls back to verbose format for complex cases:
            protocol: TCP
            destination_ports: [80, 443]
            source_ports: [1024-65535]

        Args:
            entry: L4PortSetServiceEntry from NSX API

        Returns:
            Dictionary with either "_simple" key (simplified) or full format
        """
        protocol = entry.get("l4_protocol", "TCP")
        dest_ports = entry.get("destination_ports", [])
        source_ports = entry.get("source_ports", [])
        display_name = entry.get("display_name", "")

        # Try simplified format: single dest port, no source port
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
        """Transform an ALG (Application Layer Gateway) entry to YAML format."""
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
        """
        Transform an NSX API policy object to YAML format.

        Output YAML Format:
            name: policy-id
            display_name: "My Policy"
            description: "Optional description"
            category: Application
            rules:
              - display_name: "Allow Web Traffic"
                action: ALLOW
                source_groups: [web-servers]
                destination_groups: [db-servers]
                services: [HTTPS, HTTP]
                logged: true
            tags:
              - scope: managed-by
                tag: terraform

        Args:
            api_policy: Policy object from NSX API
            include_disabled_rules: Whether to include disabled rules

        Returns:
            Dictionary in YAML format, or None if should be skipped
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

        # Policy category (determines evaluation order)
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

        # Process resource tags
        tags = api_policy.get("tags", [])
        if tags:
            result["tags"] = [{"scope": t.get("scope", ""), "tag": t.get("tag", "")} for t in tags]

        return result

    def _transform_rule(self, api_rule: dict) -> Optional[dict]:
        """
        Transform an NSX API rule to YAML format.

        Rule Fields:
            - display_name: Rule name
            - action: ALLOW, DROP, or REJECT
            - source_groups: List of source group paths (resolved to names)
            - destination_groups: List of destination group paths
            - services: List of service paths (resolved to names)
            - direction: IN_OUT (default), IN, or OUT
            - logged: Enable logging
            - disabled: Rule is disabled
            - sources_excluded: Negate source groups
            - destinations_excluded: Negate destination groups

        Args:
            api_rule: Rule object from NSX API

        Returns:
            Dictionary in YAML format
        """
        result: dict[str, Any] = {"display_name": api_rule.get("display_name", "unnamed")}

        if api_rule.get("description"):
            result["description"] = api_rule["description"]

        # Action is required
        action = api_rule.get("action", "ALLOW")
        result["action"] = action

        # Source groups (resolve paths to names)
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

        # Source exclusion (negate)
        if api_rule.get("sources_excluded", False):
            result["sources_excluded"] = True

        # Destination groups (resolve paths to names)
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

        # Destination exclusion (negate)
        if api_rule.get("destinations_excluded", False):
            result["destinations_excluded"] = True

        # Services (resolve paths to names)
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
    # EXPORT METHODS
    # =========================================================================

    def export_all(
        self,
        output_dir: str,
        skip_predefined_services: bool = True,
        include_disabled_rules: bool = False,
        generate_imports: bool = False,
        groups_module: str = "security_groups",
        services_module: str = "services",
        policies_module: str = "security_policies",
    ) -> dict:
        """
        Export all DFW configurations to YAML files.

        This is the main entry point for exporting. It:
            1. Pre-fetches VMs and segments for name resolution
            2. Exports security groups to security_groups.yaml
            3. Exports custom services to services.yaml
            4. Exports policies and rules to security_policies.yaml
            5. Optionally generates Terraform import blocks (imports.tf)

        Args:
            output_dir: Directory to write YAML files (created if not exists)
            skip_predefined_services: Skip built-in NSX services
            include_disabled_rules: Include disabled rules in export
            generate_imports: Generate Terraform import blocks (imports.tf)
            groups_module: Terraform module name for security groups
            services_module: Terraform module name for services
            policies_module: Terraform module name for security policies

        Returns:
            Dictionary with counts: {groups, services, policies, rules}

        Example:
            counts = exporter.export_all(output_dir="./exported")
            print(f"Exported {counts['groups']} groups, {counts['rules']} rules")
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        counts = {"groups": 0, "services": 0, "policies": 0, "rules": 0}

        # ---------------------------------------------------------------------
        # Pre-fetch VMs and segments for name resolution
        # ---------------------------------------------------------------------
        print("Fetching VMs for name resolution...")
        self.get_vms()
        print(f"  Cached {len(self._vm_cache)} VMs")

        print("Fetching segments for name resolution...")
        self.get_segments()
        print(f"  Cached {len(self._segment_cache)} segments")

        # ---------------------------------------------------------------------
        # Export security groups
        # ---------------------------------------------------------------------
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

        # ---------------------------------------------------------------------
        # Export services
        # ---------------------------------------------------------------------
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

        # ---------------------------------------------------------------------
        # Export policies and rules
        # ---------------------------------------------------------------------
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

        # ---------------------------------------------------------------------
        # Generate Terraform import blocks (optional)
        # ---------------------------------------------------------------------
        if generate_imports:
            print("\nGenerating Terraform import blocks...")
            imports_file = self.write_import_blocks(
                output_path,
                transformed_groups,
                transformed_services,
                transformed_policies,
                groups_module=groups_module,
                services_module=services_module,
                policies_module=policies_module,
            )
            total_imports = counts["groups"] + counts["services"] + counts["policies"]
            print(f"  Wrote {total_imports} import blocks to {imports_file}")

        return counts

    def _write_yaml(self, path: Path, data: dict, header: str = "") -> None:
        """
        Write data to a YAML file with optional header comment.

        Features:
            - Adds descriptive header comment
            - Uses block style for readability
            - Preserves key order (no sorting)
            - Handles multiline strings with | style

        Args:
            path: Output file path
            data: Dictionary to write as YAML
            header: Optional comment header (added before YAML)
        """
        # Custom representer for clean multiline string output
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
                default_flow_style=False,  # Use block style, not inline
                sort_keys=False,            # Preserve key order
                allow_unicode=True,         # Support Unicode characters
                width=120,                  # Line width for wrapping
            )

    # =========================================================================
    # YAML FILE HEADERS
    # =========================================================================
    # These provide helpful documentation at the top of each exported file.

    def _get_groups_header(self) -> str:
        """Header comment for security_groups.yaml."""
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
        """Header comment for services.yaml."""
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
        """Header comment for security_policies.yaml."""
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

    # =========================================================================
    # TERRAFORM IMPORT BLOCK GENERATION
    # =========================================================================

    def generate_import_blocks(
        self,
        groups: List[dict],
        services: List[dict],
        policies: List[dict],
        module_prefix: str = "module.",
        groups_module: str = "security_groups",
        services_module: str = "services",
        policies_module: str = "security_policies",
    ) -> str:
        """
        Generate Terraform import blocks for existing NSX resources.

        These import blocks allow Terraform to adopt existing NSX resources
        into its state without recreating them. Use with:
            terraform plan -generate-config-out=generated.tf
            terraform apply

        Import Block Format (Terraform 1.5+):
            import {
              to = module.security_groups.nsxt_policy_group.this["group-name"]
              id = "/infra/domains/default/groups/group-name"
            }

        Args:
            groups: List of transformed group objects
            services: List of transformed service objects
            policies: List of transformed policy objects
            module_prefix: Prefix for module references (default: "module.")
            groups_module: Module name for security groups
            services_module: Module name for services
            policies_module: Module name for security policies

        Returns:
            String containing all import blocks for imports.tf
        """
        lines = []

        # Header
        lines.append("# =============================================================================")
        lines.append("# Terraform Import Blocks")
        lines.append("# =============================================================================")
        lines.append("# Generated by NSX Exporter")
        lines.append("#")
        lines.append("# These import blocks allow Terraform to adopt existing NSX resources.")
        lines.append("# ")
        lines.append("# USAGE:")
        lines.append("#   1. Review this file and remove any resources you don't want to import")
        lines.append("#   2. Run: terraform plan")
        lines.append("#   3. Verify the plan shows 'import' actions (not 'create')")
        lines.append("#   4. Run: terraform apply")
        lines.append("#   5. After successful import, you can delete this file")
        lines.append("#")
        lines.append("# REQUIREMENTS:")
        lines.append("#   - Terraform 1.5+ (for import blocks)")
        lines.append("#   - Matching YAML configuration files in data/ directory")
        lines.append("# =============================================================================")
        lines.append("")

        # Generate import blocks for security groups
        if groups:
            lines.append("# -----------------------------------------------------------------------------")
            lines.append("# Security Groups")
            lines.append("# -----------------------------------------------------------------------------")
            lines.append("")
            for group in groups:
                name = group.get("name", "")
                if not name:
                    continue
                # Build the NSX path
                nsx_path = f"/infra/domains/{self.domain}/groups/{name}"
                # Build the Terraform resource address
                tf_address = f'{module_prefix}{groups_module}.nsxt_policy_group.this["{name}"]'
                lines.append("import {")
                lines.append(f'  to = {tf_address}')
                lines.append(f'  id = "{nsx_path}"')
                lines.append("}")
                lines.append("")

        # Generate import blocks for services
        if services:
            lines.append("# -----------------------------------------------------------------------------")
            lines.append("# Services")
            lines.append("# -----------------------------------------------------------------------------")
            lines.append("")
            for service in services:
                name = service.get("name", "")
                if not name:
                    continue
                # Build the NSX path
                nsx_path = f"/infra/services/{name}"
                # Build the Terraform resource address
                tf_address = f'{module_prefix}{services_module}.nsxt_policy_service.this["{name}"]'
                lines.append("import {")
                lines.append(f'  to = {tf_address}')
                lines.append(f'  id = "{nsx_path}"')
                lines.append("}")
                lines.append("")

        # Generate import blocks for security policies
        if policies:
            lines.append("# -----------------------------------------------------------------------------")
            lines.append("# Security Policies")
            lines.append("# -----------------------------------------------------------------------------")
            lines.append("")
            for policy in policies:
                name = policy.get("name", "")
                if not name:
                    continue
                # Build the NSX path
                nsx_path = f"/infra/domains/{self.domain}/security-policies/{name}"
                # Build the Terraform resource address
                tf_address = f'{module_prefix}{policies_module}.nsxt_policy_security_policy.this["{name}"]'
                lines.append("import {")
                lines.append(f'  to = {tf_address}')
                lines.append(f'  id = "{nsx_path}"')
                lines.append("}")
                lines.append("")

        return "\n".join(lines)

    def write_import_blocks(
        self,
        output_path: Path,
        groups: List[dict],
        services: List[dict],
        policies: List[dict],
        **kwargs,
    ) -> Path:
        """
        Write Terraform import blocks to imports.tf file.

        Args:
            output_path: Directory to write the file
            groups: List of transformed group objects
            services: List of transformed service objects
            policies: List of transformed policy objects
            **kwargs: Additional arguments passed to generate_import_blocks()

        Returns:
            Path to the written imports.tf file
        """
        content = self.generate_import_blocks(groups, services, policies, **kwargs)
        imports_file = output_path / "imports.tf"
        with open(imports_file, "w") as f:
            f.write(content)
        return imports_file


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """
    Main entry point for the NSX exporter CLI.

    Handles:
        - Command-line argument parsing
        - Environment variable fallbacks
        - Password input (file, argument, or interactive)
        - Error handling with helpful messages
    """
    # -------------------------------------------------------------------------
    # Argument Parser Setup
    # -------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="Export NSX-T DFW configurations to YAML format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage (prompts for password)
    %(prog)s --host nsx.example.com --username admin --output data/

    # With password file (recommended for special characters)
    %(prog)s --host nsx.example.com --username admin \\
        --password-file /path/to/password.txt --output data/

    # Using environment variables
    export NSX_HOST=nsx.example.com
    export NSX_USERNAME=admin
    export NSX_PASSWORD='MyP@ssw0rd!'
    %(prog)s --output data/

    # Include disabled rules and predefined services
    %(prog)s --host nsx.example.com --username admin \\
        --password-file /path/to/password.txt --output data/ \\
        --include-predefined-services --include-disabled-rules

    # Generate Terraform import blocks for existing resources
    %(prog)s --host nsx.example.com --username admin \\
        --password-file /path/to/password.txt --output data/ \\
        --generate-imports

    # Generate imports with custom module names
    %(prog)s --host nsx.example.com --username admin \\
        --password-file /path/to/password.txt --output data/ \\
        --generate-imports --groups-module my_groups --policies-module my_policies

Environment Variables:
    NSX_HOST      NSX Manager hostname (alternative to --host)
    NSX_USERNAME  API username (alternative to --username)
    NSX_PASSWORD  API password (alternative to --password)
""",
    )

    # Connection arguments
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
        help="Read NSX API password from file (avoids shell escaping issues with special characters)",
    )

    # Output arguments
    parser.add_argument(
        "--output", "-o",
        default="data",
        help="Output directory for YAML files (default: data)",
    )
    parser.add_argument(
        "--domain",
        default="default",
        help="NSX domain for security policies (default: default)",
    )

    # Filter arguments
    parser.add_argument(
        "--skip-predefined-services",
        action="store_true",
        default=True,
        help="Skip predefined NSX services (default: true)",
    )
    parser.add_argument(
        "--include-predefined-services",
        action="store_true",
        help="Include predefined NSX services in export",
    )
    parser.add_argument(
        "--include-disabled-rules",
        action="store_true",
        help="Include disabled rules in export",
    )

    # Terraform import arguments
    parser.add_argument(
        "--generate-imports",
        action="store_true",
        help="Generate Terraform import blocks (imports.tf) for existing NSX resources",
    )
    parser.add_argument(
        "--groups-module",
        default="security_groups",
        help="Terraform module name for security groups (default: security_groups)",
    )
    parser.add_argument(
        "--services-module",
        default="services",
        help="Terraform module name for services (default: services)",
    )
    parser.add_argument(
        "--policies-module",
        default="security_policies",
        help="Terraform module name for security policies (default: security_policies)",
    )

    # Other arguments
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: false for self-signed certs)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (show stack traces on error)",
    )

    args = parser.parse_args()

    # -------------------------------------------------------------------------
    # Validate Required Arguments
    # -------------------------------------------------------------------------
    if not args.host:
        parser.error("--host is required (or set NSX_HOST environment variable)")

    if not args.username:
        parser.error("--username is required (or set NSX_USERNAME environment variable)")

    # -------------------------------------------------------------------------
    # Get Password (file > argument > environment > interactive)
    # -------------------------------------------------------------------------
    password = None
    if args.password_file:
        # Read from file (best for passwords with special characters like !)
        password = args.password_file.read_text().strip()
    elif args.password:
        # From command line argument
        password = args.password
    else:
        # Interactive prompt (most secure, but not scriptable)
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    # Handle --include-predefined-services flag
    skip_predefined = args.skip_predefined_services
    if args.include_predefined_services:
        skip_predefined = False

    # -------------------------------------------------------------------------
    # Print Configuration Summary
    # -------------------------------------------------------------------------
    print("NSX-T DFW Configuration Exporter")
    print("================================")
    print(f"Host: {args.host}")
    print(f"Domain: {args.domain}")
    print(f"Output: {args.output}")
    print(f"Skip predefined services: {skip_predefined}")
    print(f"Include disabled rules: {args.include_disabled_rules}")
    print(f"Generate import blocks: {args.generate_imports}")
    if args.generate_imports:
        print(f"  Groups module:   {args.groups_module}")
        print(f"  Services module: {args.services_module}")
        print(f"  Policies module: {args.policies_module}")
    print()

    # -------------------------------------------------------------------------
    # Run Export
    # -------------------------------------------------------------------------
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
            generate_imports=args.generate_imports,
            groups_module=args.groups_module,
            services_module=args.services_module,
            policies_module=args.policies_module,
        )

        # Print summary
        print()
        print("=" * 50)
        print("Export Summary")
        print("=" * 50)
        print(f"Security Groups: {counts['groups']}")
        print(f"Services:        {counts['services']}")
        print(f"Policies:        {counts['policies']}")
        print(f"Rules:           {counts['rules']}")
        if args.generate_imports:
            total_imports = counts['groups'] + counts['services'] + counts['policies']
            print(f"Import Blocks:   {total_imports}")
        print()
        print("Export completed successfully!")
        if args.generate_imports:
            print()
            print("Next steps to import existing resources into Terraform:")
            print("  1. Review imports.tf and remove any resources you don't want to import")
            print("  2. Run: terraform plan")
            print("  3. Verify the plan shows 'import' actions (not 'create')")
            print("  4. Run: terraform apply")
            print("  5. After successful import, delete imports.tf")

    # -------------------------------------------------------------------------
    # Error Handling
    # -------------------------------------------------------------------------
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


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
