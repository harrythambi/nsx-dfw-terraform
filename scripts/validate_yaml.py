#!/usr/bin/env python3
"""
NSX-T DFW Terraform YAML Configuration Validator

This script validates YAML configuration files against JSON schemas and checks for:
- Schema compliance
- Duplicate names
- Cross-file reference integrity

Usage:
    python validate_yaml.py [--data-dir DATA_DIR] [--schema-dir SCHEMA_DIR]
    python validate_yaml.py --help

Examples:
    # Validate files in default locations
    python scripts/validate_yaml.py

    # Validate specific directory
    python scripts/validate_yaml.py --data-dir examples/basic/data

    # Validate with custom schema directory
    python scripts/validate_yaml.py --data-dir data --schema-dir schemas
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

try:
    import jsonschema
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    print("ERROR: jsonschema is required. Install with: pip install jsonschema")
    sys.exit(1)


class ValidationResult:
    """Holds validation results."""

    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def print_results(self) -> None:
        if self.warnings:
            print("\nWarnings:")
            for warning in self.warnings:
                print(f"  [WARN] {warning}")

        if self.errors:
            print("\nErrors:")
            for error in self.errors:
                print(f"  [ERROR] {error}")

        if self.is_valid:
            print("\n[OK] Validation passed!")
        else:
            print(f"\n[FAIL] Validation failed with {len(self.errors)} error(s)")


def load_yaml_file(file_path: Path) -> dict[str, Any] | None:
    """Load and parse a YAML file."""
    try:
        with open(file_path, "r") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse YAML file {file_path}: {e}")
        return None
    except FileNotFoundError:
        print(f"ERROR: File not found: {file_path}")
        return None


def load_json_schema(file_path: Path) -> dict[str, Any] | None:
    """Load and parse a JSON schema file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON schema {file_path}: {e}")
        return None
    except FileNotFoundError:
        print(f"ERROR: Schema file not found: {file_path}")
        return None


def validate_against_schema(
    data: dict[str, Any], schema: dict[str, Any], file_name: str, result: ValidationResult
) -> None:
    """Validate data against a JSON schema."""
    try:
        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(data))

        for error in errors:
            path = " -> ".join(str(p) for p in error.absolute_path) if error.absolute_path else "root"
            result.add_error(f"{file_name}: {error.message} (at {path})")

    except Exception as e:
        result.add_error(f"{file_name}: Schema validation error: {e}")


def check_duplicate_names(items: list[dict], item_type: str, result: ValidationResult) -> set[str]:
    """Check for duplicate names in a list of items."""
    names: set[str] = set()
    duplicates: set[str] = set()

    for item in items:
        name = item.get("name") or item.get("display_name", "")
        if name in names:
            duplicates.add(name)
        names.add(name)

    for dup in duplicates:
        result.add_error(f"Duplicate {item_type} name: '{dup}'")

    return names


def validate_cross_references(
    policies_data: dict[str, Any] | None,
    group_names: set[str],
    service_names: set[str],
    result: ValidationResult,
) -> None:
    """Validate that policy references point to defined groups and services."""
    if not policies_data:
        return

    policies = policies_data.get("security_policies", [])

    # List of predefined NSX services that are commonly available
    predefined_services = {
        "DNS", "DNS-UDP", "NTP", "HTTP", "HTTPS", "SSH", "RDP", "FTP",
        "TFTP", "SMTP", "LDAP", "LDAPS", "MySQL", "SMB", "ICMP-ALL",
        "ICMPv6-ALL", "SNMP", "Syslog-UDP", "Syslog-TCP", "AD-Server",
        "DHCP-Server", "DHCP-Client", "Kerberos", "Radius", "vMotion",
    }

    for policy in policies:
        policy_name = policy.get("name", policy.get("display_name", "unnamed"))

        # Check policy scope
        for scope_ref in policy.get("scope", []):
            if not _is_valid_reference(scope_ref, group_names):
                result.add_warning(
                    f"Policy '{policy_name}' scope references unknown group: '{scope_ref}'"
                )

        # Check rules
        for rule in policy.get("rules", []):
            rule_name = rule.get("display_name", "unnamed")

            # Check source_groups
            for ref in rule.get("source_groups", []) or []:
                if not _is_valid_reference(ref, group_names):
                    result.add_warning(
                        f"Rule '{rule_name}' in policy '{policy_name}' "
                        f"references unknown source group: '{ref}'"
                    )

            # Check destination_groups
            for ref in rule.get("destination_groups", []) or []:
                if not _is_valid_reference(ref, group_names):
                    result.add_warning(
                        f"Rule '{rule_name}' in policy '{policy_name}' "
                        f"references unknown destination group: '{ref}'"
                    )

            # Check services
            for ref in rule.get("services", []) or []:
                if not _is_valid_reference(ref, service_names, predefined_services):
                    result.add_warning(
                        f"Rule '{rule_name}' in policy '{policy_name}' "
                        f"references unknown service: '{ref}'"
                    )

            # Check rule-level scope
            for scope_ref in rule.get("scope", []) or []:
                if not _is_valid_reference(scope_ref, group_names):
                    result.add_warning(
                        f"Rule '{rule_name}' in policy '{policy_name}' "
                        f"scope references unknown group: '{scope_ref}'"
                    )


def _is_valid_reference(ref: str, defined_names: set[str], additional_valid: set[str] | None = None) -> bool:
    """Check if a reference is valid."""
    # "ANY" keyword is always valid
    if ref.upper() == "ANY":
        return True

    # Full NSX paths are assumed valid (starts with /)
    if ref.startswith("/"):
        return True

    # Check against defined names
    if ref in defined_names:
        return True

    # Check against additional valid names (e.g., predefined services)
    if additional_valid and ref in additional_valid:
        return True

    return False


def validate_group_member_groups(groups_data: dict[str, Any] | None, result: ValidationResult) -> None:
    """Validate member_groups references within security groups."""
    if not groups_data:
        return

    groups = groups_data.get("security_groups", [])
    group_names = {g.get("name", g.get("display_name", "")) for g in groups}

    for group in groups:
        group_name = group.get("name", group.get("display_name", "unnamed"))

        for member_ref in group.get("member_groups", []) or []:
            if not member_ref.startswith("/") and member_ref not in group_names:
                result.add_warning(
                    f"Group '{group_name}' references unknown member group: '{member_ref}'"
                )


def validate_service_nested_entries(services_data: dict[str, Any] | None, result: ValidationResult) -> None:
    """Validate nested_service_entries references within services."""
    if not services_data:
        return

    services = services_data.get("services", [])
    service_names = {s.get("name", s.get("display_name", "")) for s in services}

    # Predefined services
    predefined_services = {
        "DNS", "DNS-UDP", "NTP", "HTTP", "HTTPS", "SSH", "RDP", "FTP",
        "TFTP", "SMTP", "LDAP", "LDAPS", "MySQL", "SMB", "ICMP-ALL",
        "ICMPv6-ALL", "SNMP", "Syslog-UDP", "Syslog-TCP",
    }

    for service in services:
        service_name = service.get("name", service.get("display_name", "unnamed"))

        for entry in service.get("nested_service_entries", []) or []:
            ref = entry.get("service_name") or entry.get("nested_service_path", "")

            if ref and not ref.startswith("/"):
                if ref not in service_names and ref not in predefined_services:
                    result.add_warning(
                        f"Service '{service_name}' references unknown nested service: '{ref}'"
                    )


def validate_action_required(policies_data: dict[str, Any] | None, result: ValidationResult) -> None:
    """Validate that all rules have an action specified."""
    if not policies_data:
        return

    policies = policies_data.get("security_policies", [])

    for policy in policies:
        policy_name = policy.get("name", policy.get("display_name", "unnamed"))

        for rule in policy.get("rules", []):
            rule_name = rule.get("display_name", "unnamed")

            if "action" not in rule:
                result.add_error(
                    f"Rule '{rule_name}' in policy '{policy_name}' is missing required 'action' field"
                )
            elif rule["action"].upper() not in ["ALLOW", "DROP", "REJECT"]:
                result.add_error(
                    f"Rule '{rule_name}' in policy '{policy_name}' has invalid action: '{rule['action']}'. "
                    "Must be ALLOW, DROP, or REJECT"
                )


def main():
    parser = argparse.ArgumentParser(
        description="Validate NSX-T DFW Terraform YAML configuration files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                                    # Validate with defaults
    %(prog)s --data-dir examples/basic/data     # Validate specific data dir
    %(prog)s --schema-dir custom/schemas        # Use custom schemas
        """,
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Directory containing YAML data files (default: data)",
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=Path("schemas"),
        help="Directory containing JSON schema files (default: schemas)",
    )
    parser.add_argument(
        "--skip-schema",
        action="store_true",
        help="Skip JSON schema validation",
    )
    parser.add_argument(
        "--skip-references",
        action="store_true",
        help="Skip cross-reference validation",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Resolve paths relative to script location if needed
    script_dir = Path(__file__).parent.parent
    data_dir = args.data_dir if args.data_dir.is_absolute() else script_dir / args.data_dir
    schema_dir = args.schema_dir if args.schema_dir.is_absolute() else script_dir / args.schema_dir

    result = ValidationResult()

    print(f"Validating YAML files in: {data_dir}")
    print(f"Using schemas from: {schema_dir}")

    # Define file mappings
    files = {
        "security_groups": {
            "yaml": data_dir / "security_groups.yaml",
            "schema": schema_dir / "security_groups.schema.json",
        },
        "services": {
            "yaml": data_dir / "services.yaml",
            "schema": schema_dir / "services.schema.json",
        },
        "security_policies": {
            "yaml": data_dir / "security_policies.yaml",
            "schema": schema_dir / "security_policies.schema.json",
        },
    }

    # Load all YAML files
    data = {}
    for name, paths in files.items():
        if paths["yaml"].exists():
            if args.verbose:
                print(f"Loading {paths['yaml']}...")
            data[name] = load_yaml_file(paths["yaml"])
            if data[name] is None:
                result.add_error(f"Failed to load {paths['yaml']}")
        else:
            if args.verbose:
                print(f"Skipping {paths['yaml']} (not found)")
            data[name] = None

    # Validate against schemas
    if not args.skip_schema:
        print("\nValidating against JSON schemas...")
        for name, paths in files.items():
            if data[name] and paths["schema"].exists():
                schema = load_json_schema(paths["schema"])
                if schema:
                    if args.verbose:
                        print(f"  Validating {name}...")
                    validate_against_schema(
                        data[name], schema, paths["yaml"].name, result
                    )

    # Check for duplicate names
    print("\nChecking for duplicate names...")
    group_names: set[str] = set()
    service_names: set[str] = set()

    if data.get("security_groups"):
        group_names = check_duplicate_names(
            data["security_groups"].get("security_groups", []),
            "security group",
            result,
        )

    if data.get("services"):
        service_names = check_duplicate_names(
            data["services"].get("services", []),
            "service",
            result,
        )

    if data.get("security_policies"):
        check_duplicate_names(
            data["security_policies"].get("security_policies", []),
            "security policy",
            result,
        )

    # Validate action is required
    print("\nValidating required fields...")
    validate_action_required(data.get("security_policies"), result)

    # Validate cross-references
    if not args.skip_references:
        print("\nValidating cross-references...")
        validate_cross_references(
            data.get("security_policies"),
            group_names,
            service_names,
            result,
        )
        validate_group_member_groups(data.get("security_groups"), result)
        validate_service_nested_entries(data.get("services"), result)

    # Print results
    result.print_results()

    sys.exit(0 if result.is_valid else 1)


if __name__ == "__main__":
    main()
