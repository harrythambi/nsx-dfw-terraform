# =============================================================================
# Local Variables - Data Processing and Validation
# =============================================================================
#
# This file handles all data processing between YAML files and Terraform
# modules. It performs:
#
# 1. FILE LOADING:
#    - Reads YAML or JSON configuration files
#    - Auto-detects file format by extension
#
# 2. DATA TRANSFORMATION:
#    - Converts lists to maps keyed by resource name
#    - Preserves definition order using indices
#    - Generates preliminary paths for cross-references
#
# 3. SEQUENCE NUMBER CALCULATION:
#    - Groups policies by category
#    - Calculates sequence numbers within each category
#    - Allows explicit overrides
#
# 4. VALIDATION:
#    - Detects duplicate names (groups, services, policies)
#    - Fails with clear error messages
#
# Data flow:
#   YAML Files → Raw Data → Processed Data → Module Variables → NSX Resources
#
# =============================================================================

locals {
  # Load data from YAML or JSON files
  security_groups_raw = (
    can(regex("\\.ya?ml$", var.security_groups_file)) ?
    yamldecode(file(var.security_groups_file)) :
    jsondecode(file(var.security_groups_file))
  )

  services_raw = (
    can(regex("\\.ya?ml$", var.services_file)) ?
    yamldecode(file(var.services_file)) :
    jsondecode(file(var.services_file))
  )

  security_policies_raw = (
    can(regex("\\.ya?ml$", var.security_policies_file)) ?
    yamldecode(file(var.security_policies_file)) :
    jsondecode(file(var.security_policies_file))
  )

  # ===========================================================================
  # Security Groups Processing
  # ===========================================================================

  # Process security groups - maintain order with index
  security_groups_list = lookup(local.security_groups_raw, "security_groups", [])
  security_groups_with_index = {
    for idx, group in local.security_groups_list :
    lookup(group, "name", lookup(group, "display_name", "group-${idx}")) => group
  }

  # Build a preliminary group path lookup for resolving member_groups references
  # This is used to resolve group names to paths within the security groups module
  preliminary_group_paths = {
    for idx, group in local.security_groups_list :
    lookup(group, "name", lookup(group, "display_name", "group-${idx}")) =>
    "/infra/domains/${var.domain}/groups/${lookup(group, "name", lookup(group, "display_name", "group-${idx}"))}"
  }

  # ===========================================================================
  # Services Processing
  # ===========================================================================

  # Process services - maintain order with index
  services_list = lookup(local.services_raw, "services", [])
  services_with_index = {
    for idx, svc in local.services_list :
    lookup(svc, "name", lookup(svc, "display_name", "service-${idx}")) => svc
  }

  # Build a preliminary service path lookup for nested service references
  preliminary_service_paths = {
    for idx, svc in local.services_list :
    lookup(svc, "name", lookup(svc, "display_name", "service-${idx}")) =>
    "/infra/services/${lookup(svc, "name", lookup(svc, "display_name", "service-${idx}"))}"
  }

  # ===========================================================================
  # Security Policies Processing
  # ===========================================================================

  # Process security policies with category-based sequence numbers
  policies_list = lookup(local.security_policies_raw, "security_policies", [])

  # Category-based starting sequence numbers
  category_sequence_start = {
    "Emergency"      = 100
    "Infrastructure" = 1000
    "Environment"    = 2000
    "Application"    = 3000
  }

  # Group policies by category for proper sequence number calculation
  policies_by_category = {
    for cat in ["Emergency", "Infrastructure", "Environment", "Application"] : cat => [
      for idx, policy in local.policies_list : {
        index  = idx
        name   = lookup(policy, "name", lookup(policy, "display_name", "policy-${idx}"))
        policy = policy
      }
      if lookup(policy, "category", "Application") == cat
    ]
  }

  # Calculate sequence numbers respecting category-based starting points
  policies_processed = {
    for idx, policy in local.policies_list :
    lookup(policy, "name", lookup(policy, "display_name", "policy-${idx}")) => merge(
      policy,
      {
        # Use explicit sequence_number if provided, otherwise calculate based on category
        sequence_number = lookup(policy, "sequence_number", null) != null ? (
          policy.sequence_number
          ) : (
          # Category-based sequence: category_start + (position_in_category * increment)
          lookup(local.category_sequence_start, lookup(policy, "category", "Application"), 3000) +
          (
            # Find position within category
            index([
              for p in local.policies_by_category[lookup(policy, "category", "Application")] : p.name
            ], lookup(policy, "name", lookup(policy, "display_name", "policy-${idx}"))) *
            var.policy_sequence_increment
          )
        )

        # Process rules with auto-calculated sequence numbers
        rules = [
          for rule_idx, rule in lookup(policy, "rules", []) : merge(
            rule,
            {
              sequence_number = lookup(rule, "sequence_number", var.rule_sequence_start + (rule_idx * var.rule_sequence_increment))
            }
          )
        ]
      }
    )
  }

  # ===========================================================================
  # Duplicate Name Detection
  # ===========================================================================

  # Check for duplicate group names
  group_names = [for g in local.security_groups_list : lookup(g, "name", lookup(g, "display_name", ""))]
  duplicate_group_names = [
    for name in distinct(local.group_names) : name
    if length([for n in local.group_names : n if n == name]) > 1
  ]

  # Check for duplicate service names
  service_names = [for s in local.services_list : lookup(s, "name", lookup(s, "display_name", ""))]
  duplicate_service_names = [
    for name in distinct(local.service_names) : name
    if length([for n in local.service_names : n if n == name]) > 1
  ]

  # Check for duplicate policy names
  policy_names = [for p in local.policies_list : lookup(p, "name", lookup(p, "display_name", ""))]
  duplicate_policy_names = [
    for name in distinct(local.policy_names) : name
    if length([for n in local.policy_names : n if n == name]) > 1
  ]

  # Validation - fail if duplicates found
  validate_no_duplicate_groups = (
    length(local.duplicate_group_names) > 0 ?
    file("ERROR: Duplicate security group names found: ${join(", ", local.duplicate_group_names)}") :
    true
  )

  validate_no_duplicate_services = (
    length(local.duplicate_service_names) > 0 ?
    file("ERROR: Duplicate service names found: ${join(", ", local.duplicate_service_names)}") :
    true
  )

  validate_no_duplicate_policies = (
    length(local.duplicate_policy_names) > 0 ?
    file("ERROR: Duplicate policy names found: ${join(", ", local.duplicate_policy_names)}") :
    true
  )
}
