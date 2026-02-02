# =============================================================================
# NSX-T Security Policies (nsxt_policy_security_policy)
# =============================================================================
# Supports:
# - ALLOW, DROP, REJECT actions
# - Category-based sequence numbering (Infrastructure=1000, Environment=2000, Application=3000)
# - Explicit sequence_number that overrides auto-calculation
# - Collision detection for sequence numbers
# - Rule-level scope and tags
# - Reference validation with clear error messages
# - "ANY" keyword (case-insensitive) for explicit any match
# - Empty arrays [] also mean "any"
# - Defaults: direction=IN_OUT, logged=false, action=REQUIRED
# =============================================================================

locals {
  # Build lookup maps for group and service references
  group_lookup   = var.security_group_paths
  service_lookup = var.service_paths

  # Predefined NSX service paths for common services
  predefined_service_paths = {
    "DNS"        = "/infra/services/DNS"
    "DNS-UDP"    = "/infra/services/DNS-UDP"
    "NTP"        = "/infra/services/NTP"
    "HTTP"       = "/infra/services/HTTP"
    "HTTPS"      = "/infra/services/HTTPS"
    "SSH"        = "/infra/services/SSH"
    "RDP"        = "/infra/services/RDP"
    "FTP"        = "/infra/services/FTP"
    "SMTP"       = "/infra/services/SMTP"
    "LDAP"       = "/infra/services/LDAP"
    "LDAPS"      = "/infra/services/LDAPS"
    "MySQL"      = "/infra/services/MySQL"
    "SMB"        = "/infra/services/SMB"
    "ICMP-ALL"   = "/infra/services/ICMP-ALL"
    "ICMPv6-ALL" = "/infra/services/ICMPv6-ALL"
  }

  # Merged service lookup including predefined services
  all_service_lookup = merge(local.predefined_service_paths, local.service_lookup)

  # Category-based starting sequence numbers
  category_sequence_start = {
    "Emergency"      = 100
    "Infrastructure" = 1000
    "Environment"    = 2000
    "Application"    = 3000
  }

  # Valid actions for rules
  valid_actions = ["ALLOW", "DROP", "REJECT"]

  # Process policies - calculate sequence numbers and validate
  policies_with_sequence = {
    for name, policy in var.security_policies : name => merge(
      policy,
      {
        # Calculate sequence number based on category if not explicitly provided
        calculated_sequence = lookup(policy, "sequence_number", null) != null ? (
          policy.sequence_number
          ) : (
          lookup(local.category_sequence_start, lookup(policy, "category", "Application"), 3000) +
          (index([for p in values(var.security_policies) : p.display_name], policy.display_name) * var.policy_sequence_increment)
        )
      }
    )
  }

  # Collect all sequence numbers for collision detection
  all_sequence_numbers = [
    for name, policy in local.policies_with_sequence : {
      name     = name
      sequence = policy.calculated_sequence
      explicit = lookup(policy, "sequence_number", null) != null
    }
  ]

  # Find collisions (same sequence number used by different policies)
  sequence_collisions = {
    for item in local.all_sequence_numbers : item.name => [
      for other in local.all_sequence_numbers : other.name
      if other.sequence == item.sequence && other.name != item.name
    ]
  }

  # Validate and process policies
  processed_policies = {
    for name, policy in local.policies_with_sequence : name => merge(
      policy,
      {
        sequence_number = policy.calculated_sequence

        # Process rules with validation
        validated_rules = [
          for rule_idx, rule in lookup(policy, "rules", []) : merge(
            rule,
            {
              # Validate action is provided and valid
              validated_action = (
                lookup(rule, "action", null) == null ?
                file("ERROR: action is REQUIRED on every rule. Rule '${lookup(rule, "display_name", "unnamed")}' in policy '${name}' is missing action.") :
                (
                  !contains(local.valid_actions, upper(lookup(rule, "action", ""))) ?
                  file("ERROR: Invalid action '${lookup(rule, "action", "")}' in rule '${lookup(rule, "display_name", "unnamed")}'. Valid actions: ALLOW, DROP, REJECT") :
                  upper(rule.action)
                )
              )

              # Calculate rule sequence number
              rule_sequence = lookup(rule, "sequence_number", null) != null ? (
                rule.sequence_number
                ) : (
                var.rule_sequence_start + (rule_idx * var.rule_sequence_increment)
              )
            }
          )
        ]
      }
    )
  }

}

# Validation: Check for sequence number collisions
resource "null_resource" "validate_sequence_collisions" {
  for_each = {
    for name, collisions in local.sequence_collisions : name => collisions
    if length(collisions) > 0
  }

  triggers = {
    error = "ERROR: Sequence number collision detected. Policy '${each.key}' has the same sequence number as: ${join(", ", each.value)}"
  }

  lifecycle {
    precondition {
      condition     = length(each.value) == 0
      error_message = "Sequence number collision detected for policy '${each.key}'. Conflicting policies: ${join(", ", each.value)}"
    }
  }
}

resource "nsxt_policy_security_policy" "this" {
  for_each = var.security_policies

  display_name    = each.value.display_name
  description     = lookup(each.value, "description", null)
  category        = lookup(each.value, "category", "Application")
  domain          = var.domain
  sequence_number = local.processed_policies[each.key].sequence_number
  stateful        = lookup(each.value, "stateful", true)
  tcp_strict      = lookup(each.value, "tcp_strict", false)
  locked          = lookup(each.value, "locked", false)

  # Policy scope
  scope = lookup(each.value, "scope", null) != null ? [
    for s in each.value.scope : (
      # Handle "ANY" keyword
      upper(s) == "ANY" ? s :
      # Resolve group reference or use direct path
      lookup(local.group_lookup, s, null) != null ? local.group_lookup[s] : s
    )
  ] : null

  # Rules
  dynamic "rule" {
    for_each = [
      for idx, r in lookup(each.value, "rules", []) : merge(r, { _idx = idx })
    ]
    content {
      display_name = rule.value.display_name
      description  = lookup(rule.value, "description", null)

      # Rule sequence number
      sequence_number = lookup(rule.value, "sequence_number", null) != null ? (
        rule.value.sequence_number
        ) : (
        var.rule_sequence_start + (rule.value._idx * var.rule_sequence_increment)
      )

      # Action - REQUIRED, supports ALLOW, DROP, REJECT
      action = upper(rule.value.action)

      # Direction - defaults to IN_OUT
      direction = lookup(rule.value, "direction", "IN_OUT")

      # Source groups - resolve references or use direct paths
      # Empty list or null = any, "ANY" keyword = any
      source_groups = (
        lookup(rule.value, "source_groups", null) == null ||
        length(lookup(rule.value, "source_groups", [])) == 0 ||
        (length(lookup(rule.value, "source_groups", [])) == 1 && upper(lookup(rule.value, "source_groups", [""])[0]) == "ANY")
        ) ? null : [
        for g in rule.value.source_groups : (
          upper(g) == "ANY" ? g :
          lookup(local.group_lookup, g, null) != null ? local.group_lookup[g] :
          # Check if it looks like a path
          can(regex("^/", g)) ? g :
          # Fail with error if reference not found
          file("ERROR: Referenced group '${g}' not found in rule '${rule.value.display_name}' of policy '${each.value.display_name}'. Define the group in security_groups.yaml or use a full NSX path.")
        )
      ]

      # Destination groups - resolve references or use direct paths
      destination_groups = (
        lookup(rule.value, "destination_groups", null) == null ||
        length(lookup(rule.value, "destination_groups", [])) == 0 ||
        (length(lookup(rule.value, "destination_groups", [])) == 1 && upper(lookup(rule.value, "destination_groups", [""])[0]) == "ANY")
        ) ? null : [
        for g in rule.value.destination_groups : (
          upper(g) == "ANY" ? g :
          lookup(local.group_lookup, g, null) != null ? local.group_lookup[g] :
          can(regex("^/", g)) ? g :
          file("ERROR: Referenced group '${g}' not found in rule '${rule.value.display_name}' of policy '${each.value.display_name}'. Define the group in security_groups.yaml or use a full NSX path.")
        )
      ]

      sources_excluded      = lookup(rule.value, "sources_excluded", false)
      destinations_excluded = lookup(rule.value, "destinations_excluded", false)

      # Services - resolve references or use direct paths
      services = (
        lookup(rule.value, "services", null) == null ||
        length(lookup(rule.value, "services", [])) == 0 ||
        (length(lookup(rule.value, "services", [])) == 1 && upper(lookup(rule.value, "services", [""])[0]) == "ANY")
        ) ? null : [
        for s in rule.value.services : (
          upper(s) == "ANY" ? s :
          # Check local services first
          lookup(local.service_lookup, s, null) != null ? local.service_lookup[s] :
          # Check predefined services
          lookup(local.predefined_service_paths, s, null) != null ? local.predefined_service_paths[s] :
          # Check if it looks like a path
          can(regex("^/", s)) ? s :
          # Fail with error if reference not found
          file("ERROR: Referenced service '${s}' not found in rule '${rule.value.display_name}' of policy '${each.value.display_name}'. Define the service in services.yaml, use a predefined service name, or use a full NSX path.")
        )
      ]

      # Profiles
      profiles = lookup(rule.value, "profiles", null)

      ip_version = lookup(rule.value, "ip_version", "IPV4_IPV6")

      # Logged - defaults to false
      logged = lookup(rule.value, "logged", false)

      disabled  = lookup(rule.value, "disabled", false)
      notes     = lookup(rule.value, "notes", null)
      log_label = lookup(rule.value, "log_label", null)

      # Rule scope
      scope = lookup(rule.value, "scope", null) != null ? [
        for s in rule.value.scope : (
          upper(s) == "ANY" ? s :
          lookup(local.group_lookup, s, null) != null ? local.group_lookup[s] : s
        )
      ] : null

      # Rule-level tags
      dynamic "tag" {
        for_each = lookup(rule.value, "tags", [])
        content {
          scope = tag.value.scope
          tag   = tag.value.tag
        }
      }
    }
  }

  # Policy-level tags
  dynamic "tag" {
    for_each = concat(var.default_tags, lookup(each.value, "tags", []))
    content {
      scope = tag.value.scope
      tag   = tag.value.tag
    }
  }

  # Project context for multitenancy
  dynamic "context" {
    for_each = var.project_id != null ? [1] : []
    content {
      project_id = var.project_id
    }
  }

  depends_on = [null_resource.validate_sequence_collisions]
}
