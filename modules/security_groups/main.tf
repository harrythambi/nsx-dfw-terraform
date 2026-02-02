# =============================================================================
# NSX-T Security Groups (nsxt_policy_group)
# =============================================================================
# Supports:
# - Tag-based criteria
# - OS Name criteria (member_type: VirtualMachine, key: OSName)
# - Computer Name criteria (member_type: VirtualMachine, key: ComputerName)
# - IP Address expressions
# - MAC Address expressions
# - Path expressions (for nested groups / member_groups)
# - External ID expressions
# - Complex criteria_groups with AND/OR conjunctions
# =============================================================================

locals {
  # Flatten criteria_groups into criteria with proper conjunction handling
  # This processes both simple criteria and complex criteria_groups
  processed_groups = {
    for name, group in var.security_groups : name => merge(
      group,
      {
        # Process criteria from criteria_groups if present, otherwise use criteria directly
        processed_criteria = lookup(group, "criteria_groups", null) != null ? flatten([
          for cg_idx, cg in group.criteria_groups : concat(
            # Add criteria from this criteria_group
            [
              for c_idx, criteria in lookup(cg, "criteria", []) : merge(
                criteria,
                {
                  _cg_index = cg_idx
                  _c_index  = c_idx
                }
              )
            ],
            # Add conjunction after this criteria_group (except for last)
            cg_idx < length(group.criteria_groups) - 1 ? [
              {
                _is_conjunction = true
                _conjunction_operator = lookup(cg, "conjunction_with_next", "OR")
              }
            ] : []
          )
        ]) : lookup(group, "criteria", [])

        # Resolve member_groups to paths
        resolved_member_group_paths = lookup(group, "member_groups", null) != null ? [
          for mg in group.member_groups : (
            # Check if it's already a path (starts with /)
            can(regex("^/", mg)) ? mg : (
              # Look up in existing groups
              lookup(var.group_path_lookup, mg, null) != null ? var.group_path_lookup[mg] : (
                # Assume it's a name that will be created - construct the path
                "/infra/domains/${var.domain}/groups/${mg}"
              )
            )
          )
        ] : []
      }
    )
  }

  # Valid operators for condition-based criteria
  valid_operators = ["EQUALS", "CONTAINS", "STARTSWITH", "ENDSWITH", "NOTEQUALS"]
}

resource "nsxt_policy_group" "this" {
  for_each = local.processed_groups

  display_name = each.value.display_name
  description  = lookup(each.value, "description", null)
  domain       = var.domain

  # Standard criteria blocks
  dynamic "criteria" {
    for_each = [
      for c in each.value.processed_criteria : c
      if !lookup(c, "_is_conjunction", false)
    ]
    content {
      # VM Tag condition
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if lookup(cond, "type", lookup(cond, "key", "Tag")) == "Tag" ||
             (lookup(cond, "key", null) == "Tag" && lookup(cond, "type", null) == null)
        ]
        content {
          key         = "Tag"
          member_type = lookup(condition.value, "member_type", "VirtualMachine")
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # VM Name condition
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if lookup(cond, "type", lookup(cond, "key", "")) == "Name" ||
             lookup(cond, "key", null) == "Name"
        ]
        content {
          key         = "Name"
          member_type = lookup(condition.value, "member_type", "VirtualMachine")
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # OS Name condition
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if lookup(cond, "type", lookup(cond, "key", "")) == "OSName" ||
             lookup(cond, "key", null) == "OSName" ||
             lookup(cond, "type", null) == "os_name"
        ]
        content {
          key         = "OSName"
          member_type = "VirtualMachine"
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # Computer Name condition
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if lookup(cond, "type", lookup(cond, "key", "")) == "ComputerName" ||
             lookup(cond, "key", null) == "ComputerName" ||
             lookup(cond, "type", null) == "computer_name"
        ]
        content {
          key         = "ComputerName"
          member_type = "VirtualMachine"
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # Segment condition
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if lookup(cond, "member_type", "") == "Segment"
        ]
        content {
          key         = lookup(condition.value, "key", "Tag")
          member_type = "Segment"
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # SegmentPort condition
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if lookup(cond, "member_type", "") == "SegmentPort"
        ]
        content {
          key         = lookup(condition.value, "key", "Tag")
          member_type = "SegmentPort"
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # IP Address Expression
      dynamic "ip_address_expression" {
        for_each = lookup(criteria.value, "ip_addresses", null) != null ? [1] : []
        content {
          ip_addresses = criteria.value.ip_addresses
        }
      }

      # MAC Address Expression
      dynamic "mac_address_expression" {
        for_each = lookup(criteria.value, "mac_addresses", null) != null ? [1] : []
        content {
          mac_addresses = criteria.value.mac_addresses
        }
      }

      # Path Expression (for direct paths)
      dynamic "path_expression" {
        for_each = lookup(criteria.value, "paths", null) != null ? [1] : []
        content {
          member_paths = criteria.value.paths
        }
      }

      # External ID Expression
      dynamic "external_id_expression" {
        for_each = lookup(criteria.value, "external_ids", null) != null ? [1] : []
        content {
          external_ids = criteria.value.external_ids
          member_type  = lookup(criteria.value, "external_id_member_type", "VirtualMachine")
        }
      }
    }
  }

  # Nested groups via path_expression (member_groups)
  dynamic "criteria" {
    for_each = length(each.value.resolved_member_group_paths) > 0 ? [1] : []
    content {
      path_expression {
        member_paths = each.value.resolved_member_group_paths
      }
    }
  }

  # Conjunction blocks for criteria_groups
  dynamic "conjunction" {
    for_each = lookup(each.value, "criteria_groups", null) != null ? [
      for c in each.value.processed_criteria : c
      if lookup(c, "_is_conjunction", false)
    ] : (
      lookup(each.value, "conjunction", null) != null ? [{ _conjunction_operator = each.value.conjunction }] : []
    )
    content {
      operator = conjunction.value._conjunction_operator
    }
  }

  # Extended criteria for identity groups
  dynamic "extended_criteria" {
    for_each = lookup(each.value, "extended_criteria", [])
    content {
      dynamic "identity_group" {
        for_each = lookup(extended_criteria.value, "identity_groups", [])
        content {
          distinguished_name             = lookup(identity_group.value, "distinguished_name", null)
          domain_base_distinguished_name = lookup(identity_group.value, "domain_base_distinguished_name", null)
          sid                            = lookup(identity_group.value, "sid", null)
        }
      }
    }
  }

  # Tags
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
}
