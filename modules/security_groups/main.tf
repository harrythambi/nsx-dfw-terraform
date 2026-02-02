# =============================================================================
# NSX-T Security Groups (nsxt_policy_group)
# =============================================================================

resource "nsxt_policy_group" "this" {
  for_each = var.security_groups

  display_name = each.value.display_name
  description  = lookup(each.value, "description", null)
  domain       = var.domain

  dynamic "criteria" {
    for_each = lookup(each.value, "criteria", [])
    content {
      dynamic "condition" {
        for_each = lookup(criteria.value, "conditions", [])
        content {
          key         = lookup(condition.value, "key", null)
          member_type = lookup(condition.value, "member_type", "VirtualMachine")
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      dynamic "ip_address_expression" {
        for_each = lookup(criteria.value, "ip_addresses", null) != null ? [1] : []
        content {
          ip_addresses = criteria.value.ip_addresses
        }
      }

      dynamic "mac_address_expression" {
        for_each = lookup(criteria.value, "mac_addresses", null) != null ? [1] : []
        content {
          mac_addresses = criteria.value.mac_addresses
        }
      }

      dynamic "path_expression" {
        for_each = lookup(criteria.value, "paths", null) != null ? [1] : []
        content {
          member_paths = criteria.value.paths
        }
      }

      dynamic "external_id_expression" {
        for_each = lookup(criteria.value, "external_ids", null) != null ? [1] : []
        content {
          external_ids = criteria.value.external_ids
          member_type  = lookup(criteria.value, "external_id_member_type", "VirtualMachine")
        }
      }
    }
  }

  dynamic "conjunction" {
    for_each = lookup(each.value, "conjunction", null) != null ? [each.value.conjunction] : []
    content {
      operator = conjunction.value
    }
  }

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

  dynamic "tag" {
    for_each = concat(var.default_tags, lookup(each.value, "tags", []))
    content {
      scope = tag.value.scope
      tag   = tag.value.tag
    }
  }

  dynamic "context" {
    for_each = var.project_id != null ? [1] : []
    content {
      project_id = var.project_id
    }
  }
}
