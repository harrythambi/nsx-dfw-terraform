# =============================================================================
# NSX-T Security Policies (nsxt_policy_security_policy)
# =============================================================================

locals {
  # Build lookup maps for group and service references
  group_lookup   = var.security_group_paths
  service_lookup = var.service_paths
}

resource "nsxt_policy_security_policy" "this" {
  for_each = var.security_policies

  display_name    = each.value.display_name
  description     = lookup(each.value, "description", null)
  category        = lookup(each.value, "category", "Application")
  domain          = var.domain
  sequence_number = each.value.sequence_number
  stateful        = lookup(each.value, "stateful", true)
  tcp_strict      = lookup(each.value, "tcp_strict", false)
  locked          = lookup(each.value, "locked", false)

  # Policy scope
  scope = lookup(each.value, "scope", null) != null ? [
    for s in each.value.scope : (
      lookup(local.group_lookup, s, null) != null ? local.group_lookup[s] : s
    )
  ] : null

  # Rules
  dynamic "rule" {
    for_each = lookup(each.value, "rules", [])
    content {
      display_name = rule.value.display_name
      description  = lookup(rule.value, "description", null)

      sequence_number = rule.value.sequence_number

      action    = lookup(rule.value, "action", "ALLOW")
      direction = lookup(rule.value, "direction", "IN_OUT")

      # Source groups - resolve references or use direct paths
      source_groups = lookup(rule.value, "source_groups", null) != null ? [
        for g in rule.value.source_groups : (
          lookup(local.group_lookup, g, null) != null ? local.group_lookup[g] : g
        )
      ] : null

      # Destination groups - resolve references or use direct paths
      destination_groups = lookup(rule.value, "destination_groups", null) != null ? [
        for g in rule.value.destination_groups : (
          lookup(local.group_lookup, g, null) != null ? local.group_lookup[g] : g
        )
      ] : null

      sources_excluded      = lookup(rule.value, "sources_excluded", false)
      destinations_excluded = lookup(rule.value, "destinations_excluded", false)

      # Services - resolve references or use direct paths
      services = lookup(rule.value, "services", null) != null ? [
        for s in rule.value.services : (
          lookup(local.service_lookup, s, null) != null ? local.service_lookup[s] : s
        )
      ] : null

      # Profiles
      profiles = lookup(rule.value, "profiles", null)

      ip_version = lookup(rule.value, "ip_version", "IPV4_IPV6")
      logged     = lookup(rule.value, "logged", false)
      disabled   = lookup(rule.value, "disabled", false)
      notes      = lookup(rule.value, "notes", null)
      log_label  = lookup(rule.value, "log_label", null)

      # Rule scope
      scope = lookup(rule.value, "scope", null) != null ? [
        for s in rule.value.scope : (
          lookup(local.group_lookup, s, null) != null ? local.group_lookup[s] : s
        )
      ] : null

      # Rule tags
      dynamic "tag" {
        for_each = lookup(rule.value, "tags", [])
        content {
          scope = tag.value.scope
          tag   = tag.value.tag
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
