# =============================================================================
# NSX-T Services Module (nsxt_policy_service)
# =============================================================================
#
# PURPOSE:
#   Creates NSX-T service definitions that specify protocols and ports
#   for use in security policy rules. Services define WHAT traffic is
#   allowed or denied (as opposed to groups which define WHO).
#
# SERVICE ENTRY TYPES:
#   - ports:              Simple "port/protocol" format (e.g., "80/tcp")
#   - l4_port_set_entries: TCP/UDP port definitions (verbose format)
#   - icmp_entries:       ICMP type and code definitions
#   - ip_protocol_entries: Raw IP protocol numbers (e.g., 47=GRE)
#   - igmp_entries:       IGMP for multicast
#   - ether_type_entries: Layer 2 protocol types
#   - algorithm_entries:  ALG services (FTP, TFTP, etc.)
#   - members.services:   Nested service groups (reference other services)
#
# PREDEFINED SERVICES:
#   Reference any NSX predefined service by display name (e.g., "DNS", "HTTP").
#   They are automatically looked up via data source - no hardcoding needed.
#
# =============================================================================

locals {
  # ===========================================================================
  # Parse simplified 'ports' syntax: "80/tcp" -> l4_port_set_entry
  # ===========================================================================

  services_with_parsed_ports = {
    for name, svc in var.services : name => merge(
      svc,
      {
        # Combine simplified 'ports' with explicit 'l4_port_set_entries'
        _all_l4_entries = concat(
          lookup(svc, "l4_port_set_entries", []),
          [
            for port_spec in lookup(svc, "ports", []) : {
              display_name      = port_spec
              protocol          = upper(element(split("/", port_spec), 1))
              destination_ports = [element(split("/", port_spec), 0)]
            }
          ]
        )
      }
    )
  }

  # ===========================================================================
  # Extract all service member references
  # ===========================================================================

  # Extract service members from each service
  service_members = {
    for name, svc in var.services : name => lookup(lookup(svc, "members", {}), "services", [])
  }

  # Collect ALL unique service references across all services
  all_service_refs = distinct(flatten([
    for name, members in local.service_members : members
  ]))

  # ===========================================================================
  # Identify predefined services (not local, not external, not a path)
  # ===========================================================================

  predefined_service_names = [
    for ref in local.all_service_refs : ref
    if !can(regex("^/", ref)) &&                        # Not already a path
    !contains(keys(var.services), ref) &&               # Not defined locally
    !contains(keys(var.service_path_lookup), ref)       # Not passed externally
  ]

  # ===========================================================================
  # Identify services with nested references to LOCAL services
  # ===========================================================================

  services_with_local_refs = {
    for name, members in local.service_members : name => [
      for svc_name in members : svc_name
      if !can(regex("^/", svc_name)) && contains(keys(var.services), svc_name)
    ]
  }

  # Leaf services: no local nested refs (created first)
  leaf_service_names = [
    for name, refs in local.services_with_local_refs : name
    if length(refs) == 0
  ]

  # Nested services: reference other services defined in this config (created after leaf)
  nested_service_names = [
    for name, refs in local.services_with_local_refs : name
    if length(refs) > 0
  ]
}

# =============================================================================
# Build lookup map for predefined services
# =============================================================================
# Note: Predefined NSX services have predictable paths: /infra/services/{name}
# We construct paths directly instead of using data source (which has prefix
# matching issues with services like DNS, DNS-UDP, DNS-TCP).
# =============================================================================

locals {
  # Map predefined service names to their paths (constructed directly)
  predefined_service_path_lookup = {
    for name in local.predefined_service_names : name => "/infra/services/${name}"
  }

  # ===========================================================================
  # Process leaf services
  # ===========================================================================

  leaf_services = {
    for name in local.leaf_service_names : name => merge(
      local.services_with_parsed_ports[name],
      {
        # Resolve service members to paths
        resolved_service_paths = [
          for svc_name in local.service_members[name] : {
            name = svc_name
            path = (
              # Check if it's already a path
              can(regex("^/", svc_name)) ? svc_name :
              # Check external service_path_lookup
              contains(keys(var.service_path_lookup), svc_name) ?
              var.service_path_lookup[svc_name] :
              # Check predefined services (from data source)
              contains(keys(local.predefined_service_path_lookup), svc_name) ?
              local.predefined_service_path_lookup[svc_name] :
              # Should not reach here - error
              "ERROR: Service '${svc_name}' not found"
            )
          }
        ]
      }
    )
  }
}

# =============================================================================
# LEAF SERVICES - Services without local nested references (created first)
# =============================================================================

resource "nsxt_policy_service" "leaf" {
  for_each = local.leaf_services

  display_name = each.value.display_name
  description  = lookup(each.value, "description", null)

  # L4 Port Set Entry (TCP/UDP) - supports simplified 'ports' and verbose 'l4_port_set_entries'
  dynamic "l4_port_set_entry" {
    for_each = each.value._all_l4_entries
    content {
      display_name      = lookup(l4_port_set_entry.value, "display_name", null)
      description       = lookup(l4_port_set_entry.value, "description", null)
      protocol          = l4_port_set_entry.value.protocol
      destination_ports = lookup(l4_port_set_entry.value, "destination_ports", null)
      source_ports      = lookup(l4_port_set_entry.value, "source_ports", null)
    }
  }

  # ICMP Entry
  dynamic "icmp_entry" {
    for_each = lookup(each.value, "icmp_entries", [])
    content {
      display_name = lookup(icmp_entry.value, "display_name", null)
      description  = lookup(icmp_entry.value, "description", null)
      protocol     = lookup(icmp_entry.value, "protocol", "ICMPv4")
      icmp_type    = lookup(icmp_entry.value, "icmp_type", null)
      icmp_code    = lookup(icmp_entry.value, "icmp_code", null)
    }
  }

  # IP Protocol Entry
  dynamic "ip_protocol_entry" {
    for_each = lookup(each.value, "ip_protocol_entries", [])
    content {
      display_name = lookup(ip_protocol_entry.value, "display_name", null)
      description  = lookup(ip_protocol_entry.value, "description", null)
      protocol     = ip_protocol_entry.value.protocol
    }
  }

  # IGMP Entry
  dynamic "igmp_entry" {
    for_each = lookup(each.value, "igmp_entries", [])
    content {
      display_name = lookup(igmp_entry.value, "display_name", null)
      description  = lookup(igmp_entry.value, "description", null)
    }
  }

  # Ether Type Entry
  dynamic "ether_type_entry" {
    for_each = lookup(each.value, "ether_type_entries", [])
    content {
      display_name = lookup(ether_type_entry.value, "display_name", null)
      description  = lookup(ether_type_entry.value, "description", null)
      ether_type   = ether_type_entry.value.ether_type
    }
  }

  # Algorithm Entry (ALG services like FTP, TFTP, etc.)
  dynamic "algorithm_entry" {
    for_each = lookup(each.value, "algorithm_entries", [])
    content {
      display_name     = lookup(algorithm_entry.value, "display_name", null)
      description      = lookup(algorithm_entry.value, "description", null)
      algorithm        = algorithm_entry.value.algorithm
      destination_port = algorithm_entry.value.destination_port
      source_ports     = lookup(algorithm_entry.value, "source_ports", null)
    }
  }

  # Nested Service Entry (for service groups referencing external/predefined services)
  dynamic "nested_service_entry" {
    for_each = each.value.resolved_service_paths
    content {
      display_name        = nested_service_entry.value.name
      nested_service_path = nested_service_entry.value.path
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

# =============================================================================
# Build lookup for leaf service paths (for nested services to reference)
# =============================================================================

locals {
  # Map leaf service names to their actual NSX paths
  leaf_service_path_lookup = {
    for name in local.leaf_service_names : name => nsxt_policy_service.leaf[name].path
  }

  # Combined lookup: external + predefined + leaf services
  combined_service_lookup = merge(
    var.service_path_lookup,
    local.predefined_service_path_lookup,
    local.leaf_service_path_lookup
  )

  # Process nested services (with local service references)
  nested_services = {
    for name in local.nested_service_names : name => merge(
      local.services_with_parsed_ports[name],
      {
        # Resolve service members to paths (including local leaf services)
        resolved_service_paths = [
          for svc_name in local.service_members[name] : {
            name = svc_name
            path = (
              # Check if it's already a path
              can(regex("^/", svc_name)) ? svc_name :
              # Look up in combined lookup (includes leaf services)
              contains(keys(local.combined_service_lookup), svc_name) ?
              local.combined_service_lookup[svc_name] :
              # Should not reach here - error
              "ERROR: Service '${svc_name}' not found"
            )
          }
        ]
      }
    )
  }
}

# =============================================================================
# NESTED SERVICES - Services with local nested references (created after leaf)
# =============================================================================

resource "nsxt_policy_service" "nested" {
  for_each = local.nested_services

  display_name = each.value.display_name
  description  = lookup(each.value, "description", null)

  # Explicit dependency on leaf services
  depends_on = [nsxt_policy_service.leaf]

  # L4 Port Set Entry (TCP/UDP) - supports simplified 'ports' and verbose 'l4_port_set_entries'
  dynamic "l4_port_set_entry" {
    for_each = each.value._all_l4_entries
    content {
      display_name      = lookup(l4_port_set_entry.value, "display_name", null)
      description       = lookup(l4_port_set_entry.value, "description", null)
      protocol          = l4_port_set_entry.value.protocol
      destination_ports = lookup(l4_port_set_entry.value, "destination_ports", null)
      source_ports      = lookup(l4_port_set_entry.value, "source_ports", null)
    }
  }

  # ICMP Entry
  dynamic "icmp_entry" {
    for_each = lookup(each.value, "icmp_entries", [])
    content {
      display_name = lookup(icmp_entry.value, "display_name", null)
      description  = lookup(icmp_entry.value, "description", null)
      protocol     = lookup(icmp_entry.value, "protocol", "ICMPv4")
      icmp_type    = lookup(icmp_entry.value, "icmp_type", null)
      icmp_code    = lookup(icmp_entry.value, "icmp_code", null)
    }
  }

  # IP Protocol Entry
  dynamic "ip_protocol_entry" {
    for_each = lookup(each.value, "ip_protocol_entries", [])
    content {
      display_name = lookup(ip_protocol_entry.value, "display_name", null)
      description  = lookup(ip_protocol_entry.value, "description", null)
      protocol     = ip_protocol_entry.value.protocol
    }
  }

  # IGMP Entry
  dynamic "igmp_entry" {
    for_each = lookup(each.value, "igmp_entries", [])
    content {
      display_name = lookup(igmp_entry.value, "display_name", null)
      description  = lookup(igmp_entry.value, "description", null)
    }
  }

  # Ether Type Entry
  dynamic "ether_type_entry" {
    for_each = lookup(each.value, "ether_type_entries", [])
    content {
      display_name = lookup(ether_type_entry.value, "display_name", null)
      description  = lookup(ether_type_entry.value, "description", null)
      ether_type   = ether_type_entry.value.ether_type
    }
  }

  # Algorithm Entry
  dynamic "algorithm_entry" {
    for_each = lookup(each.value, "algorithm_entries", [])
    content {
      display_name     = lookup(algorithm_entry.value, "display_name", null)
      description      = lookup(algorithm_entry.value, "description", null)
      algorithm        = algorithm_entry.value.algorithm
      destination_port = algorithm_entry.value.destination_port
      source_ports     = lookup(algorithm_entry.value, "source_ports", null)
    }
  }

  # Nested Service Entry (includes references to local leaf services)
  dynamic "nested_service_entry" {
    for_each = each.value.resolved_service_paths
    content {
      display_name        = nested_service_entry.value.name
      nested_service_path = nested_service_entry.value.path
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
