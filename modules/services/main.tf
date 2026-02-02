# =============================================================================
# NSX-T Services (nsxt_policy_service)
# =============================================================================

resource "nsxt_policy_service" "this" {
  for_each = var.services

  display_name = each.value.display_name
  description  = lookup(each.value, "description", null)

  # L4 Port Set Entry (TCP/UDP)
  dynamic "l4_port_set_entry" {
    for_each = lookup(each.value, "l4_port_set_entries", [])
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
      display_name      = lookup(algorithm_entry.value, "display_name", null)
      description       = lookup(algorithm_entry.value, "description", null)
      algorithm         = algorithm_entry.value.algorithm
      destination_port  = algorithm_entry.value.destination_port
      source_ports      = lookup(algorithm_entry.value, "source_ports", null)
    }
  }

  # Nested Service Entry (for service groups)
  dynamic "nested_service_entry" {
    for_each = lookup(each.value, "nested_service_entries", [])
    content {
      display_name         = lookup(nested_service_entry.value, "display_name", null)
      description          = lookup(nested_service_entry.value, "description", null)
      nested_service_path  = nested_service_entry.value.nested_service_path
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
