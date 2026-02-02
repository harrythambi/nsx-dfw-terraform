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
#
#   L4 Port Set (l4_port_set_entries):
#     TCP/UDP port definitions. Supports single ports, multiple ports,
#     and port ranges (e.g., "80", "8080-8090").
#
#   ICMP (icmp_entries):
#     ICMP type and code definitions for ICMPv4 or ICMPv6.
#     Common types: 0=Echo Reply, 8=Echo Request, 3=Dest Unreachable
#
#   IP Protocol (ip_protocol_entries):
#     Raw IP protocol numbers for non-TCP/UDP protocols.
#     Examples: 47=GRE, 50=ESP, 51=AH, 89=OSPF
#
#   IGMP (igmp_entries):
#     Internet Group Management Protocol for multicast.
#
#   EtherType (ether_type_entries):
#     Layer 2 protocol types by EtherType number.
#     Examples: 2048=IPv4, 2054=ARP, 34525=IPv6
#
#   Algorithm (algorithm_entries):
#     Application Layer Gateway (ALG) services that require
#     deep packet inspection. Examples: FTP, TFTP, Oracle TNS.
#
#   Nested Service (nested_service_entries):
#     Compose services by including other services.
#     Reference by name or NSX path.
#
# PREDEFINED SERVICES:
#   NSX-T includes many predefined services (DNS, HTTP, SSH, etc.)
#   that can be referenced directly in policies without defining them.
#   This module maintains a lookup table of common predefined services.
#
# =============================================================================

locals {
  # Common predefined NSX services - map friendly names to NSX paths
  predefined_service_paths = {
    # Core network services
    "DNS"         = "/infra/services/DNS"
    "DNS-UDP"     = "/infra/services/DNS-UDP"
    "NTP"         = "/infra/services/NTP"
    "DHCP-Server" = "/infra/services/DHCP-Server"
    "DHCP-Client" = "/infra/services/DHCP-Client"

    # Web services
    "HTTP"  = "/infra/services/HTTP"
    "HTTPS" = "/infra/services/HTTPS"

    # Remote access
    "SSH"    = "/infra/services/SSH"
    "RDP"    = "/infra/services/RDP"
    "Telnet" = "/infra/services/Telnet"

    # File transfer
    "FTP"  = "/infra/services/FTP"
    "TFTP" = "/infra/services/TFTP"
    "SCP"  = "/infra/services/SCP"
    "SFTP" = "/infra/services/SFTP"

    # Email services
    "SMTP"     = "/infra/services/SMTP"
    "SMTP_TLS" = "/infra/services/SMTP_TLS"
    "POP3"     = "/infra/services/POP3"
    "POP3S"    = "/infra/services/POP3S"
    "IMAP"     = "/infra/services/IMAP"
    "IMAPS"    = "/infra/services/IMAPS"

    # Database services
    "MySQL"      = "/infra/services/MySQL"
    "MS-SQL-S"   = "/infra/services/MS-SQL-S"
    "Oracle-SQL" = "/infra/services/Oracle-SQL-Net"

    # Directory services
    "LDAP"      = "/infra/services/LDAP"
    "LDAPS"     = "/infra/services/LDAPS"
    "AD-Server" = "/infra/services/AD-Server"
    "Kerberos"  = "/infra/services/Kerberos"

    # Windows services
    "WINS"     = "/infra/services/WINS"
    "SMB"      = "/infra/services/SMB"
    "NBNS-UDP" = "/infra/services/NBNS-UDP"
    "NBNS-TCP" = "/infra/services/NBNS-TCP"
    "NBDG-TCP" = "/infra/services/NBDG-TCP"
    "NBDG-UDP" = "/infra/services/NBDG-UDP"
    "NBSS"     = "/infra/services/NBSS"

    # Monitoring and management
    "SNMP"       = "/infra/services/SNMP"
    "SNMP-Trap"  = "/infra/services/SNMP-Trap"
    "Syslog-UDP" = "/infra/services/Syslog-UDP"
    "Syslog-TCP" = "/infra/services/Syslog-TCP"

    # ICMP
    "ICMP-ALL"   = "/infra/services/ICMP-ALL"
    "ICMPv6-ALL" = "/infra/services/ICMPv6-ALL"
    "ICMP Echo"  = "/infra/services/ICMP_Echo_Reply"

    # VPN
    "IKE"       = "/infra/services/IKE"
    "IPSEC-ESP" = "/infra/services/IPSEC-ESP"
    "IPSEC-AH"  = "/infra/services/IPSEC-AH"
    "L2TP"      = "/infra/services/L2TP"
    "PPTP"      = "/infra/services/PPTP"

    # Virtualization
    "vMotion"        = "/infra/services/vMotion"
    "vSphere-Client" = "/infra/services/vSphere-Client"

    # Other common services
    "Radius"            = "/infra/services/RADIUS"
    "Radius-Accounting" = "/infra/services/RADIUS-Accounting"
    "TACACS+"           = "/infra/services/TACACS+"
  }

  # ===========================================================================
  # Identify services with nested references to local services
  # ===========================================================================

  # For each service, identify which nested entries reference local services
  services_with_local_refs = {
    for name, svc in var.services : name => [
      for entry in lookup(svc, "nested_service_entries", []) :
      lookup(entry, "service_name", "")
      if lookup(entry, "service_name", null) != null &&
      !can(regex("^/", lookup(entry, "service_name", ""))) &&
      contains(keys(var.services), lookup(entry, "service_name", "")) &&
      !contains(keys(local.predefined_service_paths), lookup(entry, "service_name", ""))
    ]
  }

  # Leaf services: no nested entries or only reference external/predefined services
  leaf_service_names = [
    for name, refs in local.services_with_local_refs : name
    if length(refs) == 0
  ]

  # Nested services: reference other services defined in this config
  nested_service_names = [
    for name, refs in local.services_with_local_refs : name
    if length(refs) > 0
  ]

  # ===========================================================================
  # Process leaf services
  # ===========================================================================

  leaf_services = {
    for name in local.leaf_service_names : name => merge(
      var.services[name],
      {
        # Process nested_service_entries to resolve references (external/predefined only)
        resolved_nested_entries = lookup(var.services[name], "nested_service_entries", null) != null ? [
          for entry in var.services[name].nested_service_entries : merge(
            entry,
            {
              resolved_path = (
                # Check if path is already provided
                lookup(entry, "nested_service_path", null) != null ? entry.nested_service_path :
                # Check if service_name is provided - resolve it
                lookup(entry, "service_name", null) != null ? (
                  # First check external service_path_lookup
                  lookup(var.service_path_lookup, entry.service_name, null) != null ?
                  var.service_path_lookup[entry.service_name] :
                  # Then check predefined services
                  lookup(local.predefined_service_paths, entry.service_name, null) != null ?
                  local.predefined_service_paths[entry.service_name] :
                  # Otherwise assume it's a path
                  can(regex("^/", entry.service_name)) ? entry.service_name :
                  "/infra/services/${entry.service_name}"
                ) : null
              )
            }
          )
        ] : []
      }
    )
  }
}

# Data source for predefined services - enables validation that they exist
data "nsxt_policy_service" "predefined" {
  for_each = toset(var.predefined_services_to_lookup)

  display_name = each.value
}

# =============================================================================
# LEAF SERVICES - Services without local nested references (created first)
# =============================================================================

resource "nsxt_policy_service" "leaf" {
  for_each = local.leaf_services

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
      display_name     = lookup(algorithm_entry.value, "display_name", null)
      description      = lookup(algorithm_entry.value, "description", null)
      algorithm        = algorithm_entry.value.algorithm
      destination_port = algorithm_entry.value.destination_port
      source_ports     = lookup(algorithm_entry.value, "source_ports", null)
    }
  }

  # Nested Service Entry (for service groups referencing external/predefined services)
  dynamic "nested_service_entry" {
    for_each = each.value.resolved_nested_entries
    content {
      display_name        = lookup(nested_service_entry.value, "display_name", null)
      description         = lookup(nested_service_entry.value, "description", null)
      nested_service_path = nested_service_entry.value.resolved_path
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
    local.predefined_service_paths,
    local.leaf_service_path_lookup
  )

  # Process nested services (with local service references)
  nested_services = {
    for name in local.nested_service_names : name => merge(
      var.services[name],
      {
        # Process nested_service_entries to resolve references (including local services)
        resolved_nested_entries = lookup(var.services[name], "nested_service_entries", null) != null ? [
          for entry in var.services[name].nested_service_entries : merge(
            entry,
            {
              resolved_path = (
                # Check if path is already provided
                lookup(entry, "nested_service_path", null) != null ? entry.nested_service_path :
                # Check if service_name is provided - resolve it
                lookup(entry, "service_name", null) != null ? (
                  # Look up in combined lookup (includes leaf services)
                  lookup(local.combined_service_lookup, entry.service_name, null) != null ?
                  local.combined_service_lookup[entry.service_name] :
                  # Otherwise assume it's a path
                  can(regex("^/", entry.service_name)) ? entry.service_name :
                  "/infra/services/${entry.service_name}"
                ) : null
              )
            }
          )
        ] : []
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
    for_each = each.value.resolved_nested_entries
    content {
      display_name        = lookup(nested_service_entry.value, "display_name", null)
      description         = lookup(nested_service_entry.value, "description", null)
      nested_service_path = nested_service_entry.value.resolved_path
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
