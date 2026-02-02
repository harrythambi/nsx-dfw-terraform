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

  # Process services to resolve nested service references
  processed_services = {
    for name, svc in var.services : name => merge(
      svc,
      {
        # Process nested_service_entries to resolve references
        resolved_nested_entries = lookup(svc, "nested_service_entries", null) != null ? [
          for entry in svc.nested_service_entries : merge(
            entry,
            {
              resolved_path = (
                # Check if path is already provided
                lookup(entry, "nested_service_path", null) != null ? entry.nested_service_path :
                # Check if service_name is provided - resolve it
                lookup(entry, "service_name", null) != null ? (
                  # First check local services
                  lookup(var.service_path_lookup, entry.service_name, null) != null ?
                  var.service_path_lookup[entry.service_name] :
                  # Then check predefined services
                  lookup(local.predefined_service_paths, entry.service_name, null) != null ?
                  local.predefined_service_paths[entry.service_name] :
                  # Otherwise assume it's a path or will be created
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

resource "nsxt_policy_service" "this" {
  for_each = local.processed_services

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

  # Nested Service Entry (for service groups referencing other services)
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
