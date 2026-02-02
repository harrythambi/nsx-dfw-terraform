# =============================================================================
# NSX-T Security Groups Module (nsxt_policy_group)
# =============================================================================
#
# PURPOSE:
#   Creates NSX-T security groups that define membership criteria for VMs,
#   segments, and other objects. These groups are referenced in security
#   policies to define source/destination for firewall rules.
#
# SUPPORTED CRITERIA TYPES:
#   - Tag-based:      Match VMs by NSX tags (scope|tag format)
#   - Name-based:     Match VMs by display name (CONTAINS, EQUALS, etc.)
#   - OS Name:        Match VMs by operating system (Windows, Linux, etc.)
#   - Computer Name:  Match VMs by hostname/computer name
#   - IP Address:     Static IPs, CIDR ranges, IP ranges
#   - MAC Address:    Static MAC addresses
#   - Path:           Reference other NSX objects by their path
#   - External ID:    Match by external identifiers (e.g., VM BIOS UUID)
#   - Segment:        Match by network segment tags
#   - SegmentPort:    Match by segment port tags
#
# CONJUNCTIONS:
#   - OR:  Match if ANY criteria block matches (default between criteria)
#   - AND: Match if ALL criteria blocks match (use criteria_groups)
#
# STATIC MEMBERS:
#   Groups can include static members by path:
#   - virtual_machines:        VM paths from realized state
#   - segments:                NSX segment paths
#   - segment_ports:           Segment port paths
#   - groups:                  Nested security group paths
#   - vifs:                    Virtual interface paths
#   - physical_servers:        Physical server paths
#   - distributed_port_groups: vSphere distributed port group paths
#   - distributed_ports:       vSphere distributed port paths
#
# NESTED GROUPS:
#   Groups can include other groups using member_groups or members.groups,
#   enabling hierarchical group composition.
#
# IDENTITY GROUPS:
#   Extended criteria supports Active Directory identity-based groups
#   using distinguished names or SIDs.
#
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
                _is_conjunction       = true
                _conjunction_operator = lookup(cg, "conjunction_with_next", "OR")
              }
            ] : []
          )
        ]) : lookup(group, "criteria", [])

        # Resolve member_groups to paths (legacy support)
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

        # Collect member display names for data source lookups
        # These will be resolved to paths via data sources
        vm_members                     = lookup(lookup(group, "members", {}), "virtual_machines", [])
        segment_members                = lookup(lookup(group, "members", {}), "segments", [])
        segment_port_members           = lookup(lookup(group, "members", {}), "segment_ports", [])
        group_members                  = lookup(lookup(group, "members", {}), "groups", [])
        vif_members                    = lookup(lookup(group, "members", {}), "vifs", [])
        physical_server_members        = lookup(lookup(group, "members", {}), "physical_servers", [])
        distributed_port_group_members = lookup(lookup(group, "members", {}), "distributed_port_groups", [])
        distributed_port_members       = lookup(lookup(group, "members", {}), "distributed_ports", [])
      }
    )
  }

  # ===========================================================================
  # Collect all unique member names for data source lookups
  # ===========================================================================

  # Collect all VM display names that need to be looked up
  all_vm_names = distinct(flatten([
    for name, group in local.processed_groups : group.vm_members
  ]))

  # Collect all segment display names that need to be looked up
  all_segment_names = distinct(flatten([
    for name, group in local.processed_groups : group.segment_members
  ]))

  # Collect all group names that need to be looked up (excluding paths and locally defined groups)
  all_external_group_names = distinct(flatten([
    for name, group in local.processed_groups : [
      for g in group.group_members : g
      if !can(regex("^/", g)) && !contains(keys(var.group_path_lookup), g)
    ]
  ]))
}

# =============================================================================
# Data Sources - Look up objects by display name
# =============================================================================

# Look up Virtual Machines by display name
data "nsxt_policy_vm" "members" {
  for_each = toset(local.all_vm_names)

  display_name = each.value
}

# Look up Segments by display name
data "nsxt_policy_segment" "members" {
  for_each = toset(local.all_segment_names)

  display_name = each.value
}

# Look up existing Groups by display name (for groups not defined in this config)
data "nsxt_policy_group" "members" {
  for_each = toset(local.all_external_group_names)

  display_name = each.value
  domain       = var.domain
}

# =============================================================================
# Build lookup maps from display name to path
# =============================================================================

locals {
  # VM display name to path lookup
  vm_path_lookup = {
    for name in local.all_vm_names : name => data.nsxt_policy_vm.members[name].path
  }

  # Segment display name to path lookup
  segment_path_lookup = {
    for name in local.all_segment_names : name => data.nsxt_policy_segment.members[name].path
  }

  # External group display name to path lookup
  external_group_path_lookup = {
    for name in local.all_external_group_names : name => data.nsxt_policy_group.members[name].path
  }

  # Combined group lookup: local groups + external groups
  combined_group_lookup = merge(var.group_path_lookup, local.external_group_path_lookup)

  # ===========================================================================
  # Resolve member display names to paths for each group
  # ===========================================================================
  groups_with_resolved_members = {
    for name, group in local.processed_groups : name => merge(
      group,
      {
        # Resolve all static member paths
        static_member_paths = concat(
          # Virtual Machines - resolve display names to paths
          [for vm in group.vm_members : local.vm_path_lookup[vm]],

          # Segments - resolve display names to paths
          [for seg in group.segment_members : local.segment_path_lookup[seg]],

          # Segment Ports - keep as paths (format: segment_name/port_name)
          # These are already expected to be paths or will need custom handling
          group.segment_port_members,

          # VIFs - keep as paths
          group.vif_members,

          # Physical Servers - keep as paths
          group.physical_server_members,

          # Distributed Port Groups - keep as paths
          group.distributed_port_group_members,

          # Distributed Ports - keep as paths
          group.distributed_port_members,

          # Groups - resolve names to paths
          [
            for g in group.group_members : (
              # If it's already a path, use it directly
              can(regex("^/", g)) ? g :
              # Look up in combined group lookup
              lookup(local.combined_group_lookup, g, "/infra/domains/${var.domain}/groups/${g}")
            )
          ]
        )
      }
    )
  }

  # Valid operators for condition-based criteria
  valid_operators = ["EQUALS", "CONTAINS", "STARTSWITH", "ENDSWITH", "NOTEQUALS"]
}

resource "nsxt_policy_group" "this" {
  for_each = local.groups_with_resolved_members

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
      # VM Tag condition (excludes Segment/SegmentPort which have their own blocks)
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if(lookup(cond, "type", lookup(cond, "key", "Tag")) == "Tag" ||
          (lookup(cond, "key", null) == "Tag" && lookup(cond, "type", null) == null)) &&
          !contains(["Segment", "SegmentPort"], lookup(cond, "member_type", "VirtualMachine"))
        ]
        content {
          key         = "Tag"
          member_type = lookup(condition.value, "member_type", "VirtualMachine")
          operator    = lookup(condition.value, "operator", "EQUALS")
          value       = condition.value.value
        }
      }

      # VM Name condition (excludes Segment/SegmentPort which have their own blocks)
      dynamic "condition" {
        for_each = [
          for cond in lookup(criteria.value, "conditions", []) : cond
          if(lookup(cond, "type", lookup(cond, "key", "")) == "Name" ||
          lookup(cond, "key", null) == "Name") &&
          !contains(["Segment", "SegmentPort"], lookup(cond, "member_type", "VirtualMachine"))
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
      dynamic "ipaddress_expression" {
        for_each = lookup(criteria.value, "ip_addresses", null) != null ? [1] : []
        content {
          ip_addresses = criteria.value.ip_addresses
        }
      }

      # MAC Address Expression
      dynamic "macaddress_expression" {
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

  # Nested groups via path_expression (member_groups - legacy)
  dynamic "criteria" {
    for_each = length(each.value.resolved_member_group_paths) > 0 ? [1] : []
    content {
      path_expression {
        member_paths = each.value.resolved_member_group_paths
      }
    }
  }

  # Static members via path_expression (members section)
  # Includes: virtual_machines, segments, segment_ports, groups, vifs,
  # physical_servers, distributed_port_groups, distributed_ports
  dynamic "criteria" {
    for_each = length(each.value.static_member_paths) > 0 ? [1] : []
    content {
      path_expression {
        member_paths = each.value.static_member_paths
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
