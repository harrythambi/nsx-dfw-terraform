# =============================================================================
# Local Variables - Data Processing
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

  # Process security groups - maintain order with index
  security_groups_list = lookup(local.security_groups_raw, "security_groups", [])
  security_groups_with_index = {
    for idx, group in local.security_groups_list :
    lookup(group, "name", lookup(group, "display_name", "group-${idx}")) => group
  }

  # Process services - maintain order with index
  services_list = lookup(local.services_raw, "services", [])
  services_with_index = {
    for idx, svc in local.services_list :
    lookup(svc, "name", lookup(svc, "display_name", "service-${idx}")) => svc
  }

  # Process security policies with auto-calculated sequence numbers
  policies_list = lookup(local.security_policies_raw, "security_policies", [])
  
  policies_processed = {
    for idx, policy in local.policies_list :
    lookup(policy, "name", lookup(policy, "display_name", "policy-${idx}")) => merge(
      policy,
      {
        # Auto-calculate policy sequence number if not provided
        sequence_number = lookup(policy, "sequence_number", var.policy_sequence_start + (idx * var.policy_sequence_increment))
        
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
}
