# =============================================================================
# NSX-T DFW Terraform Module
# =============================================================================
# This module manages NSX-T Distributed Firewall components:
# - Security Groups (nsxt_policy_group)
# - Services (nsxt_policy_service)
# - Security Policies with Rules (nsxt_policy_security_policy)
#
# Features:
# - YAML/JSON configuration files for all resources
# - OS Name, Computer Name, and nested groups criteria
# - Complex criteria_groups with AND/OR conjunctions
# - Nested service entries with predefined service lookup
# - REJECT action, rule-level scope and tags
# - Category-based sequence numbering with collision detection
# - Reference validation with clear error messages
# =============================================================================

# =============================================================================
# Security Groups Module
# =============================================================================

module "security_groups" {
  source = "./modules/security_groups"

  security_groups          = local.security_groups_with_index
  domain                   = var.domain
  project_id               = var.project_id
  default_tags             = var.default_tags
  tolerate_partial_success = var.tolerate_partial_success
  group_path_lookup        = local.preliminary_group_paths
}

# =============================================================================
# Services Module
# =============================================================================

module "services" {
  source = "./modules/services"

  services                      = local.services_with_index
  project_id                    = var.project_id
  default_tags                  = var.default_tags
  service_path_lookup           = local.preliminary_service_paths
  predefined_services_to_lookup = var.predefined_services_to_lookup
}

# =============================================================================
# Security Policies Module
# =============================================================================

module "security_policies" {
  source = "./modules/security_policies"

  security_policies         = local.policies_processed
  domain                    = var.domain
  project_id                = var.project_id
  default_tags              = var.default_tags
  policy_sequence_increment = var.policy_sequence_increment
  rule_sequence_start       = var.rule_sequence_start
  rule_sequence_increment   = var.rule_sequence_increment

  # Pass group and service paths for reference resolution
  security_group_paths = module.security_groups.group_paths
  service_paths        = module.services.service_paths

  depends_on = [
    module.security_groups,
    module.services
  ]
}
