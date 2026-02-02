# =============================================================================
# NSX-T DFW Terraform Module
# =============================================================================
# This module manages NSX-T Distributed Firewall components:
# - Security Groups (nsxt_policy_group)
# - Services (nsxt_policy_service)
# - Security Policies with Rules (nsxt_policy_security_policy)
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
}

# =============================================================================
# Services Module
# =============================================================================

module "services" {
  source = "./modules/services"

  services     = local.services_with_index
  project_id   = var.project_id
  default_tags = var.default_tags
}

# =============================================================================
# Security Policies Module
# =============================================================================

module "security_policies" {
  source = "./modules/security_policies"

  security_policies = local.policies_processed
  domain            = var.domain
  project_id        = var.project_id
  default_tags      = var.default_tags

  # Pass group and service paths for reference
  security_group_paths = module.security_groups.group_paths
  service_paths        = module.services.service_paths

  depends_on = [
    module.security_groups,
    module.services
  ]
}
