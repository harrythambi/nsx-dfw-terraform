# =============================================================================
# NSX-T Distributed Firewall (DFW) Terraform Module - Root Module
# =============================================================================
#
# OVERVIEW:
#   This is the root module that orchestrates NSX-T DFW configuration.
#   It reads YAML configuration files and delegates resource creation
#   to specialized submodules.
#
# COMPONENTS MANAGED:
#   1. Security Groups (nsxt_policy_group)
#      - Define workload membership using various criteria
#      - Support tags, IPs, names, paths, and complex expressions
#
#   2. Services (nsxt_policy_service)
#      - Define protocols and ports for firewall rules
#      - Support TCP/UDP, ICMP, IP protocols, ALG, and more
#
#   3. Security Policies (nsxt_policy_security_policy)
#      - Container for firewall rules
#      - Category-based ordering (Emergency → Infrastructure → Environment → Application)
#
# CONFIGURATION FILES:
#   - data/security_groups.yaml   - Group definitions
#   - data/services.yaml          - Service definitions
#   - data/security_policies.yaml - Policy and rule definitions
#
# DEPENDENCY CHAIN:
#   Security Groups → Services → Security Policies
#   (Groups and services must exist before policies can reference them)
#
# FEATURES:
#   - YAML/JSON configuration files for GitOps workflows
#   - Automatic reference resolution (name → NSX path)
#   - Category-based sequence numbering with collision detection
#   - Comprehensive validation with clear error messages
#   - Multitenancy support via NSX-T projects
#
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

  services            = local.services_with_index
  project_id          = var.project_id
  default_tags        = var.default_tags
  service_path_lookup = local.preliminary_service_paths
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
