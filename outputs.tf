# =============================================================================
# Root Module Outputs
# =============================================================================

output "security_group_paths" {
  description = "Map of security group names to their NSX paths"
  value       = module.security_groups.group_paths
}

output "service_paths" {
  description = "Map of service names to their NSX paths"
  value       = module.services.service_paths
}

output "security_policy_paths" {
  description = "Map of security policy names to their NSX paths"
  value       = module.security_policies.policy_paths
}
