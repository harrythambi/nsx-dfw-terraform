# =============================================================================
# Services Module Outputs
# =============================================================================

output "service_paths" {
  description = "Map of service names to their NSX paths"
  value = merge(
    { for k, v in nsxt_policy_service.leaf : k => v.path },
    { for k, v in nsxt_policy_service.nested : k => v.path }
  )
}

output "service_ids" {
  description = "Map of service names to their IDs"
  value = merge(
    { for k, v in nsxt_policy_service.leaf : k => v.id },
    { for k, v in nsxt_policy_service.nested : k => v.id }
  )
}

output "services" {
  description = "Full service resources"
  value = merge(nsxt_policy_service.leaf, nsxt_policy_service.nested)
}

output "predefined_service_paths" {
  description = "Map of predefined service names to their NSX paths (constructed)"
  value       = local.predefined_service_path_lookup
}

output "all_service_paths" {
  description = "Combined map of custom and predefined service paths"
  value = merge(
    { for k, v in nsxt_policy_service.leaf : k => v.path },
    { for k, v in nsxt_policy_service.nested : k => v.path },
    local.predefined_service_path_lookup
  )
}
