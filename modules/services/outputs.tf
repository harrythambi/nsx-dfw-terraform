# =============================================================================
# Services Module Outputs
# =============================================================================

output "service_paths" {
  description = "Map of service names to their NSX paths"
  value       = { for k, v in nsxt_policy_service.this : k => v.path }
}

output "service_ids" {
  description = "Map of service names to their IDs"
  value       = { for k, v in nsxt_policy_service.this : k => v.id }
}

output "services" {
  description = "Full service resources"
  value       = nsxt_policy_service.this
}

output "predefined_service_paths" {
  description = "Map of predefined service names to their NSX paths"
  value       = { for k, v in data.nsxt_policy_service.predefined : k => v.path }
}

output "all_service_paths" {
  description = "Combined map of custom and predefined service paths"
  value = merge(
    { for k, v in nsxt_policy_service.this : k => v.path },
    { for k, v in data.nsxt_policy_service.predefined : k => v.path }
  )
}
