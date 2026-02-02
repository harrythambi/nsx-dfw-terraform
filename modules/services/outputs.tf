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
