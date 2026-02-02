output "group_paths" {
  description = "Map of security group names to their NSX paths"
  value       = { for k, v in nsxt_policy_group.this : k => v.path }
}

output "group_ids" {
  description = "Map of security group names to their IDs"
  value       = { for k, v in nsxt_policy_group.this : k => v.id }
}

output "groups" {
  description = "Full security group resources"
  value       = nsxt_policy_group.this
}
