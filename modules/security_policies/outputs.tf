output "policy_paths" {
  description = "Map of policy names to their NSX paths"
  value       = { for k, v in nsxt_policy_security_policy.this : k => v.path }
}

output "policy_ids" {
  description = "Map of policy names to their IDs"
  value       = { for k, v in nsxt_policy_security_policy.this : k => v.id }
}

output "policies" {
  description = "Full security policy resources"
  value       = nsxt_policy_security_policy.this
}
