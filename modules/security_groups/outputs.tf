output "group_paths" {
  description = "Map of security group names to their NSX paths"
  value = merge(
    { for k, v in nsxt_policy_group.leaf : k => v.path },
    { for k, v in nsxt_policy_group.nested : k => v.path }
  )
}

output "group_ids" {
  description = "Map of security group names to their IDs"
  value = merge(
    { for k, v in nsxt_policy_group.leaf : k => v.id },
    { for k, v in nsxt_policy_group.nested : k => v.id }
  )
}

output "groups" {
  description = "Full security group resources"
  value = merge(nsxt_policy_group.leaf, nsxt_policy_group.nested)
}
