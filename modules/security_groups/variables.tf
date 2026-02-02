# =============================================================================
# Security Groups Module Variables
# =============================================================================

variable "security_groups" {
  description = "Map of security groups with their configurations"
  type        = any
  default     = {}
}

variable "domain" {
  description = "NSX-T domain"
  type        = string
  default     = "default"
}

variable "project_id" {
  description = "NSX-T project ID for multitenancy"
  type        = string
  default     = null
}

variable "default_tags" {
  description = "Default tags to apply to all resources"
  type = list(object({
    scope = string
    tag   = string
  }))
  default = []
}

variable "tolerate_partial_success" {
  description = "Treat partially successful realization as valid state"
  type        = bool
  default     = false
}

variable "group_path_lookup" {
  description = "Map of group names to paths for resolving member_groups references"
  type        = map(string)
  default     = {}
}
