# =============================================================================
# Services Module Variables
# =============================================================================

variable "services" {
  description = "Map of services with their configurations"
  type        = any
  default     = {}
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

variable "service_path_lookup" {
  description = "Map of service names to paths for resolving nested service references"
  type        = map(string)
  default     = {}
}

variable "predefined_services_to_lookup" {
  description = "List of predefined NSX service names to look up via data source"
  type        = list(string)
  default     = []
}
