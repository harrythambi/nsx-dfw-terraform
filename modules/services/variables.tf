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
