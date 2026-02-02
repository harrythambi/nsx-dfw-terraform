# =============================================================================
# Security Policies Module Variables
# =============================================================================

variable "security_policies" {
  description = "Map of security policies with their configurations"
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

variable "security_group_paths" {
  description = "Map of security group names to paths for reference"
  type        = map(string)
  default     = {}
}

variable "service_paths" {
  description = "Map of service names to paths for reference"
  type        = map(string)
  default     = {}
}

# =============================================================================
# Sequence Number Configuration
# =============================================================================

variable "policy_sequence_increment" {
  description = "Increment between policy sequence numbers within a category"
  type        = number
  default     = 10
}

variable "rule_sequence_start" {
  description = "Starting sequence number for rules within a policy"
  type        = number
  default     = 100
}

variable "rule_sequence_increment" {
  description = "Increment between rule sequence numbers within a policy"
  type        = number
  default     = 10
}
