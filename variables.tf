# =============================================================================
# NSX-T Provider Variables
# =============================================================================

variable "nsx_manager_host" {
  description = "NSX-T Manager hostname or IP address"
  type        = string
}

variable "nsx_username" {
  description = "NSX-T Manager username"
  type        = string
  sensitive   = true
}

variable "nsx_password" {
  description = "NSX-T Manager password"
  type        = string
  sensitive   = true
}

variable "nsx_allow_unverified_ssl" {
  description = "Allow unverified SSL certificates"
  type        = bool
  default     = false
}

variable "nsx_max_retries" {
  description = "Maximum number of retries for API calls"
  type        = number
  default     = 10
}

variable "nsx_retry_min_delay" {
  description = "Minimum delay in milliseconds between retries"
  type        = number
  default     = 500
}

variable "nsx_retry_max_delay" {
  description = "Maximum delay in milliseconds between retries"
  type        = number
  default     = 5000
}

# =============================================================================
# Data Source Paths (YAML or JSON files)
# =============================================================================

variable "security_groups_file" {
  description = "Path to YAML or JSON file containing security group definitions"
  type        = string
  default     = "data/security_groups.yaml"
}

variable "services_file" {
  description = "Path to YAML or JSON file containing service definitions"
  type        = string
  default     = "data/services.yaml"
}

variable "security_policies_file" {
  description = "Path to YAML or JSON file containing security policy definitions"
  type        = string
  default     = "data/security_policies.yaml"
}

# =============================================================================
# Global Configuration
# =============================================================================

variable "domain" {
  description = "NSX-T domain for resources (default for on-prem, cgw for VMC)"
  type        = string
  default     = "default"
}

variable "project_id" {
  description = "NSX-T project ID for multitenancy (optional)"
  type        = string
  default     = null
}

# =============================================================================
# Sequence Number Configuration
# =============================================================================

variable "policy_sequence_start" {
  description = "Starting sequence number for security policies (deprecated - use category-based)"
  type        = number
  default     = 1000
}

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

# =============================================================================
# Default Tags
# =============================================================================

variable "default_tags" {
  description = "Default tags to apply to all resources"
  type = list(object({
    scope = string
    tag   = string
  }))
  default = []
}

# =============================================================================
# Tolerance Settings
# =============================================================================

variable "tolerate_partial_success" {
  description = "Treat partially successful realization as valid state"
  type        = bool
  default     = false
}

