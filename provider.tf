# =============================================================================
# NSX-T Provider Configuration
# =============================================================================

provider "nsxt" {
  host                 = var.nsx_manager_host
  username             = var.nsx_username
  password             = var.nsx_password
  allow_unverified_ssl = var.nsx_allow_unverified_ssl
  max_retries          = var.nsx_max_retries
  retry_min_delay      = var.nsx_retry_min_delay
  retry_max_delay      = var.nsx_retry_max_delay
}
