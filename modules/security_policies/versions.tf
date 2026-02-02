terraform {
  required_version = ">= 1.0.0"

  required_providers {
    nsxt = {
      source  = "vmware/nsxt"
      version = ">= 3.4.0"
    }
  }
}
