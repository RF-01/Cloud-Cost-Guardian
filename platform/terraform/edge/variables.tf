# Inputs per CONTRACT §8 (platform edge row) plus name_prefix, owner_email, dry_run.

variable "name_prefix" {
  description = "Prefix of every resource name, e.g. cg-dev- (CONTRACT §1)"
  type        = string
}

variable "owner_email" {
  description = "Owner of this stack (tags come from the root's default_tags)"
  type        = string
}

variable "dry_run" {
  description = "Stack DRY_RUN. CloudFront doesn't act on resources, so it's unused"
  type        = bool
}

variable "dashboard_public_dns" {
  description = "Dashboard instance public DNS name (dashboard module output): CloudFront's origin"
  type        = string
}

variable "origin_secret" {
  description = "X-Origin-Verify value CloudFront adds to every origin request (design §6.4)"
  type        = string
  sensitive   = true
}

variable "dashboard_username" {
  description = "Team login checked by the CloudFront Function (basic auth)"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{3,32}$", var.dashboard_username))
    error_message = "dashboard_username must be 3-32 letters, digits, '.', '_' or '-' (no ':', basic auth splits on it)."
  }
}

variable "dashboard_password" {
  description = "Team password checked by the CloudFront Function (basic auth)"
  type        = string
  sensitive   = true
}
