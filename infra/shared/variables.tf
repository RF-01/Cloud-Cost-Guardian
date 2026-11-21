variable "aws_profile" {
  description = "AWS CLI profile to run as (your IAM user, never root)"
  type        = string
  default     = "guardian"
}

variable "owner_email" {
  description = "Owner tag for the account-wide resources"
  type        = string
  default     = "rif07@mail.aub.edu"
}

variable "team_members" {
  description = "IAM username => email (the email tag used by the CloudTrail creator lookup)"
  type        = map(string)
  default = {
    reda   = "rif07@mail.aub.edu"
    khaled = "kfs14@mail.aub.edu"
    ahmad  = "afe18@mail.aub.edu"
    meryem = "mrs28@mail.aub.edu"
  }
}

variable "sender_email" {
  description = "From address of every Guardian email (must be verified in SES)"
  type        = string
  default     = "rif07@mail.aub.edu"
}

variable "team_email" {
  description = "Team address: alerts and findings with no known owner"
  type        = string
  default     = "rif07@mail.aub.edu"
}
