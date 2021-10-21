variable "aws_access_key_id" {
  description = "Initial AWS IAM user access key ID"
  type        = string
}

variable "aws_secret_access_key" {
  description = "Initial AWS IAM secret access key"
  type        = string
}

variable "aws_iam_username" {
  description = "AWS IAM username for which access keys will be rotated"
  type        = string
}

variable "name" {
  description = "Name for the Secret Manager secret"
  type        = string
}

variable "resource_tags" {
  default     = {}
  description = "Tags to be applied to created resources"
  type        = map(string)
}

variable "rotation_days" {
  default     = 30
  description = "Number of days after which the secret is rotated"
  type        = number
}

variable "terraform_organization_name" {
  description = "Terraform organization for which tokens will be generated"
  type        = string
}

variable "terraform_team_name" {
  description = "Terraform team for which tokens will be generated"
  type        = string
  default     = "owners"
}

variable "terraform_workspace_name" {
  description = "Name of the Terraform workspace to update"
  type        = string
}
