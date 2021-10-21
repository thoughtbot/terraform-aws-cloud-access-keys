variable "tfe_token" {}

variable "oauth_token" {}

variable "tfe_ssh_key" {}

variable "tfc_iam_username" {}

variable "github_token" {}

variable "new_relic_account_id" {}

variable "new_relic_api_key" {}

variable "pagerduty_token" {}

variable "pagerduty_user_token" {}

variable "slack_token" {}

variable "aws_accesskey_id" {}

variable "aws_secret_accesskey" {}

variable "tfe_team_name" {}

variable "workspace_paths" {
  description = "Paths to workspaces within this repository"
  type        = list(string)
}
