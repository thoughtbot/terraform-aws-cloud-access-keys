resource "tfe_variable" "meta_aws_accesskey_id" {

  key          = "AWS_ACCESS_KEY_ID"
  value        = var.aws_accesskey_id
  category     = "env"
  sensitive    = true
  workspace_id = data.tfe_workspace.meta.id
  description  = "aws iam user access key ID"
}

resource "tfe_variable" "meta_aws_secret_accesskey" {

  key          = "AWS_SECRET_ACCESS_KEY"
  value        = var.aws_secret_accesskey
  category     = "env"
  sensitive    = true
  workspace_id = data.tfe_workspace.meta.id
  description  = "aws iam secret access key"
}

resource "tfe_variable" "tfe_token" {
  for_each = tfe_workspace.this

  key          = "TFE_TOKEN"
  value        = var.tfe_token
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "terraform cloud token"
}

resource "tfe_variable" "aws_accesskey_id" {
  for_each = tfe_workspace.this

  key          = "AWS_ACCESS_KEY_ID"
  value        = var.aws_accesskey_id
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "aws iam user access key ID"
}

resource "tfe_variable" "aws_secret_accesskey" {
  for_each = tfe_workspace.this

  key          = "AWS_SECRET_ACCESS_KEY"
  value        = var.aws_secret_accesskey
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "aws iam secret access key"
}

resource "tfe_variable" "github_token" {
  for_each = tfe_workspace.this

  key          = "GITHUB_TOKEN"
  value        = var.GITHUB_TOKEN
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "ssm parameter store github token"
}

resource "tfe_variable" "new_relic_account_id" {
  for_each = tfe_workspace.this

  key          = "NEW_RELIC_ACCOUNT_ID"
  value        = var.NEW_RELIC_ACCOUNT_ID
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "ssm parameter store new relic account id"
}

resource "tfe_variable" "new_relic_api_key" {
  for_each = tfe_workspace.this

  key          = "NEW_RELIC_API_KEY"
  value        = var.NEW_RELIC_API_KEY
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "ssm parameter new relic api key"
}

resource "tfe_variable" "pagerduty_token" {
  for_each = tfe_workspace.this

  key          = "PAGERDUTY_TOKEN"
  value        = var.PAGERDUTY_TOKEN
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "ssm parameter pagerduty token"
}

resource "tfe_variable" "pagerduty_user_token" {
  for_each = tfe_workspace.this

  key          = "PAGERDUTY_USER_TOKEN"
  value        = var.PAGERDUTY_USER_TOKEN
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "ssm parameter pagerduty user token"
}

resource "tfe_variable" "slack_token" {
  for_each = tfe_workspace.this

  key          = "SLACK_TOKEN"
  value        = var.SLACK_TOKEN
  category     = "env"
  sensitive    = true
  workspace_id = each.value.id
  description  = "ssm parameter slack token"
}
