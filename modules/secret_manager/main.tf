
data "aws_region" "this" {}

data "aws_caller_identity" "this" {}

locals {
  account_arn     = "arn:aws:iam::${local.account_id}:root"
  account_id      = data.aws_caller_identity.this.account_id
  region          = data.aws_region.this.name
  sid_suffix      = join("", regexall("[[:alnum:]]+", var.name))
  trust_principal = coalesce(var.trust_principal, local.account_arn)
  endpoint        = "https://secretsmanager.${local.region}.amazonaws.com"
  role_name       = split("/", aws_iam_role.rotation.arn)[1]
  secret_parts    = split(":", aws_secretsmanager_secret.this.arn)
  secret_id       = local.secret_parts[length(local.secret_parts) - 1]
}
