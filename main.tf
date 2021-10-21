data "archive_file" "function" {
  output_path = "${path.module}/${local.secret_id}.zip"
  source_dir  = "${path.module}/lambda_script"
  type        = "zip"
}

data "aws_caller_identity" "this" {}

data "aws_iam_policy_document" "kms_key" {
  statement {
    resources = ["*"]
    sid       = "AllowManagement"

    not_actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]

    principals {
      identifiers = [local.account_arn]
      type        = "AWS"
    }
  }

  statement {
    resources = ["*"]
    sid       = "AllowSecretsManager"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]

    principals {
      identifiers = [local.account_arn]
      type        = "AWS"
    }
  }
}

data "aws_iam_policy_document" "rotation" {
  statement {
    resources = [aws_secretsmanager_secret.this.arn]
    sid       = "ManageSecret"

    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]
  }

  statement {
    resources = [aws_kms_key.this.arn]
    sid       = "UseKey"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
  }
}

data "aws_iam_policy_document" "rotation_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "secret" {
  statement {
    resources = ["*"]
    sid       = "AllowRotation"

    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]

    principals {
      identifiers = [aws_iam_role.rotation.arn]
      type        = "AWS"
    }
  }
}

data "aws_region" "this" {}

locals {
  account_arn  = "arn:aws:iam::${local.account_id}:root"
  account_id   = data.aws_caller_identity.this.account_id
  endpoint     = "https://secretsmanager.${local.region}.amazonaws.com"
  region       = data.aws_region.this.name
  secret_id    = local.secret_parts[length(local.secret_parts) - 1]
  secret_parts = split(":", aws_secretsmanager_secret.this.arn)
}

resource "aws_iam_policy" "rotation" {
  name   = "${var.name}-rotation"
  policy = data.aws_iam_policy_document.rotation.json
  tags   = var.resource_tags
}

resource "aws_iam_role" "rotation" {
  assume_role_policy = data.aws_iam_policy_document.rotation_assume_role.json
  name               = "${var.name}-rotation"
  tags               = var.resource_tags
}

resource "aws_iam_role_policy_attachment" "rotation" {
  policy_arn = aws_iam_policy.rotation.arn
  role       = aws_iam_role.rotation.id
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.arn
}

resource "aws_kms_key" "this" {
  description         = var.name
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms_key.json
  tags                = var.resource_tags
}

resource "aws_lambda_function" "rotation" {
  description      = "Rotate function for ${local.secret_id}"
  filename         = data.archive_file.function.output_path
  function_name    = local.secret_id
  handler          = "lambda_handler"
  role             = aws_iam_role.rotation.arn
  runtime          = "python3.8"
  source_code_hash = data.archive_file.function.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      IAM_USERNAME             = var.aws_iam_username
      SECRETS_MANAGER_ENDPOINT = local.endpoint
      TFE_TEAM_ID              = data.tfe_team.this.id
      TFE_TEAM_NAME            = data.tfe_team.this.name
      TFE_WORKSPACE_ID         = data.tfe_workspace.this.id
    }
  }
}

resource "aws_lambda_permission" "secretsmanager" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
  statement_id  = "AllowSecretManager"
}

resource "aws_secretsmanager_secret" "this" {
  description = "AWS access keys and Terraform Cloud token for Terraform Cloud"
  kms_key_id  = aws_kms_key.this.arn
  name        = var.name
  tags        = var.resource_tags
}

resource "aws_secretsmanager_secret_policy" "this" {
  policy     = data.aws_iam_policy_document.secret.json
  secret_arn = aws_secretsmanager_secret.this.arn
}

resource "aws_secretsmanager_secret_rotation" "this" {
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  secret_id           = aws_secretsmanager_secret.this.arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

resource "aws_secretsmanager_secret_version" "initial" {
  secret_id = aws_secretsmanager_secret.this.id

  secret_string = jsonencode({
    AWS_ACCESS_KEY_ID     = var.aws_access_key_id
    AWS_SECRET_ACCESS_KEY = var.aws_secret_access_key
    TFE_TOKEN             = tfe_team_token.initial.token
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

data "tfe_team" "this" {
  name         = var.terraform_team_name
  organization = var.terraform_organization_name
}

data "tfe_workspace" "this" {
  name         = var.terraform_workspace_name
  organization = var.terraform_organization_name
}

resource "tfe_team_token" "initial" {
  team_id = data.tfe_team.this.id
}
