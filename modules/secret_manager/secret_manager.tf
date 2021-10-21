resource "aws_secretsmanager_secret" "this" {
  description = var.description
  kms_key_id  = aws_kms_key.this.arn
  name        = var.name
  tags        = var.resource_tags
}


resource "aws_secretsmanager_secret_policy" "this" {
  secret_arn = aws_secretsmanager_secret.this.arn
  policy     = data.aws_iam_policy_document.secret.json
}

data "aws_iam_policy_document" "secret" {

  statement {
    sid       = "AllowRotation"
    resources = ["*"]
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.rotation.arn]
    }
  }

  statement {
    sid       = "AllowRead"
    resources = ["*"]
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
    ]
    principals {
      type        = "AWS"
      identifiers = [local.trust_principal]
    }

  }
}

resource "aws_secretsmanager_secret_version" "initial" {
  secret_id     = aws_secretsmanager_secret.this.id
  secret_string = var.initial_value

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_rotation" "this" {
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  secret_id           = aws_secretsmanager_secret.this.arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}
