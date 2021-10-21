data "aws_iam_policy_document" "rotation_assume_role" {

  statement {
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }
  }
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

resource "aws_iam_policy" "rotation" {
  name   = "${var.name}-rotation"
  policy = data.aws_iam_policy_document.rotation.json
  tags   = var.resource_tags
}

data "aws_iam_policy_document" "rotation" {
  statement {
    sid = "ManageSecret"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]
    resources = [aws_secretsmanager_secret.this.arn]
  }

  statement {
    sid = "UseKey"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [aws_kms_key.this.arn]
  }
}

resource "aws_lambda_function" "rotation" {
  description      = "Rotate function for ${local.secret_id}"
  filename         = data.archive_file.function.output_path
  function_name    = local.secret_id
  handler          = var.handler
  role             = aws_iam_role.rotation.arn
  runtime          = var.runtime
  source_code_hash = data.archive_file.function.output_base64sha256
  timeout          = 60

  environment {
    variables = merge(
      var.env_variables,
      { SECRETS_MANAGER_ENDPOINT = local.endpoint }
    )
  }
}

data "archive_file" "function" {
  output_path = "${path.module}/${local.secret_id}.zip"
  source_dir  = var.source_dir
  type        = "zip"
}

resource "aws_lambda_permission" "secretsmanager" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
  statement_id  = "AllowSecretManager"
}
