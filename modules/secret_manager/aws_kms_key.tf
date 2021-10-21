resource "aws_kms_key" "this" {
  description         = var.name
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms_key.json
  tags                = var.resource_tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.arn
}

data "aws_iam_policy_document" "kms_key" {
  statement {
    sid = "AllowManagement"
    not_actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = ["*"]
    principals {
      identifiers = [local.account_arn]
      type        = "AWS"
    }
  }

  statement {
    sid = "AllowSecretsManager"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = ["*"]
    principals {
      identifiers = [local.account_arn]
      type        = "AWS"
    }
  }
}
