# Terraform Cloud AWS Access Keys

This module will create a Secrets Manager secret to rotate AWS access keys for
use in a Terraform Cloud workspace. The included Lambda rotation function will
generate new access keys and new Terraform Cloud OAuth tokens on a schedule and
write the new values as variables to a Terraform Cloud Workspace.

## Prerequisites

* An IAM user capable of managing its own access keys
* An existing access key for the above IAM user
* A Terraform Workspace to which access keys will be provided

## Usage

```
module "aws_access_keys" {
  source = "git@github.com:thoughtbot/terraform-cloud-aws-access-keys.git?ref=v0.1.0"

  # Provide details for your existing IAM user
  aws_access_key_id           = var.aws_access_key_id
  aws_iam_username            = "terraform-cloud"
  aws_secret_access_key       = var.aws_secret_access_key

  # Provide a name for the Secrets Manager secret
  name                        = "terraform-cloud-access-keys"

  # Provide details about your Terraform workspace
  # Hint: you can provide the name of the workspace in which the module is used
  terraform_organization_name = "my_org"
  terraform_team_name         = "owners"
  terraform_workspace_name    = "meta"
}
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.14.0 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | ~> 2.2 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 3.45 |
| <a name="requirement_tfe"></a> [tfe](#requirement\_tfe) | ~> 0.26 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | 2.2.0 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 3.63.0 |
| <a name="provider_tfe"></a> [tfe](#provider\_tfe) | 0.26.1 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_iam_policy.rotation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.rotation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.rotation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_alias.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_lambda_function.rotation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.secretsmanager](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_secretsmanager_secret.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_policy) | resource |
| [aws_secretsmanager_secret_rotation.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation) | resource |
| [aws_secretsmanager_secret_version.initial](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version) | resource |
| [tfe_team_token.initial](https://registry.terraform.io/providers/hashicorp/tfe/latest/docs/resources/team_token) | resource |
| [archive_file.function](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.kms_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.rotation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.rotation_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.secret](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [tfe_team.this](https://registry.terraform.io/providers/hashicorp/tfe/latest/docs/data-sources/team) | data source |
| [tfe_workspace.this](https://registry.terraform.io/providers/hashicorp/tfe/latest/docs/data-sources/workspace) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_access_key_id"></a> [aws\_access\_key\_id](#input\_aws\_access\_key\_id) | Initial AWS IAM user access key ID | `string` | n/a | yes |
| <a name="input_aws_iam_username"></a> [aws\_iam\_username](#input\_aws\_iam\_username) | AWS IAM username for which access keys will be rotated | `string` | n/a | yes |
| <a name="input_aws_secret_access_key"></a> [aws\_secret\_access\_key](#input\_aws\_secret\_access\_key) | Initial AWS IAM secret access key | `string` | n/a | yes |
| <a name="input_name"></a> [name](#input\_name) | Name for the Secret Manager secret | `string` | n/a | yes |
| <a name="input_resource_tags"></a> [resource\_tags](#input\_resource\_tags) | Tags to be applied to created resources | `map(string)` | `{}` | no |
| <a name="input_rotation_days"></a> [rotation\_days](#input\_rotation\_days) | Number of days after which the secret is rotated | `number` | `30` | no |
| <a name="input_terraform_organization_name"></a> [terraform\_organization\_name](#input\_terraform\_organization\_name) | Terraform organization for which tokens will be generated | `string` | n/a | yes |
| <a name="input_terraform_team_name"></a> [terraform\_team\_name](#input\_terraform\_team\_name) | Terraform team for which tokens will be generated | `string` | `"owners"` | no |
| <a name="input_terraform_workspace_name"></a> [terraform\_workspace\_name](#input\_terraform\_workspace\_name) | Name of the Terraform workspace to update | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END_TF_DOCS -->
