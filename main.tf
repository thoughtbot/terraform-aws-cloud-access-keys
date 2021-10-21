module "secret_manager" {
  source = "./modules/secret_manager"

  initial_value = jsonencode({
    AWS_ACCESS_KEY_ID     = var.aws_accesskey_id
    AWS_SECRET_ACCESS_KEY = var.aws_secret_accesskey
    TFE_TOKEN             = var.tfe_token
  })

  description = "Access ID and Access secret keys for terraform cloud"
  name        = "terraform-cloud-credentials"
  resource_tags = {
    type = "terraform-cloud"
  }
  rotation_days = 30
  handler       = "lambda_handler"
  runtime       = "python3.8"
  source_dir    = "${path.module}/lambda_script"
  env_variables = {
    USERNAME          = var.tfc_iam_username,
    META_WORKSPACE_ID = data.tfe_workspace.meta.id
    TFE_TEAM_ID       = data.tfe_team.this.id
    TFE_TEAM_NAME     = var.tfe_team_name
  }
}

resource "tfe_workspace" "this" {
  for_each = toset(var.workspace_paths)

  name              = replace(each.value, "/[./]/", "-")
  organization      = "thoughtbot"
  trigger_prefixes  = [each.value, join("/", [dirname(each.value), "modules"])]
  working_directory = each.value
  ssh_key_id        = data.tfe_ssh_key.this.id


  vcs_repo {
    identifier         = "thoughtbot/mission-control-ops"
    oauth_token_id     = tfe_oauth_client.this.oauth_token_id
    ingress_submodules = true
  }
}

resource "tfe_oauth_client" "this" {
  organization     = "thoughtbot"
  api_url          = "https://api.github.com"
  http_url         = "https://github.com"
  oauth_token      = var.oauth_token
  service_provider = "github"
}

data "tfe_ssh_key" "this" {
  name         = var.tfe_ssh_key
  organization = "thoughtbot"
}


data "tfe_workspace" "meta" {
  name         = "meta"
  organization = "thoughtbot"
}

data "tfe_team" "this" {
  name         = var.tfe_team_name
  organization = "thoughtbot"
}
