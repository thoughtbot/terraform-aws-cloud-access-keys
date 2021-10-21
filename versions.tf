terraform {
  required_providers {
    archive = { source = "hashicorp/archive", version = "~> 2.2" }
    aws     = { source = "hashicorp/aws", version = "~> 3.45" }
    tfe     = { source = "hashicorp/tfe", version = "~> 0.26" }
  }

  required_version = ">= 0.14.0"
}
