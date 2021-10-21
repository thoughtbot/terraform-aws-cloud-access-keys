terraform {
  backend "remote" {
    organization = "thoughtbot"

    workspaces {
      name = "meta"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
