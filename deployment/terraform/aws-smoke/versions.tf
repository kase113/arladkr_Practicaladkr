terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = {
      ManagedBy       = "terraform"
      ProtocolSuite   = var.protocol_suite
      ExperimentGroup = var.experiment_group
    }
  }
}
