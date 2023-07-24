# tf-aft-mgr-account-grolston-statefile
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
  backend "s3" {
    bucket = "tf-aft-mgr-account-grolston-statefile"
    key    = "management-account"
    region = "us-east-1"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

## Config Setup

resource "aws_iam_role" "config_role" {
  name = "george-config"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "config_role_attachment" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}


resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "george-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "config_dc" {
  name           = "org-config-delivery-channel"
  s3_bucket_name = var.control_tower_logs_s3
  s3_key_prefix  = var.org_id
  #sns_topic_arn  = "${var.sns_topic_arn}"

  snapshot_delivery_properties {
    delivery_frequency = "Three_Hours"
  }

  depends_on = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_configuration_recorder_status" "config_status" {
  name       = aws_config_configuration_recorder.config_recorder.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.config_dc]
}


resource "aws_organizations_organization" "org_aft" {
  aws_service_access_principals = ["guardduty.amazonaws.com",
    "account.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "controltower.amazonaws.com",
    "sso.amazonaws.com",
  "securityhub.amazonaws.com"]
  feature_set          = "ALL"
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}

## Guard Duty
resource "aws_guardduty_detector" "management_account_guardduty_detector" {
  finding_publishing_frequency = "ONE_HOUR"
}

resource "aws_guardduty_organization_admin_account" "org_aft_guardduty_da" {
  depends_on       = [aws_organizations_organization.org_aft]
  admin_account_id = var.audit_account_id
}

## SecurityHub

resource "aws_securityhub_account" "management_account_securityhub" {}

resource "aws_securityhub_organization_admin_account" "org_aft_securityhub" {
  depends_on       = [aws_organizations_organization.org_aft]
  admin_account_id = var.audit_account_id
}

