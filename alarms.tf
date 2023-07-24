data "aws_caller_identity" "current" {}

# SNS Topic for Notifications
resource "aws_sns_topic" "account-security-alerts" {
  name = "Security-Alerts"
}

resource "aws_sns_topic_policy" "default" {
  arn    = aws_sns_topic.account-security-alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    sid = "alloweventbridge"
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.account-security-alerts.arn]
  }

  statement {
     sid = "allowusersubscriptions"
     effect = "Allow"
     actions = [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:AddPermission",
        "SNS:RemovePermission",
        "SNS:DeleteTopic",
        "SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Publish",
        "SNS:Receive"
      ]

      principals {
         type = "AWS"
         identifiers = ["*"]
      }

      resources = [aws_sns_topic.account-security-alerts.arn]

      condition {
          test = "StringLike"
          variable = "AWS:SourceOwner"
          values = [data.aws_caller_identity.current.account_id]
      }
  }
}

######################################################
## Monitor Root User Account Usage
resource "aws_cloudwatch_event_rule" "Alert-4-3" {
  name        = "Alert-Root-Account-Usage"
  description = "Respond to Root Account Usage"

  event_pattern = <<EOF
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "userIdentity": {
      "type": ["Root"],
      "invokedBy": [ { "exists": false } ]
    },
    "eventType": [{ "anything-but": "AwsServiceEvent"}]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-3" {
  rule      = aws_cloudwatch_event_rule.Alert-4-3.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

######################################################
## Monitor Changes to CloudTraill
resource "aws_cloudwatch_event_rule" "Alert-4-5" {
  name        = "Alert-Cloudtrail-Changes"
  description = "Respond to Cloudtrail Changes"

  event_pattern = <<EOF
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "CreateTrail",
      "UpdateTrail",
      "DeleteTrail",
      "StartLogging",
      "StopLogging"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-5" {
  rule      = aws_cloudwatch_event_rule.Alert-4-5.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

######################################################
## Monitor Console Login Failures

resource "aws_cloudwatch_event_rule" "Alert-4-6" {
  name        = "Alert-Console-Login-Failures"
  description = "Respond to Console Login Failures"

  event_pattern = <<EOF
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "responseElements": {
      "ConsoleLogin": ["Failure"]
    }
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-6" {
  rule      = aws_cloudwatch_event_rule.Alert-4-6.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

#####################################################
## Monitro AWS Config Changes
resource "aws_cloudwatch_event_rule" "Alert-4-9" {
  name        = "Alert-AWSConfig-Changes"
  description = "Respond to AWS Config Service Changes"

  event_pattern = <<EOF
{
  "source": ["aws.config"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["config.amazonaws.com"],
    "eventName": [
      "StopConfigurationRecorder",
      "DeleteDeliveryChannel",
      "PutDeliveryChannel",
      "PutConfigurationRecorder"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-9" {
  rule      = aws_cloudwatch_event_rule.Alert-4-9.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

## Monitor Network Gateway Changes
resource "aws_cloudwatch_event_rule" "Alert-4-12" {
  name        = "Alert-Network-Gateway-Changes"
  description = "Respond to Network Gateway Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "CreateCustomerGateway",
      "DeleteCustomerGateway",
      "AttachInternetGateway",
      "CreateInternetGateway",
      "DeleteInternetGateway",
      "DetachInternetGateway"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-12" {
  rule      = aws_cloudwatch_event_rule.Alert-4-12.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

## Monitor VPC Changes
resource "aws_cloudwatch_event_rule" "Alert-4-14" {
  name        = "Alert-VPC-Changes"
  description = "Respond to VPC Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "CreateVpc",
      "DeleteVpc",
      "ModifyVpcAttribute",
      "AcceptVpcPeeringConnection",
      "CreateVpcPeeringConnection",
      "DeleteVpcPeeringConnection",
      "RejectVpcPeeringConnection",
      "AttachClassicLinkVpc",
      "DetachClassicLinkVpc",
      "DisableVpcClassicLink",
      "EnableVpcClassicLink"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-14" {
  rule      = aws_cloudwatch_event_rule.Alert-4-14.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

############################################################
## Monitor Logins without MFA

resource "aws_cloudwatch_event_rule" "Alert-4-2" {
  name        = "Alert-Sign-In-Without-MFA"
  description = "Respond to Console login without MFA"

  event_pattern = <<EOF
    {
      "detail-type": ["AWS Console Sign In via CloudTrail"],
      "detail": {
        "eventName": ["ConsoleLogin"],
        "userIdentity": {
          "type": ["IAMUser"]
        },
        "additionalEventData": {
          "MFAUsed": [{ "anything-but": "Yes"}]
        },
        "responseElements": {
          "ConsoleLogin": ["Success"]
        }
      }
    }
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-2" {
  rule      = aws_cloudwatch_event_rule.Alert-4-2.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}

########################################################
## Monitor Unathorized API Calls

resource "aws_cloudwatch_event_rule" "Alert-4-1" {
  name        = "Alert-Unauthorized-API-Calls"
  description = "Respond to Unauthorized API Calls"

  event_pattern = <<EOF
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "errorCode": ["AccessDenied*", "*UnauthorizedOperation"]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-1" {
  rule      = aws_cloudwatch_event_rule.Alert-4-1.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.account-security-alerts.arn
}