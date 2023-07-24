variable "audit_account_id" {
  type        = string
  description = "audit account id"
}

variable "control_tower_logs_s3" {
  type        = string
  description = "Control Tower Logging S3 Bucket"
}

variable "org_id" {
  type        = string
  description = "Org ID"
}
