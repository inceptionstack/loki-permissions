variable "account_id" {
  description = "AWS account ID"
  type        = string
}

variable "agent_role_name" {
  description = "Name for the agent's IAM role"
  type        = string
  default     = "loki-agent-role"
}

variable "iam_path" {
  description = "IAM path prefix for agent-created roles (must end with /)"
  type        = string
  default     = "/loki/"

  validation {
    condition     = can(regex("^/.*/$", var.iam_path))
    error_message = "iam_path must start and end with /"
  }
}

variable "boundary_policy_name" {
  description = "Name of the permissions boundary policy"
  type        = string
  default     = "LokiPermissionsBoundary"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
