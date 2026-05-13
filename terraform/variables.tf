variable "account_id" {
  description = "AWS account ID"
  type        = string
}

variable "agent_role_name" {
  description = "Name for the agent's IAM role"
  type        = string
  default     = "loki-agent-role"

  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.agent_role_name))
    error_message = "agent_role_name must match IAM naming rules: letters/digits and any of +=,.@-_, 1–64 chars. No slashes, spaces, or colons (would corrupt ARN composition)."
  }
}

variable "iam_path" {
  description = "IAM path prefix for agent-created roles (must end with /)"
  type        = string
  default     = "/loki/"

  validation {
    condition     = can(regex("^/([\\w+=,.@-]+/)+$", var.iam_path))
    error_message = "iam_path must be a valid IAM path (e.g. /loki/ or /loki/sub/) starting and ending with /, with at least one path segment. Empty string and bare root '/' are both rejected because they would widen ARN-scoped allows like 'role/${var.iam_path}*' to 'role/*' (every role in the account)."
  }
}

variable "boundary_policy_name" {
  description = "Name of the permissions boundary policy"
  type        = string
  default     = "LokiPermissionsBoundary"

  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,128}$", var.boundary_policy_name))
    error_message = "boundary_policy_name must match IAM policy naming rules: letters/digits and any of +=,.@-_, 1–128 chars. No slashes, spaces, or colons (would corrupt ARN composition)."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "trail_bucket_name" {
  description = <<-EOT
    Name of the S3 bucket holding CloudTrail logs. When set, adds
    DenyTrailStorageTampering scoped to this bucket. Leave null to skip
    (e.g. if no CloudTrail exists, or the bucket is managed by a
    separate Terraform state with its own protections). Must be
    managed *outside* this agent's Terraform state — the agent role
    will be denied PutBucketPolicy/PutEncryptionConfiguration on it.

    Pass the BARE bucket name (e.g. "my-org-cloudtrail-logs"), NOT a
    full S3 ARN. Pasting an ARN produces a malformed deny resource
    (arn:aws:s3:::arn:aws:s3:::foo) that silently matches nothing.
  EOT
  type        = string
  default     = null

  validation {
    # S3 bucket-name rules (subset that catches the common mistakes):
    #   - 3–63 chars
    #   - lowercase letters, digits, dot, hyphen only
    #   - must start and end with letter or digit
    #   - no consecutive dots (S3 rejects "a..b")
    # Notably rejects: ARNs (contain colons), uppercase, underscores.
    # Does NOT validate IP-format names (192.168.x.x) or xn-- prefix —
    # AWS rejects those server-side at apply time.
    condition = (
      var.trail_bucket_name == null ||
      (
        can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.trail_bucket_name)) &&
        !can(regex("\\.\\.", var.trail_bucket_name))
      )
    )
    error_message = "trail_bucket_name must be a bare S3 bucket name (3–63 chars, lowercase alphanumerics + dots/hyphens, no colons), not a full ARN. Got: ${var.trail_bucket_name == null ? "<null>" : (var.trail_bucket_name == "" ? "<empty string>" : var.trail_bucket_name)}"
  }
}

variable "trail_kms_key_arn" {
  description = <<-EOT
    Full ARN of the KMS CMK encrypting CloudTrail. When set, adds
    DenyTrailKmsTampering scoped to this key. Leave null if the trail
    is unencrypted or absent. Must be a full key ARN
    (arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID), not a key UUID or alias
    — a partial value yields a silent no-op deny.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.trail_kms_key_arn == null || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/(mrk-[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$", var.trail_kms_key_arn))
    error_message = "trail_kms_key_arn must be a full KMS key ARN for AWS commercial region (arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID or .../key/mrk-... for multi-region keys), or null. Note: partition support (aws-us-gov, aws-cn) is planned for a future release; currently this policy only supports AWS commercial regions."
  }
}

variable "trail_protection_acknowledged" {
  description = <<-EOT
    Set to true when you have intentionally left trail_bucket_name AND
    trail_kms_key_arn null because the account has no CloudTrail (or the
    trail is managed in a way where these denies are inappropriate).

    This is a fail-closed safety check: if both vars are null and this
    flag is false, plan/apply errors out. The intent is to prevent the
    common case of "forgot to set the trail vars" silently deploying
    without audit-trail tampering protection while the agent retains
    PowerUser-level S3/KMS access to the (existing) trail bucket/CMK.
  EOT
  type        = bool
  default     = false
}
