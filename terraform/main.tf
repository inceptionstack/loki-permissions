locals {

  # ---------------------------------------------------------------------------
  # PARTITION LOCK-IN (deferred; revisit if GovCloud / China support is needed)
  # ---------------------------------------------------------------------------
  # The AWS partition `aws` is hardcoded in 3 places:
  #   1. terraform/main.tf      — ARN composition (`arn:aws:iam:...`, etc.)
  #   2. policies/*.json        — inline ARN literals
  #   3. terraform/variables.tf — `trail_kms_key_arn` validation regex
  # User decision (2026-05-13): no GovCloud/China support in this template.
  # If that changes, introduce `var.aws_partition` (default "aws") and thread
  # it through all 3 sites — don't fix one in isolation.
  # ---------------------------------------------------------------------------

  # Fail-closed safety check: if neither trail var is set, the user
  # must explicitly acknowledge they have no CloudTrail to protect.
  # Otherwise the deny statements silently disappear while the agent
  # keeps PowerUser-level S3/KMS access to whatever audit trail does
  # exist in the account. See trail_protection_acknowledged in
  # variables.tf.
  trail_protection_omitted = var.trail_bucket_name == null && var.trail_kms_key_arn == null
}

# --- Permissions Boundary ---
# Caps the maximum permissions of any role the agent creates.
# Even if the agent attaches AdministratorAccess, effective perms are limited.

resource "aws_iam_policy" "permissions_boundary" {
  name        = var.boundary_policy_name
  path        = var.iam_path
  description = "Permissions boundary for AI agent-created roles. Blocks IAM/Orgs/Account."

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.permissions_boundary_statements
  })

  tags = var.tags
}

# --- Agent Role ---

resource "aws_iam_role" "agent" {
  name = var.agent_role_name
  path = var.iam_path

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

# Base: PowerUserAccess
resource "aws_iam_role_policy_attachment" "power_user" {
  role       = aws_iam_role.agent.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Scoped IAM permissions
resource "aws_iam_role_policy" "iam_scoped" {
  name = "LokiIAMScoped"
  role = aws_iam_role.agent.name

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.iam_scoped_statements
  })
}

# Deny guardrails — explicit denies that can't be overridden
resource "aws_iam_role_policy" "deny_guardrails" {
  name = "LokiDenyGuardrails"
  role = aws_iam_role.agent.name

  lifecycle {
    precondition {
      condition     = !local.trail_protection_omitted || var.trail_protection_acknowledged
      error_message = "BOTH trail_bucket_name AND trail_kms_key_arn are null — DenyTrailStorageTampering and DenyTrailKmsTampering will NOT be deployed. ** This disables an entire defense layer. ** If your account has a CloudTrail, the agent retains PowerUser-level S3/KMS access to its bucket and CMK; audit-trail tampering will not be blocked. To proceed anyway (e.g. no trail exists, or trail protection is enforced elsewhere), set trail_protection_acknowledged = true — you are responsible for the resulting risk."
    }
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      local.deny_guardrails_base_statements,
      var.trail_bucket_name != null ? [local.deny_trail_storage_statement] : [],
      var.trail_kms_key_arn != null ? [local.deny_trail_kms_statement] : []
    )
  })
}

locals {
  permissions_boundary_statements = [
    {
      Sid       = "AllowEverythingExceptDangerous"
      Effect    = "Allow"
      NotAction = ["iam:*", "organizations:*", "account:*"]
      Resource  = "*"
    },
    {
      Sid      = "AllowPassRoleOnlyAgentRoles"
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = "arn:aws:iam::${var.account_id}:role${var.iam_path}*"
    },
    {
      Sid    = "AllowReadOnlyIAM"
      Effect = "Allow"
      Action = [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies"
      ]
      Resource = "*"
    }
  ]

  iam_scoped_statements = [
    {
      Sid    = "AllowRoleManagementUnderAgentPath"
      Effect = "Allow"
      Action = [
        "iam:CreateRole", "iam:DeleteRole", "iam:GetRole",
        "iam:GetRolePolicy", "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
        "iam:TagRole", "iam:UntagRole", "iam:ListRoleTags",
        "iam:UpdateRole", "iam:UpdateRoleDescription",
        "iam:UpdateAssumeRolePolicy",
        "iam:PutRolePolicy", "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy", "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary"
      ]
      Resource = "arn:aws:iam::${var.account_id}:role${var.iam_path}*"
    },
    {
      Sid    = "AllowPolicyManagementUnderAgentPath"
      Effect = "Allow"
      Action = [
        "iam:CreatePolicy", "iam:DeletePolicy",
        "iam:GetPolicy", "iam:GetPolicyVersion",
        "iam:ListPolicyVersions", "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion", "iam:TagPolicy", "iam:UntagPolicy"
      ]
      Resource = "arn:aws:iam::${var.account_id}:policy${var.iam_path}*"
    },
    {
      Sid    = "AllowInstanceProfileManagementUnderAgentPath"
      Effect = "Allow"
      Action = [
        "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
        "iam:GetInstanceProfile", "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile"
      ]
      Resource = "arn:aws:iam::${var.account_id}:instance-profile${var.iam_path}*"
    },
    {
      Sid      = "AllowPassRoleOnlyAgentRoles"
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = "arn:aws:iam::${var.account_id}:role${var.iam_path}*"
    },
    {
      Sid    = "AllowServiceLinkedRoles"
      Effect = "Allow"
      Action = [
        "iam:CreateServiceLinkedRole",
        "iam:DeleteServiceLinkedRole",
        "iam:GetServiceLinkedRoleDeletionStatus"
      ]
      Resource = "arn:aws:iam::${var.account_id}:role/aws-service-role/*"
    },
    {
      Sid    = "AllowIAMReadOnly"
      Effect = "Allow"
      Action = [
        "iam:ListRoles", "iam:ListPolicies", "iam:ListInstanceProfiles",
        "iam:GetAccountSummary", "iam:SimulatePrincipalPolicy",
        "iam:ListOpenIDConnectProviders", "iam:ListSAMLProviders"
      ]
      Resource = "*"
    }
  ]

  deny_guardrails_base_statements = [
    {
      Sid    = "DenyIdentityManagement"
      Effect = "Deny"
      Action = [
        "iam:CreateUser", "iam:DeleteUser",
        "iam:CreateGroup", "iam:DeleteGroup",
        "iam:CreateAccessKey", "iam:DeleteAccessKey",
        "iam:CreateLoginProfile", "iam:DeleteLoginProfile", "iam:UpdateLoginProfile",
        "iam:AddUserToGroup", "iam:RemoveUserFromGroup",
        "iam:AttachUserPolicy", "iam:DetachUserPolicy",
        "iam:PutUserPolicy", "iam:DeleteUserPolicy",
        "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
        "iam:PutGroupPolicy", "iam:DeleteGroupPolicy",
        "iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice"
      ]
      Resource = "*"
    },
    {
      Sid    = "DenySelfEscalation"
      Effect = "Deny"
      Action = [
        "iam:AttachRolePolicy", "iam:DetachRolePolicy",
        "iam:PutRolePolicy", "iam:DeleteRolePolicy",
        "iam:UpdateAssumeRolePolicy", "iam:DeleteRole",
        "iam:TagRole", "iam:UntagRole",
        "iam:UpdateRole", "iam:UpdateRoleDescription",
        "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"
      ]
      Resource = [aws_iam_role.agent.arn]
    },
    {
      Sid      = "DenyOrganizationsAndAccount"
      Effect   = "Deny"
      Action   = ["organizations:*", "account:*"]
      Resource = "*"
    },
    {
      Sid    = "DenyRoleManagementOutsideAgentPath"
      Effect = "Deny"
      Action = [
        "iam:CreateRole", "iam:DeleteRole",
        "iam:PutRolePolicy", "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy", "iam:DetachRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
        "iam:TagRole", "iam:UntagRole",
        "iam:UpdateRole", "iam:UpdateRoleDescription"
      ]
      NotResource = [
        "arn:aws:iam::${var.account_id}:role${var.iam_path}*",
        "arn:aws:iam::${var.account_id}:role/aws-service-role/*"
      ]
    },
    {
      Sid      = "DenyCreateRoleWithoutBoundary"
      Effect   = "Deny"
      Action   = "iam:CreateRole"
      Resource = "arn:aws:iam::${var.account_id}:role${var.iam_path}*"
      Condition = {
        StringNotEquals = {
          "iam:PermissionsBoundary" = aws_iam_policy.permissions_boundary.arn
        }
      }
    },
    {
      Sid    = "DenyRemovingBoundary"
      Effect = "Deny"
      Action = [
        "iam:DeleteRolePermissionsBoundary",
        "iam:PutRolePermissionsBoundary"
      ]
      Resource = "arn:aws:iam::${var.account_id}:role${var.iam_path}*"
    },
    {
      Sid    = "DenyBoundaryPolicyModification"
      Effect = "Deny"
      Action = [
        "iam:DeletePolicy", "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"
      ]
      Resource = aws_iam_policy.permissions_boundary.arn
    },
    {
      Sid    = "DenyCloudTrailTampering"
      Effect = "Deny"
      Action = [
        "cloudtrail:CreateTrail", "cloudtrail:CreateEventDataStore",
        "cloudtrail:CreateChannel",
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors",
        "cloudtrail:PutResourcePolicy", "cloudtrail:DeleteResourcePolicy",
        "cloudtrail:DeleteEventDataStore", "cloudtrail:UpdateEventDataStore",
        "cloudtrail:DeleteChannel", "cloudtrail:UpdateChannel"
      ]
      Resource = "*"
    },
    {
      Sid    = "DenyAuditServiceTampering"
      Effect = "Deny"
      Action = [
        "config:DeleteConfigurationRecorder", "config:StopConfigurationRecorder",
        "config:PutConfigurationRecorder",
        "config:DeleteDeliveryChannel", "config:PutDeliveryChannel",
        "config:DeleteConfigRule",
        "config:DeleteConfigurationAggregator", "config:DeleteOrganizationConfigRule",
        "config:DeleteRetentionConfiguration", "config:DeleteRemediationConfiguration",
        "config:DeleteEvaluationResults",
        "guardduty:DeleteDetector", "guardduty:UpdateDetector",
        "guardduty:DisassociateFromMasterAccount", "guardduty:StopMonitoringMembers",
        "guardduty:DeletePublishingDestination", "guardduty:UpdatePublishingDestination",
        "guardduty:DisassociateMembers", "guardduty:DeleteMembers",
        "guardduty:UpdateMemberDetectors",
        "guardduty:CreateFilter", "guardduty:UpdateFilter", "guardduty:DeleteFilter",
        "securityhub:DisableSecurityHub", "securityhub:DisassociateFromMasterAccount",
        "securityhub:BatchDisableStandards", "securityhub:UpdateStandardsControl",
        "securityhub:DeleteInsight", "securityhub:UpdateInsight",
        "securityhub:BatchUpdateFindings"
      ]
      Resource = "*"
    }
  ]

  deny_trail_storage_statement = {
    Sid    = "DenyTrailStorageTampering"
    Effect = "Deny"
    Action = [
      "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy",
      "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketOwnershipControls",
      "s3:PutBucketNotification", "s3:PutBucketWebsite",
      "s3:PutBucketVersioning", "s3:PutBucketLogging",
      "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
      "s3:PutEncryptionConfiguration", "s3:PutBucketObjectLockConfiguration",
      "s3:DeleteObject", "s3:DeleteObjectVersion",
      "s3:PutObject",
      "s3:PutObjectAcl", "s3:PutObjectLegalHold",
      "s3:PutObjectRetention", "s3:BypassGovernanceRetention"
    ]
    Resource = [
      # coalesce() shields against null when the deny statement is
      # gated out by var.trail_bucket_name == null in concat() above.
      # Terraform evaluates this local eagerly, so a null var would
      # crash the whole plan even though the value is never used.
      # The sentinel "INVALID_UNUSED" uses uppercase + underscore (both
      # forbidden in real S3 bucket names) so the deploy would not
      # match any actual bucket. NOTE: IAM policy *syntax* validation
      # would still accept the resulting ARN — the safety here comes
      # from the concat() gate, not from the sentinel itself. The
      # sentinel is defense-in-depth: if the gate is ever dropped by
      # mistake, the resulting deny is a no-op rather than a deny
      # against an attacker-controlled bucket name.
      "arn:aws:s3:::${coalesce(var.trail_bucket_name, "INVALID_UNUSED")}",
      "arn:aws:s3:::${coalesce(var.trail_bucket_name, "INVALID_UNUSED")}/*"
    ]
  }

  deny_trail_kms_statement = {
    Sid    = "DenyTrailKmsTampering"
    Effect = "Deny"
    Action = [
      "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy",
      "kms:CreateGrant", "kms:RevokeGrant", "kms:CancelKeyDeletion",
      "kms:UpdateAlias", "kms:DeleteAlias",
      "kms:PutResourcePolicy", "kms:DeleteResourcePolicy",
      "kms:ImportKeyMaterial", "kms:DeleteImportedKeyMaterial"
    ]
    # See coalesce() comment on deny_trail_storage_statement.Resource
    # above for why the sentinel is needed. The sentinel is ARN-shaped
    # but uses an invalid region ("invalid") and all-zero account/key,
    # so it deploys cleanly if ever ungated but matches no real key.
    Resource = [coalesce(var.trail_kms_key_arn, "arn:aws:kms:invalid:000000000000:key/00000000-0000-0000-0000-000000000000")]
  }
}

# --- Instance Profile ---

resource "aws_iam_instance_profile" "agent" {
  name = "${var.agent_role_name}-profile"
  path = var.iam_path
  role = aws_iam_role.agent.name
  tags = var.tags
}
