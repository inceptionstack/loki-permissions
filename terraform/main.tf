locals {
  boundary_arn = "arn:aws:iam::${var.account_id}:policy${var.iam_path}${var.boundary_policy_name}"
  role_path    = var.iam_path
}

# --- Permissions Boundary ---
# Caps the maximum permissions of any role the agent creates.
# Even if the agent attaches AdministratorAccess, effective perms are limited.

resource "aws_iam_policy" "permissions_boundary" {
  name        = var.boundary_policy_name
  path        = var.iam_path
  description = "Permissions boundary for AI agent-created roles. Blocks IAM/Orgs/Account."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEverythingExceptDangerous"
        Effect   = "Allow"
        NotAction = ["iam:*", "organizations:*", "account:*"]
        Resource = "*"
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
  })

  tags = var.tags
}

# --- Agent Role ---

resource "aws_iam_role" "agent" {
  name = var.agent_role_name

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
    Version = "2012-10-17"
    Statement = [
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
        Sid    = "AllowInstanceProfileManagement"
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
  })
}

# Deny guardrails — explicit denies that can't be overridden
resource "aws_iam_role_policy" "deny_guardrails" {
  name = "LokiDenyGuardrails"
  role = aws_iam_role.agent.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
          "iam:UpdateAssumeRolePolicy", "iam:DeleteRole"
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
          "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"
        ]
        NotResource = [
          "arn:aws:iam::${var.account_id}:role${var.iam_path}*",
          "arn:aws:iam::${var.account_id}:role/aws-service-role/*"
        ]
      },
      {
        Sid       = "DenyCreateRoleWithoutBoundary"
        Effect    = "Deny"
        Action    = "iam:CreateRole"
        Resource  = "arn:aws:iam::${var.account_id}:role${var.iam_path}*"
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
      }
    ]
  })
}

# --- Instance Profile ---

resource "aws_iam_instance_profile" "agent" {
  name = "${var.agent_role_name}-profile"
  role = aws_iam_role.agent.name
  tags = var.tags
}
