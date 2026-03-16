# Loki Policy Template — Scoped IAM for AI Agents

> Template for creating a least-privilege IAM policy for an AI DevOps agent running on EC2.
> Replaces `YourCurrentAdminRole` with `PowerUserAccess` + scoped IAM permissions.
> Last updated: 2026-03-16

---

## Overview

AI agents need broad AWS access to build infrastructure, but should NOT have:
- Full IAM admin (can't create users, access keys, or modify their own role)
- Organization management
- Account-level settings
- Ability to escalate their own privileges

**Solution:** `PowerUserAccess` (AWS managed) + `LokiIAMScoped` (custom) + guardrails.

---

## Architecture

```
EC2 Instance Profile
  └── IAM Role: loki-agent-role
        ├── PowerUserAccess (AWS managed)      ← all services except IAM/Org
        ├── LokiIAMScoped (custom)             ← scoped IAM for Terraform
        ├── LokiDenyGuardrails (custom)        ← explicit denies for safety
        └── LokiPermissionsBoundary (custom)   ← caps max perms on created roles
```

### Anti-Escalation: Permissions Boundary

**Problem:** Even with `/loki/` path restrictions, the agent could create a role with `AdministratorAccess` or `iam:*`, assume it, and escalate privileges.

**Solution:** A **permissions boundary** that caps the maximum permissions any `/loki/` role can have. The guardrails enforce that:
1. Every `CreateRole` under `/loki/` **must** include the boundary (denied otherwise)
2. The agent **cannot remove** the boundary from existing roles
3. The agent **cannot modify** the boundary policy itself

The boundary allows all services EXCEPT `iam:*`, `organizations:*`, and `account:*`. This means even if a role has `AdministratorAccess` attached, the effective permissions are capped at PowerUser-level.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEverythingExceptDangerous",
      "Effect": "Allow",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "account:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowPassRoleOnlyLoki",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/loki/*"
    },
    {
      "Sid": "AllowReadOnlyIAM",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

### Guardrails That Enforce the Boundary

These statements in `LokiDenyGuardrails` ensure the boundary can't be bypassed:

```json
{
  "Sid": "DenyCreateRoleWithoutBoundary",
  "Effect": "Deny",
  "Action": "iam:CreateRole",
  "Resource": "arn:aws:iam::*:role/loki/*",
  "Condition": {
    "StringNotEquals": {
      "iam:PermissionsBoundary": "arn:aws:iam::*:policy/loki/LokiPermissionsBoundary"
    }
  }
},
{
  "Sid": "DenyRemovingBoundary",
  "Effect": "Deny",
  "Action": [
    "iam:DeleteRolePermissionsBoundary",
    "iam:PutRolePermissionsBoundary"
  ],
  "Resource": "arn:aws:iam::*:role/loki/*"
},
{
  "Sid": "DenyBoundaryPolicyModification",
  "Effect": "Deny",
  "Action": [
    "iam:DeletePolicy",
    "iam:CreatePolicyVersion",
    "iam:DeletePolicyVersion",
    "iam:SetDefaultPolicyVersion"
  ],
  "Resource": "arn:aws:iam::*:policy/loki/LokiPermissionsBoundary"
}
```

---

## Policy 1: LokiIAMScoped

Allows the agent to create/manage IAM roles and policies **only under the `/loki/` path**.
This lets Terraform create execution roles for Lambda, ECS, CodeBuild, CodePipeline, etc.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRoleManagementUnderLokiPath",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListInstanceProfilesForRole",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:ListRoleTags",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "arn:aws:iam::*:role/loki/*"
    },
    {
      "Sid": "AllowPolicyManagementUnderLokiPath",
      "Effect": "Allow",
      "Action": [
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicyVersions",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:TagPolicy",
        "iam:UntagPolicy"
      ],
      "Resource": "arn:aws:iam::*:policy/loki/*"
    },
    {
      "Sid": "AllowInstanceProfileManagementUnderLokiPath",
      "Effect": "Allow",
      "Action": [
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:TagInstanceProfile"
      ],
      "Resource": "arn:aws:iam::*:instance-profile/loki/*"
    },
    {
      "Sid": "AllowPassRoleOnlyLokiRoles",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/loki/*"
    },
    {
      "Sid": "AllowServiceLinkedRoles",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole",
        "iam:DeleteServiceLinkedRole",
        "iam:GetServiceLinkedRoleDeletionStatus"
      ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/*"
    },
    {
      "Sid": "AllowIAMReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListInstanceProfiles",
        "iam:GetAccountSummary",
        "iam:GetAccountAuthorizationDetails",
        "iam:SimulatePrincipalPolicy",
        "iam:ListOpenIDConnectProviders",
        "iam:ListSAMLProviders"
      ],
      "Resource": "*"
    }
  ]
}
```

### Important Notes

- Replace `*` in the account position of ARNs with your actual AWS account ID for tighter scoping
- The `/loki/` path means all Terraform-created roles must use `path = "/loki/"` in their config
- `PassRole` is restricted to `/loki/*` roles only — the agent can't assign roles it didn't create
- Service-linked roles are allowed because AWS services create these automatically

---

## Policy 2: LokiDenyGuardrails

Explicit denies that prevent privilege escalation and dangerous actions.
**Deny always wins over Allow** — these can't be bypassed even with PowerUserAccess.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIdentityManagement",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateGroup",
        "iam:DeleteGroup",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:CreateLoginProfile",
        "iam:DeleteLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:PutUserPolicy",
        "iam:DeleteUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:DetachGroupPolicy",
        "iam:PutGroupPolicy",
        "iam:DeleteGroupPolicy",
        "iam:DeactivateMFADevice",
        "iam:DeleteVirtualMFADevice"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenySelfEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:DeleteRole"
      ],
      "Resource": [
        "arn:aws:iam::*:role/YourCurrentAdminRole",
        "arn:aws:iam::*:role/loki-agent-role",
        "arn:aws:iam::*:instance-profile/your-agent-profile"
      ],
      "Condition": {}
    },
    {
      "Sid": "DenyOrganizationsAndAccount",
      "Effect": "Deny",
      "Action": [
        "organizations:*",
        "account:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyRoleManagementOutsideLokiPath",
      "Effect": "Deny",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:UpdateAssumeRolePolicy"
      ],
      "NotResource": [
        "arn:aws:iam::*:role/loki/*",
        "arn:aws:iam::*:role/aws-service-role/*"
      ]
    }
  ]
}
```

### Guardrail Explanations

| Rule | Why |
|------|-----|
| DenyIdentityManagement | Agent can't create users, access keys, or login profiles — no new identities |
| DenySelfEscalation | Agent can't modify its own role or instance profile — no privilege escalation |
| DenyOrganizationsAndAccount | Agent can't manage the AWS Organization or account settings |
| DenyRoleManagementOutsideLokiPath | Agent can't touch ANY role outside `/loki/*` — protects admin roles, service roles, etc. |

---

## Terraform Integration

All Terraform IAM resources must use `path = "/loki/"`:

```hcl
# Before (YourCurrentAdminRole era)
resource "aws_iam_role" "lambda_execution" {
  name = "my-app-lambda-role"
  # ... assume_role_policy
}

# After (LokiIAMScoped era)
resource "aws_iam_role" "lambda_execution" {
  name = "my-app-lambda-role"
  path = "/loki/"                    # ← Required!
  # ... assume_role_policy
}

# Same for policies
resource "aws_iam_policy" "custom" {
  name = "my-app-custom-policy"
  path = "/loki/"                    # ← Required!
  # ... policy document
}
```

**Update `new-project-template.md`** to include `/loki/` path as a hard requirement for all IAM resources.

---

## Instance Profile Setup

```bash
# 1. Create the agent role (do this as the human admin, NOT the agent)
aws iam create-role \
  --role-name loki-agent-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# 2. Attach policies
aws iam attach-role-policy --role-name loki-agent-role \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiIAMScoped \
  --policy-document file://loki-iam-scoped.json

aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiDenyGuardrails \
  --policy-document file://loki-deny-guardrails.json

# 3. Create instance profile and attach
aws iam create-instance-profile --instance-profile-name your-agent-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name your-agent-profile \
  --role-name loki-agent-role

# 4. Associate with EC2 instance
aws ec2 associate-iam-instance-profile \
  --instance-id i-XXXXXXXXX \
  --iam-instance-profile Name=your-agent-profile
```

---

## Verification Checklist

After setup, verify the agent:
- [ ] ✅ Can create S3 buckets, Lambda functions, ECS services (PowerUser)
- [ ] ✅ Can `terraform apply` and create IAM roles under `/loki/`
- [ ] ✅ Can `iam:PassRole` for `/loki/*` roles to Lambda/ECS/etc.
- [ ] ❌ Cannot create IAM users or access keys
- [ ] ❌ Cannot modify its own role (`loki-agent-role`)
- [ ] ❌ Cannot modify/delete roles outside `/loki/*`
- [ ] ❌ Cannot access Organizations or Account settings
- [ ] ❌ Cannot create instance profiles outside `/loki/*`

```bash
# Test: should SUCCEED
aws iam create-role --role-name test-verify --path /loki/ \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam delete-role --role-name test-verify

# Test: should FAIL (AccessDenied)
aws iam create-user --user-name test-should-fail
aws iam create-role --role-name test-outside-path \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
```

---

## Security Properties

1. **No privilege escalation** — agent can't modify its own permissions
2. **No lateral movement** — agent can't create users/keys to persist access
3. **Blast radius limited** — agent can only create/modify roles under `/loki/`
4. **Audit trail** — all IAM actions logged in CloudTrail
5. **Reversible** — admin can delete `/loki/*` roles to revoke all agent-created permissions
6. **Human retains control** — admin role and instance profile are protected by explicit deny

---

*This is a template. Customize paths, account IDs, and role names for your environment.*
