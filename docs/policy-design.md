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

> **Canonical source:** [`policies/permissions-boundary.json`](../policies/permissions-boundary.json) (placeholders form) and `terraform/main.tf` `aws_iam_policy.permissions_boundary` (Terraform form).

| Sid | Effect | What it does |
|------|--------|--------------|
| AllowEverythingExceptDangerous | Allow | `NotAction: [iam:*, organizations:*, account:*]` on `Resource: *` — caps every role attached to the boundary at PowerUser-level |
| AllowPassRoleOnlyAgentRoles | Allow | `iam:PassRole` only to `role/IAM_PATH*` — boundary-attached roles can hand off only to agent-path roles |
| AllowReadOnlyIAM | Allow | Get/List role-policy basics for self-introspection |

### Guardrails That Enforce the Boundary

These statements in `LokiDenyGuardrails` ensure the boundary can't be bypassed:

> **Illustrative — see [`policies/deny-guardrails.json`](../policies/deny-guardrails.json) for the canonical form.** The snippet below uses concrete `loki/` / `LokiPermissionsBoundary` literals for readability; the canonical file uses `IAM_PATH` / `IAM_PATHLokiPermissionsBoundary` placeholders.

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

> **Canonical source:** [`policies/iam-scoped.json`](../policies/iam-scoped.json) (placeholders form) and `terraform/main.tf` `aws_iam_role_policy.iam_scoped` (Terraform form). Both must stay in sync; the table below is a Sid-level summary, not a full reproduction.

| Sid | Effect | Resource | Purpose |
|------|--------|----------|---------|
| AllowRoleManagementUnderAgentPath | Allow | `role/IAM_PATH*` | Create/manage roles only under the agent path |
| AllowPolicyManagementUnderAgentPath | Allow | `policy/IAM_PATH*` | Create/manage policies only under the agent path |
| AllowInstanceProfileManagementUnderAgentPath | Allow | `instance-profile/IAM_PATH*` | Same scope for instance profiles |
| AllowPassRoleOnlyAgentRoles | Allow | `role/IAM_PATH*` | `iam:PassRole` only to agent-created roles |
| AllowServiceLinkedRoles | Allow | `role/aws-service-role/*` | AWS services need to create their own SLRs |
| AllowIAMReadOnly | Allow | `*` | Read-only IAM (Get/List/Simulate) account-wide |

### Important Notes

- Replace `*` in the account position of ARNs with your actual AWS account ID for tighter scoping
- The `IAM_PATH` (e.g. `/loki/` for Terraform, `loki/` for JSON substitution — see README) means all Terraform-created roles must use `path = var.iam_path` in their config
- `PassRole` is restricted to agent-path roles only — the agent can't assign roles it didn't create
- Service-linked roles are allowed because AWS services create these automatically

---

## Policy 2: LokiDenyGuardrails

Explicit denies that prevent privilege escalation and dangerous actions.
**Deny always wins over Allow** — these can't be bypassed even with PowerUserAccess.

> **Two equivalent representations.** This policy is shipped in two forms:
>
> - [`policies/deny-guardrails.json`](../policies/deny-guardrails.json) — raw IAM policy document with literal
>   placeholders (`ACCOUNT_ID`, `IAM_PATH`, `AGENT_ROLE_NAME`, etc.).
>   Used by the AWS-CLI `Quick Start` flow in the README.
> - `terraform/main.tf` `aws_iam_role_policy.deny_guardrails` — same
>   policy expressed via `jsonencode()` over a list of statement objects.
>   Used by the `terraform/` module flow.
>
> The two **must stay in sync** — enforced by the per-Sid Action-set parity
> check in `.github/workflows/lint.yml`. The Terraform form is canonical for
> ARN composition (uses `aws_iam_role.agent.arn` directly, no path footgun)
> and gates the trail-storage / trail-KMS statements behind input variables
> with validation. The JSON form is canonical for documentation, review,
> and copy/paste auditing. When changing one, change both; CI fails the PR
> otherwise.

The table below is a Sid-level summary; consult the canonical files for the full action lists.

| Sid | Resource scope | Purpose |
|------|----------------|---------|
| DenyIdentityManagement | `*` | No new IAM users, access keys, login profiles, MFA devices |
| DenySelfEscalation | `role/IAM_PATHAGENT_ROLE_NAME` (JSON) / `aws_iam_role.agent.arn` (TF) | Agent cannot mutate its own role (policies, trust, tags, description, boundary) |
| DenyOrganizationsAndAccount | `*` | No `organizations:*` / `account:*` |
| DenyRoleManagementOutsideAgentPath | `NotResource: [role/IAM_PATH*, role/aws-service-role/*]` | Role mutation only inside agent path |
| DenyCreateRoleWithoutBoundary | `role/IAM_PATH*` | New roles must attach the permissions boundary |
| DenyRemovingBoundary | `role/IAM_PATH*` | Cannot remove boundary from agent-path roles |
| DenyBoundaryPolicyModification | `policy/IAM_PATHLokiPermissionsBoundary` | Cannot mutate the boundary policy itself |
| DenyCloudTrailTampering | `*` | Cannot stop/delete/update trails, event-data-stores, channels, selectors, resource policies |
| DenyAuditServiceTampering | `*` | Cannot disable Config/GuardDuty/SecurityHub recorders, members, filters, finding triage |
| DenyTrailStorageTampering | trail S3 bucket | Cannot delete/policy-modify/notify-redirect/object-overwrite the trail bucket |
| DenyTrailKmsTampering | trail KMS CMK | Cannot delete/disable/grant-modify/import-material the trail's CMK |

### Guardrail Explanations

| Rule | Why |
|------|-----|
| DenyIdentityManagement | Agent can't create users, access keys, or login profiles — no new identities |
| DenySelfEscalation | Agent can't modify its own role or instance profile — no privilege escalation. The JSON template builds the role ARN as `role/IAM_PATHAGENT_ROLE_NAME` so the deny works whether the agent role lives at the root or under a path — substitute `IAM_PATH` (e.g. `loki/`) and `AGENT_ROLE_NAME` (e.g. `loki-agent-role`) independently. The Terraform module avoids the placeholder entirely by referencing `aws_iam_role.agent.arn`. |
| DenyOrganizationsAndAccount | Agent can't manage the AWS Organization or account settings |
| DenyRoleManagementOutsideAgentPath | Agent can't touch ANY role outside the agent path — protects admin roles, service roles, etc. |

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

The authoritative setup flow lives in the [main README's Quick Start](../README.md#quick-start). It includes the substitution helper that resolves placeholders in `policies/*.json` to runnable IAM policy documents under `out/*.json`, then runs `aws iam create-policy` / `create-role` / `put-role-policy` / `create-instance-profile` against the resolved files. Don't duplicate that flow here — single source of truth.

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
4. **Audit trail integrity** — all IAM actions logged in CloudTrail.
   The agent is explicitly denied:
   - CloudTrail tampering: `StopLogging`, `DeleteTrail`, `UpdateTrail`,
     `PutEventSelectors`, `PutInsightSelectors`, event-data-store mutation
   - Config / GuardDuty / SecurityHub recorder tampering (delete, stop,
     overwrite, or disable individual standards/controls)
   - Trail S3 bucket tampering: delete, policy/ACL change, object
     deletion, lifecycle/versioning rewrite, governance-retention bypass
   - Trail KMS key tampering: schedule-deletion, disable, key-policy
     rewrite, grant create/revoke

   The S3 bucket and KMS key denies are scoped to specific ARNs
   (placeholders `TRAIL_BUCKET_NAME` and `TRAIL_KMS_KEY_ARN` in the
   template) so they do not block the agent from working with other
   buckets/keys.

   **Trade-offs and caveats:**

   - *CloudTrail denies use `Resource: "*"`.* Most CloudTrail actions
     support trail-ARN scoping, but we deny on `*` so the agent cannot
     stand up a competing/parallel trail and then disable it. To make
     that rationale airtight, the deny also covers `cloudtrail:CreateTrail`,
     `CreateEventDataStore`, and `CreateChannel` — the agent cannot
     create new audit infrastructure at all. The side effect is that
     trail provisioning is an admin/Terraform task, not an agent task.
     Adjust if your operating model differs.

   - *KMS grant denies (`CreateGrant` / `RevokeGrant`) cover the
     direct path only.* They prevent the agent from issuing or
     revoking grants on the trail's CMK. They do **not** affect
     service-linked grants created by AWS services on the agent's
     behalf (those use `kms:GrantIsForAWSResource`). For the threat
     model here (agent blinding its own audit) this is sufficient;
     if you also want to prevent service-mediated grant churn, add
     a condition `"Bool": {"kms:GrantIsForAWSResource": "false"}`.

   - *Placeholders must be substituted before deployment.* A
     literal `TRAIL_BUCKET_NAME` or `TRAIL_KMS_KEY_ID` left in the
     policy is syntactically valid but matches nothing — a silent
     no-op. If the trail is unencrypted or absent entirely, delete
     the corresponding statement rather than supplying a fake ARN.
     A pre-deploy lint (`grep -E 'KMS_REGION|TRAIL_(BUCKET_NAME|KMS_KEY_ID)'
     policies/*.json`) should return nothing. The KMS resource is
     split into `KMS_REGION:ACCOUNT_ID:key/TRAIL_KMS_KEY_ID` rather
     than a single `TRAIL_KMS_KEY_ARN` placeholder so partial
     substitution still produces an ARN-shaped string — partial
     fills fail loudly instead of deploying a dead deny.

   - *Day-2 ops on the trail bucket and CMK are blocked for the agent.*
     `s3:PutBucketPolicy`, `PutEncryptionConfiguration`, `PutBucketVersioning`,
     `kms:PutKeyPolicy`, `ScheduleKeyDeletion`, `CreateGrant`, etc.
     are all denied. The trail bucket and KMS key **must be managed
     outside this agent's Terraform state** — use a separate state
     file with a separate (admin) role, or treat the audit trail as
     unmanaged infra. Otherwise routine maintenance (KMS key rotation,
     bucket policy update for a new principal, lifecycle-rule change)
     will silently fail with no remediation path until the deny is
     lifted manually. Recommended layout: a dedicated `audit-trail/`
     module owned by the platform/security team, run with an admin
     role; this `loki-permissions` module references its outputs but
     never writes to the bucket/key.

   - *Config / GuardDuty / SecurityHub initial setup is also blocked
     for the agent.* `DenyAuditServiceTampering` covers
     `config:PutConfigurationRecorder` and `config:PutDeliveryChannel`
     (so the agent cannot overwrite an existing recorder to point at
     a black-hole bucket). The side effect is that *first-time setup*
     of these services must also be done outside the agent's Terraform
     state — same separation-of-duties pattern as the trail bucket/CMK.
     If the agent attempts to enable Config / GuardDuty / SecurityHub
     for the first time, the apply fails on these actions; the fix is
     to bootstrap them via an admin role and have the agent reference
     the resulting infrastructure read-only.

   - *Cross-partition templates.* The JSON and Terraform templates hardcode
     `aws` partition (commercial region ARNs). GovCloud (`aws-us-gov`) and
     China (`aws-cn`) deployments would require manual partition substitution
     throughout all 4 JSON files + Terraform module. **Partition support is
     planned as a future enhancement** to thread a `var.aws_partition` parameter
     and systematically replace all `arn:aws:` with `arn:${aws_partition}:`.
     This is a separate scope from the current audit-trail deny set; users
     deploying to non-commercial regions should use this template as a
     reference and manually update partitions.

   - *Residual gaps (not currently denied, intentional):* the agent
     can still call `cloudtrail:GetTrail` / `LookupEvents` /
     `DescribeTrails` for legitimate debugging, and can still create
     **new** S3 buckets / KMS keys unrelated to the audit trail. The
     deny statements above are surgically targeted at the audit
     infrastructure; they do not impose a blanket S3/KMS read-only
     posture, which would break the agent's day job.

   - *Triage actions denied (intentional, broad).* `DenyAuditServiceTampering`
     denies `securityhub:BatchUpdateFindings` and `guardduty:CreateFilter`/
     `UpdateFilter`/`DeleteFilter` with `Resource: "*"`. These actions can
     legitimately be used for triage (mark findings RESOLVED, suppress noise
     via filter), but the same actions can also be used to silence findings
     about the agent's own activity. We deny broadly because triage is a
     human/SOC task, not an agent task. If your operating model needs the
     agent to do triage, scope these by `securityhub:ASFFSyntaxPath` /
     `guardduty:DetectorId` conditions or move them out of the deny set.
5. **Reversible** — admin can delete `/loki/*` roles to revoke all agent-created permissions
6. **Human retains control** — admin role and instance profile are protected by explicit deny

---

*This is a template. Customize paths, account IDs, and role names for your environment.*
