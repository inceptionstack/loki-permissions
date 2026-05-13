# loki-permissions

Scoped IAM policies for AI DevOps agents running on AWS EC2.

**Drop-in replacement for `AdministratorAccess`** — gives the agent enough permissions to build infrastructure via Terraform while preventing privilege escalation.

## What Is This For?

This policy set is designed for **autonomous AI coding/DevOps agents** (e.g., [OpenClaw](https://github.com/openclaw/openclaw), Claude Code, Codex) that run on an EC2 instance and manage AWS infrastructure on behalf of a human operator.

### The Agent Runtime Environment

```
┌─────────────────────────────────────────────────┐
│  VPC (private)                                  │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │  Private Subnet (no public IP)            │  │
│  │                                           │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │  EC2 Instance (Graviton/ARM64)      │  │  │
│  │  │                                     │  │  │
│  │  │  • AI Agent process (Node.js)       │  │  │
│  │  │  • Terraform CLI                    │  │  │
│  │  │  • AWS CLI                          │  │  │
│  │  │  • Git (CodeCommit / GitHub)        │  │  │
│  │  │  • Docker (for inspecting images)   │  │  │
│  │  │                                     │  │  │
│  │  │  Auth: EC2 Instance Profile (IMDSv2)│  │  │
│  │  └─────────────────────────────────────┘  │  │
│  │                                           │  │
│  └───────────┬───────────────────────────────┘  │
│              │                                  │
│         NAT Gateway (outbound only)             │
│                                                 │
│  Ingress: NONE (no SSH, no public ports)        │
│  Egress: HTTPS only (AWS APIs, Git, npm/pip)    │
│  Agent access: via messaging integration only   │
│  (Telegram, Discord, Slack — not SSH)           │
│                                                 │
└─────────────────────────────────────────────────┘
```

### Key Security Context

- **No inbound access.** The EC2 instance has no public IP, no SSH, no open ports. The agent communicates with its human operator through a messaging platform (Telegram, Discord, etc.), not through direct network access.
- **Outbound only.** NAT Gateway allows HTTPS egress for AWS API calls, git operations, and package managers. No arbitrary outbound connections.
- **IMDSv2 only.** Instance metadata service requires session tokens (hop limit ≥2 for containers). No IMDSv1 fallback.
- **No Docker builds on the instance.** Container images are built exclusively through CodePipeline/CodeBuild. The agent triggers pipelines, not local Docker builds.
- **Single-tenant.** One agent per instance. The agent operates on behalf of one human operator.
- **Workspace isolation.** The agent's working directory is its only persistent storage. All infrastructure is managed through Terraform (state in S3) and CI/CD pipelines.

### What the Agent Does

The agent acts as an autonomous DevOps engineer. It:
- Creates and manages AWS infrastructure via Terraform (VPCs, Lambda, ECS, S3, DynamoDB, API Gateway, CloudFront, etc.)
- Writes application code and pushes to CodeCommit/GitHub
- Triggers and monitors CI/CD pipelines (CodePipeline + CodeBuild)
- Creates IAM execution roles for the services it deploys (Lambda roles, ECS task roles, pipeline roles)
- Debugs production issues using CloudWatch Logs, CloudTrail, and other observability tools
- Manages Cognito user pools, Secrets Manager, and other application-level AWS services

### Why It Needs IAM Permissions

Every Terraform project creates IAM roles — Lambda execution roles, ECS task roles, CodeBuild service roles, CodePipeline service roles, VPC Flow Log roles, etc. Without IAM permissions, `terraform apply` fails on every project.

`PowerUserAccess` alone blocks all IAM write operations. This policy set adds **scoped IAM** — the agent can create roles and policies, but only under a designated path (`/loki/`), and every role it creates is capped by a permissions boundary.

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Agent creates admin role and assumes it | Permissions boundary caps all created roles at PowerUser-level (no IAM access) |
| Agent creates IAM user with access keys | Explicit deny on all identity management actions |
| Agent modifies its own role to add permissions | Explicit deny on self-modification |
| Agent removes the permissions boundary from a role | Explicit deny on boundary removal/modification |
| Agent modifies the boundary policy itself | Explicit deny on boundary policy version changes |
| Agent creates roles outside its namespace | Explicit deny on role operations outside `/loki/*` |
| Agent accesses Organization or Account settings | Explicit deny on `organizations:*` and `account:*` |
| Compromised agent persists access after remediation | Admin deletes all `/loki/*` roles — clean sweep, no hidden roles elsewhere |

## The Problem

AI agents that manage AWS infrastructure need broad permissions. But giving them `AdministratorAccess` is dangerous:
- Agent could create IAM users/access keys (persistent backdoor)
- Agent could modify its own role (privilege escalation)
- Agent could create high-privilege roles and assume them
- No blast radius containment

## The Solution

Three policies that work together:

| Policy | Purpose |
|--------|---------|
| `LokiIAMScoped` | Allows IAM role/policy management **only** under a designated path (`/loki/`) |
| `LokiDenyGuardrails` | Explicit denies that prevent escalation, even if other policies allow it |
| `LokiPermissionsBoundary` | Caps the maximum permissions of any role the agent creates |

Combined with `PowerUserAccess` (AWS managed), this gives the agent full service access + scoped IAM — without any escalation path.

## Security Properties

- ✅ Agent can create IAM roles for Lambda, ECS, CodeBuild, etc. (Terraform works)
- ✅ All created roles are capped at PowerUser-level via permissions boundary
- ❌ Agent cannot create IAM users, groups, or access keys
- ❌ Agent cannot modify its own role or instance profile
- ❌ Agent cannot create roles outside the `/loki/` path
- ❌ Agent cannot remove or modify the permissions boundary
- ❌ Agent cannot access Organizations or Account settings

## Quick Start

> ⚠️ **Step 0 first.** The `policies/*.json` files contain literal placeholders
> (`ACCOUNT_ID`, `IAM_PATH`, `TRAIL_BUCKET_NAME`, etc.). Handing raw template files
> to `aws iam create-policy` fails with `MalformedPolicyDocument`. Run the
> substitution helper from the [Customization](#customization) section below
> first; it produces resolved `out/*.json` files. The commands below consume
> `out/*.json`, not `policies/*.json`.

```bash
# 0. Resolve placeholders → out/*.json (see "Customization" section for the helper)
#    After running it, you should have: out/permissions-boundary.json, out/iam-scoped.json,
#    out/deny-guardrails.json, out/trust-policy.json

# 1. Create the permissions boundary (admin does this)
aws iam create-policy \
  --policy-name LokiPermissionsBoundary \
  --path "/loki/" \
  --policy-document file://out/permissions-boundary.json

# 2. Create the agent role
aws iam create-role \
  --role-name loki-agent-role \
  --path "/loki/" \
  --assume-role-policy-document file://out/trust-policy.json

# 3. Attach all policies
aws iam attach-role-policy --role-name loki-agent-role \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiIAMScoped \
  --policy-document file://out/iam-scoped.json
aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiDenyGuardrails \
  --policy-document file://out/deny-guardrails.json

# 4. Create instance profile and attach to EC2
aws iam create-instance-profile \
  --instance-profile-name loki-agent-profile \
  --path "/loki/"
aws iam add-role-to-instance-profile \
  --instance-profile-name loki-agent-profile \
  --role-name loki-agent-role
aws ec2 associate-iam-instance-profile \
  --instance-id <YOUR_INSTANCE_ID> \
  --iam-instance-profile Name=loki-agent-profile
```

See [docs/](docs/) for detailed policy architecture and Terraform integration notes.

### Terraform

```hcl
module "loki_permissions" {
  source = "github.com/inceptionstack/loki-permissions//terraform"

  account_id      = "123456789012"
  agent_role_name = "loki-agent-role"

  # Optional: scoped denies on the audit-trail S3 bucket and KMS key.
  # Leave null if you have no CloudTrail or it's unencrypted.
  # IMPORTANT: these resources must be managed outside this state.
  trail_bucket_name = "my-org-cloudtrail-logs"
  trail_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abcd1234-..."
}
```

The `trail_kms_key_arn` variable has plan-time validation — partial values (key UUIDs, alias ARNs) are rejected. If your trail is unencrypted, leave it `null` and the `DenyTrailKmsTampering` statement is omitted entirely (preferred over deploying a dead deny).

## Repository Structure

```
├── policies/                    # Raw IAM policy JSON files
│   ├── iam-scoped.json         # Scoped IAM permissions
│   ├── deny-guardrails.json    # Explicit deny guardrails
│   ├── permissions-boundary.json# Max permissions ceiling
│   └── trust-policy.json       # EC2 assume role trust
├── terraform/                   # Terraform module
│   ├── main.tf                 # Agent role + policies
│   ├── variables.tf            # Configurable inputs
│   ├── outputs.tf              # ARNs and names
│   └── examples/               # Standalone consumer examples (NOT part of module)
│       ├── README.md
│       └── downstream-consumer.tf
├── docs/
│   └── policy-design.md        # Full policy architecture docs
├── .github/workflows/
│   └── lint.yml                # JSON parse, sub round-trip, TF validate, JSON↔TF parity
└── README.md
```

## Customization

Before deploying, update these values in the policy files:

| Placeholder | Description | Example |
|------------|-------------|---------|
| `ACCOUNT_ID` | Your AWS account ID | `123456789012` |
| `AGENT_ROLE_NAME` | Bare name of the agent's IAM role (no path). The path is supplied separately via `IAM_PATH`. Used by `DenySelfEscalation` together with `IAM_PATH` to build the role ARN. | `loki-agent-role` |
| `IAM_PATH` | Path prefix for agent-created roles. **Substitute with NO leading slash** (e.g. `loki/`) so it composes correctly into ARNs as `role/loki/...`. The Terraform variable accepts the conventional leading-slash form (`/loki/`) and handles ARN composition itself. | `loki/` (in JSON) <br> `/loki/` (Terraform var) |
| `TRAIL_BUCKET_NAME` | S3 bucket holding CloudTrail logs (used by `DenyTrailStorageTampering`) | `my-org-cloudtrail-logs` |
| `KMS_REGION` | Region of the trail's KMS CMK (used by `DenyTrailKmsTampering`) | `us-east-1` |
| `TRAIL_KMS_KEY_ID` | UUID of the trail's KMS CMK (used by `DenyTrailKmsTampering`) | `abcd1234-...` |

> ⚠️ **Both `TRAIL_*` placeholders must be replaced with real values before deployment.** A leftover literal placeholder will deploy a syntactically valid statement that matches no resource — silent no-op. If your trail is **unencrypted**, delete the entire `DenyTrailKmsTampering` statement rather than supplying a fake KMS ARN. Likewise, if you have no CloudTrail at all, delete `DenyTrailStorageTampering` and `DenyTrailKmsTampering`.
>
> **Pre-deploy lint** (run after substitution, before `aws iam put-role-policy`):
>
> ```bash
> # 1. No literal placeholders should remain
> ! grep -E 'ACCOUNT_ID|AGENT_ROLE_NAME|IAM_PATH|KMS_REGION|TRAIL_(BUCKET_NAME|KMS_KEY_ID)' out/*.json
>
> # 2. No double-slash ARNs (catches IAM_PATH substituted with leading slash)
> ! grep -E 'role//|policy//|instance-profile//' out/*.json
>
> # 3. Strict JSON parse on the substituted output (templates are checked by CI)
> for f in out/*.json; do python3 -c "import json; json.load(open('$f'))" || echo "BROKEN: $f"; done
> ```
>
> **Substitution helper** (avoids ordering footguns when tokens share substrings, e.g. `IAM_PATH` is a prefix of `IAM_PATHAGENT_ROLE_NAME`):
>
> ```bash
> # Edit these for your environment
> ACCOUNT_ID="123456789012"
> AGENT_ROLE_NAME="loki-agent-role"
> IAM_PATH="loki/"                # NO leading slash for JSON substitution
> TRAIL_BUCKET_NAME="my-org-cloudtrail-logs"
> KMS_REGION="us-east-1"
> TRAIL_KMS_KEY_ID="abcd1234-abcd-1234-abcd-123456789012"
>
> # Substitute longest tokens first — prevents IAM_PATH matching inside IAM_PATHAGENT_ROLE_NAME.
> # PARALLEL to `.github/workflows/lint.yml` substitution step but NOT identical:
> # this README hardcodes "LokiPermissionsBoundary" while CI uses ${BOUNDARY_POLICY_NAME}.
> # The two paths are equivalent for the default boundary name; if the boundary is
> # renamed in Terraform, this CLI flow does not pick it up. (Extract to
> # scripts/substitute.sh if drift becomes a problem in practice.)
> #
> # NOTE: The JSON template (this CLI flow) hardcodes the boundary name
> # "LokiPermissionsBoundary". To use a different boundary name, either
> # (a) deploy via the Terraform module which parameterizes it as
> # var.boundary_policy_name, or (b) edit the literal in policies/*.json
> # before running this helper.
> mkdir -p out
> for f in policies/*.json; do
>   sed \
>     -e "s|IAM_PATHAGENT_ROLE_NAME|${IAM_PATH}${AGENT_ROLE_NAME}|g" \
>     -e "s|IAM_PATHLokiPermissionsBoundary|${IAM_PATH}LokiPermissionsBoundary|g" \
>     -e "s|IAM_PATH|${IAM_PATH}|g" \
>     -e "s|ACCOUNT_ID|${ACCOUNT_ID}|g" \
>     -e "s|TRAIL_BUCKET_NAME|${TRAIL_BUCKET_NAME}|g" \
>     -e "s|KMS_REGION|${KMS_REGION}|g" \
>     -e "s|TRAIL_KMS_KEY_ID|${TRAIL_KMS_KEY_ID}|g" \
>     "$f" > "out/$(basename "$f")"
> done
>
> # Then run the lint above against out/*.json
> ```
>
> The KMS resource is split into `KMS_REGION:ACCOUNT_ID:key/TRAIL_KMS_KEY_ID` rather than a single `TRAIL_KMS_KEY_ARN` placeholder so partial substitution still produces an ARN-shaped string — a common mistake (pasting only the key UUID) at least fails loudly instead of deploying a dead deny.
>
> **Day-2 ops warning:** `DenyTrailStorageTampering` blocks `s3:PutBucketPolicy`, `PutEncryptionConfiguration`, `PutBucketVersioning`, etc. on the trail bucket; `DenyTrailKmsTampering` blocks `kms:PutKeyPolicy`, `ScheduleKeyDeletion`, etc. on the trail's CMK. The trail bucket and KMS key **must be managed outside this agent's Terraform state** (separate state file, separate role, or admin-only). Otherwise day-2 maintenance — KMS key rotation, bucket policy update for new accounts, lifecycle-rule changes — will silently fail with no remediation path until the deny is lifted manually. Recommended layout: a dedicated `audit-trail/` Terraform module owned by the platform/security team, run with an admin role; this `loki-permissions` module references its outputs but never writes to the bucket/key.
>
> **Terraform users:** if you deploy via the `terraform/` module, set `trail_bucket_name` and `trail_kms_key_arn` (full ARN) variables — the module variable validation rejects partial ARNs at plan-time. Leave them `null` to skip the trail-storage and trail-KMS statements entirely.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

SPDX-License-Identifier: Apache-2.0
