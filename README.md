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

```bash
# 1. Create the permissions boundary (admin does this)
aws iam create-policy \
  --policy-name LokiPermissionsBoundary \
  --path "/loki/" \
  --policy-document file://policies/permissions-boundary.json

# 2. Create the agent role
aws iam create-role \
  --role-name loki-agent-role \
  --assume-role-policy-document file://policies/trust-policy.json

# 3. Attach all policies
aws iam attach-role-policy --role-name loki-agent-role \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiIAMScoped \
  --policy-document file://policies/iam-scoped.json
aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiDenyGuardrails \
  --policy-document file://policies/deny-guardrails.json

# 4. Create instance profile and attach to EC2
aws iam create-instance-profile --instance-profile-name loki-agent-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name loki-agent-profile \
  --role-name loki-agent-role
aws ec2 associate-iam-instance-profile \
  --instance-id <YOUR_INSTANCE_ID> \
  --iam-instance-profile Name=loki-agent-profile
```

See [docs/](docs/) for detailed setup, migration, and Terraform integration guides.

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
│   └── outputs.tf              # ARNs and names
├── docs/
│   ├── policy-design.md        # Full policy architecture docs
│   └── migration-guide.md      # Step-by-step migration from admin
└── README.md
```

## Customization

Before deploying, update these values in the policy files:

| Placeholder | Description | Example |
|------------|-------------|---------|
| `ACCOUNT_ID` | Your AWS account ID | `123456789012` |
| `AGENT_ROLE_NAME` | Name of the agent's IAM role | `loki-agent-role` |
| `BOUNDARY_POLICY_NAME` | Name of the permissions boundary | `LokiPermissionsBoundary` |
| `IAM_PATH` | Path prefix for agent-created roles | `/loki/` |

## License

MIT
