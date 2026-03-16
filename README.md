# loki-permissions

Scoped IAM policies for AI DevOps agents running on AWS EC2.

**Drop-in replacement for `AdministratorAccess` / `AdministratorAccess`** — gives the agent enough permissions to build infrastructure via Terraform while preventing privilege escalation.

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
