# Loki Policy Migration Template — YourCurrentAdminRole → Scoped Permissions

> Step-by-step migration guide for downgrading an AI agent from full admin to scoped permissions.
> Designed for zero-downtime migration with rollback capability.
> Last updated: 2026-03-16

---

## Prerequisites

- [ ] Read `Loki-Policy-Template.md` — understand the target policy architecture
- [ ] Admin access to create the new role and policies (human does this, NOT the agent)
- [ ] List of all existing IAM roles created by Terraform (the agent can generate this)
- [ ] Terraform state access for all managed projects

---

## Phase 1: Inventory (Agent does this)

### 1.1 List all IAM roles created by the agent's Terraform projects

```bash
# For each infra repo, find all IAM resources
for REPO in $(aws codecommit list-repositories --query 'repositories[*].repositoryName' --output text); do
  echo "=== $REPO ==="
  # Clone and scan for IAM resources
  git clone <repo-url> /tmp/$REPO 2>/dev/null
  grep -r 'aws_iam_role\|aws_iam_policy' /tmp/$REPO/*.tf 2>/dev/null | grep 'resource'
done
```

### 1.2 Generate migration manifest

Create a JSON file listing every role that needs to move to `/loki/` path:

```json
{
  "migration_date": "2026-03-16",
  "account_id": "ACCOUNT_ID",
  "roles_to_migrate": [
    {
      "project": "myapp",
      "current_name": "myapp-enqueue-role",
      "current_arn": "arn:aws:iam::ACCOUNT_ID:role/myapp-enqueue-role",
      "new_path": "/loki/",
      "new_name": "myapp-enqueue-role",
      "new_arn": "arn:aws:iam::ACCOUNT_ID:role/loki/myapp-enqueue-role",
      "terraform_file": "iam.tf",
      "terraform_resource": "aws_iam_role.enqueue",
      "services_using_role": ["lambda:myapp-enqueue"]
    }
  ],
  "policies_to_migrate": [],
  "instance_profiles_to_migrate": []
}
```

### 1.3 Check for cross-references

Some roles are referenced by ARN in other services (Lambda function configs, ECS task definitions, etc.). These need to be updated too:

```bash
# Find all places a role ARN is hardcoded
grep -r "arn:aws:iam.*role/" /tmp/*/  # In Terraform
aws lambda list-functions --query 'Functions[*].{fn: FunctionName, role: Role}' # In Lambda configs
aws ecs list-task-definitions # In ECS task defs
```

---

## Phase 2: Prepare (Human admin does steps 2.1-2.3, Agent does 2.4)

### 2.1 Create the new agent role (Human admin)

```bash
# Create the agent role that will replace YourCurrentAdminRole
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
```

### 2.2 Attach policies to new role (Human admin)

```bash
# Base: PowerUserAccess
aws iam attach-role-policy --role-name loki-agent-role \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# Scoped IAM (from Loki-Policy-Template.md)
aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiIAMScoped \
  --policy-document file://loki-iam-scoped.json

# Deny guardrails (from Loki-Policy-Template.md)
aws iam put-role-policy --role-name loki-agent-role \
  --policy-name LokiDenyGuardrails \
  --policy-document file://loki-deny-guardrails.json
```

### 2.3 Create instance profile (Human admin)

```bash
aws iam create-instance-profile --instance-profile-name your-agent-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name your-agent-profile \
  --role-name loki-agent-role
```

### 2.4 Update all Terraform configs (Agent)

For every Terraform project, update IAM resources to use `/loki/` path:

```hcl
# Add path = "/loki/" to every aws_iam_role
resource "aws_iam_role" "example" {
  name = "my-app-role"
  path = "/loki/"          # ← ADD THIS
  # ... rest unchanged
}

# Add path = "/loki/" to every aws_iam_policy  
resource "aws_iam_policy" "example" {
  name = "my-app-policy"
  path = "/loki/"          # ← ADD THIS
  # ... rest unchanged
}

# Add path = "/loki/" to every aws_iam_instance_profile
resource "aws_iam_instance_profile" "example" {
  name = "my-app-profile"
  path = "/loki/"          # ← ADD THIS
  # ... rest unchanged
}
```

**Important:** Adding `path` to an existing role is a **destructive change** — Terraform will destroy the old role and create a new one. This means:
- Lambda functions will briefly lose their execution role
- ECS services will need task def updates
- CodePipeline/CodeBuild roles will need re-attachment

---

## Phase 3: Migrate Roles (Agent, one project at a time)

### Migration Strategy: Parallel Create → Switch → Delete

To avoid downtime, create new `/loki/` roles alongside old ones, switch services over, then delete old roles.

### 3.1 Per-project migration steps

```bash
# For each project (e.g., myapp):

# Step 1: terraform plan — review what will change
cd /tmp/<project>-infra
terraform plan

# Step 2: If Terraform shows destroy+create for roles, proceed carefully
# The plan should show:
#   - aws_iam_role.xxx will be destroyed (old path)
#   - aws_iam_role.xxx will be created (new /loki/ path)

# Step 3: Apply with -target for IAM resources first
terraform apply -target=aws_iam_role.enqueue -target=aws_iam_role.parser ...

# Step 4: Apply the rest (Lambda configs will update to new role ARNs)
terraform apply

# Step 5: Verify all services are working
aws lambda invoke --function-name <fn> /dev/null  # Test each Lambda
aws codepipeline start-pipeline-execution --name <pipeline>  # Test pipeline
```

### 3.2 Alternative: Terraform state manipulation (advanced, zero-downtime)

For critical production services, use `terraform state rm` + `terraform import` to avoid destroy+create:

```bash
# 1. Manually create new role with /loki/ path via CLI
aws iam create-role --role-name my-role --path /loki/ --assume-role-policy-document ...
aws iam put-role-policy --role-name my-role --policy-name ... --policy-document ...

# 2. Update Lambda to use new role
aws lambda update-function-configuration --function-name my-fn --role arn:aws:iam::...:role/loki/my-role

# 3. Remove old resource from Terraform state
terraform state rm aws_iam_role.my_role

# 4. Import new role into Terraform state
terraform import aws_iam_role.my_role my-role

# 5. Delete old role manually
aws iam delete-role-policy --role-name my-old-role --policy-name ...
aws iam delete-role --role-name my-old-role
```

---

## Phase 4: Switch Instance Profile (Human admin)

**⚠️ This is the critical moment. Do this during a maintenance window.**

```bash
# 1. Disassociate current instance profile
ASSOC_ID=$(aws ec2 describe-iam-instance-profile-associations \
  --filters "Name=instance-id,Values=i-XXXXXXXXX" \
  --query 'IamInstanceProfileAssociations[0].AssociationId' --output text)

aws ec2 replace-iam-instance-profile-association \
  --association-id $ASSOC_ID \
  --iam-instance-profile Name=your-agent-profile

# 2. Verify agent can still operate
# Agent should run verification checklist from Loki-Policy-Template.md
```

### Rollback plan

If anything breaks:
```bash
# Immediately revert to YourCurrentAdminRole
aws ec2 replace-iam-instance-profile-association \
  --association-id $ASSOC_ID \
  --iam-instance-profile Name=<original-profile-name>
```

---

## Phase 5: Verify (Agent)

Run the full verification checklist:

```bash
echo "=== Positive tests (should succeed) ==="

# Can create /loki/ roles
aws iam create-role --role-name migration-test --path /loki/ \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
echo "✅ Create /loki/ role"
aws iam delete-role --role-name migration-test
echo "✅ Delete /loki/ role"

# Can use PowerUser services
aws s3 ls >/dev/null && echo "✅ S3 access"
aws lambda list-functions --max-items 1 >/dev/null && echo "✅ Lambda access"
aws dynamodb list-tables --max-items 1 >/dev/null && echo "✅ DynamoDB access"

echo ""
echo "=== Negative tests (should fail with AccessDenied) ==="

# Cannot create users
aws iam create-user --user-name test-should-fail 2>&1 | grep -q "AccessDenied" && echo "✅ Blocked: create user"

# Cannot create roles outside /loki/
aws iam create-role --role-name outside-path-test \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' 2>&1 | grep -q "AccessDenied" && echo "✅ Blocked: role outside /loki/"

# Cannot modify own role
aws iam attach-role-policy --role-name loki-agent-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>&1 | grep -q "AccessDenied" && echo "✅ Blocked: self-escalation"

# Cannot create access keys
aws iam create-access-key --user-name admin 2>&1 | grep -q "AccessDenied" && echo "✅ Blocked: create access key"
```

---

## Phase 6: Cleanup (Agent)

```bash
# 1. Delete old IAM roles that are no longer in use
# (Only after verifying all services use /loki/ roles)
for OLD_ROLE in $(cat migration-manifest.json | jq -r '.roles_to_migrate[].current_name'); do
  echo "Deleting old role: $OLD_ROLE"
  # Remove inline policies first
  for POLICY in $(aws iam list-role-policies --role-name $OLD_ROLE --query 'PolicyNames[*]' --output text); do
    aws iam delete-role-policy --role-name $OLD_ROLE --policy-name $POLICY
  done
  # Detach managed policies
  for POLICY_ARN in $(aws iam list-attached-role-policies --role-name $OLD_ROLE --query 'AttachedPolicies[*].PolicyArn' --output text); do
    aws iam detach-role-policy --role-name $OLD_ROLE --policy-arn $POLICY_ARN
  done
  # Delete role
  aws iam delete-role --role-name $OLD_ROLE
done

# 2. Remove old instance profile (human admin)
# aws iam remove-role-from-instance-profile ...
# aws iam delete-instance-profile ...

# 3. Update MEMORY.md and AGENTS.md with new role info
```

---

## Post-Migration Updates

### AGENTS.md
Add to Safety section:
```markdown
- **IAM roles must use path `/loki/`** — Terraform `path = "/loki/"` on all `aws_iam_role`, `aws_iam_policy`, and `aws_iam_instance_profile` resources. Agent cannot create roles outside this path.
```

### new-project-template.md
Update IAM section to include `/loki/` path requirement.

### MEMORY.md
Update IAM Role entry:
```markdown
- **IAM Role:** loki-agent-role (PowerUserAccess + LokiIAMScoped + LokiDenyGuardrails)
- **IAM Path:** /loki/ (all Terraform IAM resources must use this path)
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `terraform apply` fails with AccessDenied on IAM | Missing `path = "/loki/"` in Terraform | Add `path = "/loki/"` to the resource |
| Lambda fails with "role cannot be assumed" | New role ARN not propagated (IAM eventual consistency) | Wait 10-30 seconds and retry |
| CodePipeline fails | Pipeline role moved but stage configs reference old ARN | Update pipeline stage configs |
| Agent can't `PassRole` | Role is outside `/loki/` path | Move role to `/loki/` path first |
| `terraform plan` shows destroy+create for roles | Path change = new resource | Expected — use parallel create strategy or state manipulation |

---

## Timeline Estimate

| Phase | Duration | Who |
|-------|----------|-----|
| Phase 1: Inventory | 15 min | Agent |
| Phase 2: Prepare | 30 min | Human (role) + Agent (Terraform) |
| Phase 3: Migrate roles | 15-30 min per project | Agent |
| Phase 4: Switch profile | 5 min | Human |
| Phase 5: Verify | 10 min | Agent |
| Phase 6: Cleanup | 15 min | Agent |
| **Total** | **~2-3 hours** | Mixed |

---

*This is a template. Adjust phases and steps for your specific environment.*
