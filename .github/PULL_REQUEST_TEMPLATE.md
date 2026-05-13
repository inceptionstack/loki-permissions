# Pull Request

## What this PR does

<!-- One sentence. -->

## Why

<!-- Link the issue this addresses, or describe the threat/bug. -->

## Type of change

- [ ] New deny action(s) — added to BOTH `policies/deny-guardrails.json` AND `terraform/main.tf`
- [ ] Bug fix — existing deny wasn't blocking what it should
- [ ] Documentation
- [ ] CI / tooling
- [ ] Other (describe)

## Checklist

- [ ] If touching policies: JSON and Terraform sides updated together (CI parity check would fail otherwise)
- [ ] `terraform fmt -recursive` is clean
- [ ] No new placeholders introduced without README + substitution-helper updates
- [ ] No real account IDs / bucket names / KMS ARNs in fixtures
- [ ] Documented breaking changes in commit body if any (e.g., variable rename, IAM resource recreate)
