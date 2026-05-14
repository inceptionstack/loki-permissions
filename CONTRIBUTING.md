# Contributing to loki-permissions

Thanks for your interest in improving this project.

## What this repo is

A scoped IAM policy template for AI DevOps agents running on AWS EC2. It is opinionated about a specific threat model (autonomous agents on private subnets, no SSH, message-driven control). Contributions that fit this threat model are welcome; contributions that broaden the scope to a generic IAM library are likely to be declined.

## Reporting bugs

Open a [GitHub issue](https://github.com/inceptionstack/loki-permissions/issues) using the bug template. Please include:

- Which deployment path you used (CLI Quick Start / Terraform module)
- The exact `aws iam` or `terraform apply` error message
- Output of `aws sts get-caller-identity` (redact account ID if you prefer)
- Whether the failure is at `terraform plan`, `terraform apply`, or runtime

## Suggesting changes

For anything beyond a typo fix:

1. Open an issue first describing the problem and proposed change
2. Wait for maintainer response before opening a PR — saves rework if the direction is wrong
3. Reference the issue in your PR

## Pull requests

- One concern per PR. Don't bundle a bugfix with refactoring.
- Run the linter locally before pushing:
  ```bash
  cd terraform
  terraform fmt -recursive
  terraform init -backend=false -input=false && terraform validate
  # The full parity check (JSON ↔ Terraform) requires rendered statement
  # files. See .github/workflows/lint.yml for the canonical render flow,
  # then: python3 ../scripts/check_parity.py
  ```
- CI must pass. The lint workflow validates JSON, Terraform, and per-Sid action parity between JSON and Terraform forms.
- Update `policies/*.json` AND `terraform/main.tf` together. CI will fail on drift between the two encodings.

## Adding new deny actions

When extending the audit-tampering deny set:

1. Add the action to BOTH `policies/deny-guardrails.json` and the corresponding `local` in `terraform/main.tf`
2. Group by service (cloudtrail / config / guardduty / securityhub / s3 / kms)
3. If the action requires a new placeholder or variable, document it in the README placeholder table
4. CI's parity check will fail if you forget either side

## Security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for the private disclosure process.

## License

By contributing, you agree your contributions are licensed under the Apache License 2.0 (matching this project's LICENSE).
