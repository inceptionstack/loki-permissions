# Terraform Examples

This directory contains **standalone, non-module** Terraform snippets that
demonstrate how to author IAM resources from a *consuming* project (a
project that runs *under* the agent role and creates roles for its own
Lambda/CodeBuild/etc.).

These files are **not** part of the `loki-permissions` module. They are
reference material only. The `terraform/` directory is the actual module;
this `examples/` subdirectory is kept in a subdirectory because Terraform
would treat sibling `.tf` files as part of the same module otherwise
(causing `Duplicate variable declaration` errors when both define
`variable "account_id"`).

## Files

- `downstream-consumer.tf` — shows what an agent-spawned Lambda /
  CodeBuild / CodePipeline role looks like with the required `path` and
  `permissions_boundary` attributes set. Copy/adapt into your project.

## Usage

```bash
# In your project, NOT in this repo:
cp terraform/examples/downstream-consumer.tf my-project/iam.tf
# Then edit variables and `terraform apply` from my-project/.
```
