# Security Policy

## Reporting a Vulnerability

This repo defines IAM policies that protect production AWS environments from agent-driven privilege escalation and audit-trail tampering. Security issues here can have high blast radius.

**Do NOT open a public GitHub issue for security findings.**

### Private disclosure

Email security findings to: **security@inceptionstack.dev**

Include:

- A description of the issue and the threat it enables (privilege escalation, audit blinding, scope widening, etc.)
- The specific Sid / statement / variable / Terraform resource involved
- A proof-of-concept policy snippet or `aws iam simulate-principal-policy` invocation that demonstrates the issue
- Your suggested fix, if any

You will receive an acknowledgement within 5 business days.

### What counts as a vulnerability

- A bypass of one of the documented denies (e.g., an action that should be blocked by `DenySelfEscalation` but isn't)
- A scope-widening pattern that defeats the agent-path restriction
- A footgun in the substitution helper or Terraform module that produces a syntactically valid but semantically wrong policy
- A regression in CI that lets JSON↔Terraform drift land on `main`

### What doesn't

- Suggestions to add deny actions that don't bypass an existing category — open a normal issue for those
- Concerns about deployments outside this repo's documented threat model (single-tenant agent on private subnet)
- IAM permissions intentionally allowed by `LokiIAMScoped` in agent-path scope

## Supported versions

This is a template repo; we maintain `main` only. If you fork, you are responsible for tracking upstream fixes.

## Threat model recap

See the [README](README.md#threat-model) for the full threat model. In short:

- The agent is **trusted** to do legitimate DevOps work
- The agent is **not trusted** to escalate, persist as a new identity, or blind audit infrastructure
- Recovery from a compromised agent relies on CloudTrail integrity — the audit-tampering denies are the lynchpin
