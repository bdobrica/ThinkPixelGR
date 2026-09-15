# ADR-0006: Authenticate evaluation callers and authorize tenant scope at ingress

- Status: Accepted
- Date: 2026-09-15

## Context

Evaluation requests carry `tenant_id`, `subject`, target metadata, and arbitrary
content supplied by a caller. None of those fields is trustworthy evidence of
the caller's identity or tenant access. At the same time, ThinkPixelGR must not
become the authority for Runs, models, tools, Workspaces, or memory merely
because it authenticates access to its own API.

ADR-0001 establishes that a guardrail decision is content-policy evidence for a
caller to enforce, not an authorization grant. This remains true when the
evaluation endpoint itself is authenticated.

## Decision

ThinkPixelGR authenticates protected API requests through a replaceable
authentication and authorization port. The initial adapter accepts Bearer
credentials whose values are supplied through environment variables. Static
configuration stores environment-variable names and principal scopes, never
credential values; the running adapter retains only SHA-256 token digests.

The authenticated principal is established at the HTTP ingress. `tenant_id`
must be within that principal's server-side tenant scope before policy
resolution or detector execution begins. Tenantless access and all-tenant
access are separate explicit scopes. Request `subject`, `target`, `metadata`,
content, guardrail selectors, findings, transformations, and decisions MUST NOT
establish or expand the principal's tenant scope.

Live and ready health endpoints remain anonymous. Policy enumeration requires a
separate `policyReader` capability because canonical policy identifiers can
reveal deployment or tenant configuration. Deployments may explicitly disable
authentication for local compatibility, but the shipped example enables it.

This authorization admits a principal only to request a GR evaluation for the
specified tenant. It does not authorize the evaluated operation. In particular,
an `allow`, `monitor`, `redact`, or `block` decision cannot grant or widen Run,
model, tool, Workspace, memory, credential, or side-effect authority. The caller
must independently enforce the authority applicable to the operation.

## Consequences

- Missing or invalid credentials return `401`; authenticated principals outside
  the requested tenant or API capability return `403`.
- An OIDC, workload-identity, mTLS, or gateway-assertion adapter can replace the
  static adapter without changing the evaluation domain.
- TLS termination, credential issuance, rotation, and revocation remain
  deployment responsibilities.
- Enabling authentication can require existing clients to add a Bearer header.
  Authentication remains deployment-selectable within `/v1`, so deployments
  can stage that operational migration without changing request payloads.
