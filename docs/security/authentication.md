# Authentication and tenant authorization

ThinkPixelGR can require Bearer authentication for evaluation and policy-list
requests. This protects access to the GR API; it does not authorize the model,
tool, retrieval, ingestion, or other operation whose content is being checked.
Callers remain responsible for that authorization even when the result is
`allow`.

## Static Bearer adapter

The initial adapter is intended for local or controlled service-to-service
deployments. Configure principals using environment-variable references:

```yaml
auth:
  enabled: true
  principals:
    - id: gateway
      tokenEnv: THINKPIXELGR_GATEWAY_TOKEN
      tenants: [tenant-a, tenant-b]
      allowTenantless: false
      policyReader: false
      metricsReader: false
```

Set `THINKPIXELGR_GATEWAY_TOKEN` in the process environment before startup. A
token must contain at least 32 bytes. ThinkPixelGR fails startup if an enabled
configuration has a missing, short, or duplicated token, duplicated principal
ID, or invalid tenant scope. Credential values are not read from YAML, included
in configuration errors, or retained in plaintext after startup; only SHA-256
digests are retained for matching.

Send the credential as `Authorization: Bearer <token>`. Missing, malformed, or
unknown credentials return `401 UNAUTHENTICATED` and a `WWW-Authenticate:
Bearer` challenge. A valid principal without the requested tenant scope returns
`403 FORBIDDEN`.

Tenant access is exact by default. `tenants: ["*"]` explicitly permits every
non-empty tenant. `allowTenantless: true` independently permits requests that
omit `tenant_id`. `policyReader: true` independently permits `GET /v1/policies`.
`metricsReader: true` independently permits `GET /metrics`. Wildcard tenant
access, policy discovery, and metrics access are not inferred from one another.

The request's `subject`, roles, metadata, content, target, or selected policies
are untrusted evaluation input and cannot change these scopes. Likewise, a
guardrail result cannot grant permissions to a Run or operation.

## Deployment guidance

- Terminate TLS before credentials cross an untrusted network.
- Generate high-entropy service credentials, inject them through a secret
  manager or protected environment, and avoid placing them in command lines,
  configuration files, logs, traces, or evidence.
- Rotate a static credential by updating its environment value and restarting
  the service. Use distinct credentials for distinct principals.
- Omitting `auth` or setting `auth.enabled: false` selects compatibility mode.
  Use it only in a trusted local environment: it permits all tenant and
  policy-list and metrics access and is not suitable for a shared deployment.
- Prefer a future workload-identity, mTLS, or OIDC adapter when identity-aware
  infrastructure and revocation are required.
