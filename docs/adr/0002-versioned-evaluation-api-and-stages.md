# ADR-0002: Use a versioned evaluation API and canonical stages

- Status: Accepted
- Date: 2026-08-30

## Context

Gateways and services need one stable integration shape across several points
in an LLM-adjacent workflow. Go implementation types are not a cross-component
contract and must not be imported by peer repositories.

## Decision

The public HTTP contract is defined by [`api/openapi.yaml`](../../api/openapi.yaml)
and is versioned under `/v1`. The canonical evaluation stages are
`pre_request`, `pre_model`, `post_model`, `pre_tool`, `post_tool`,
`pre_retrieval`, `post_retrieval`, and `ingestion`.

Requests carry a caller-generated request identifier, stage, content envelope,
optional tenant context, and policy/profile selectors. Responses carry an
evaluation identifier, the request identifier, decision, applied immutable
policy identifiers, findings, and timing. A policy block is a successful
evaluation response, not a transport error.

Public schema changes require implementation, compatibility documentation, and
contract-test updates in the same change. New incompatible behavior requires a
new API version.

## Consequences

- The OpenAPI document, rather than internal Go types, is authoritative for
  interoperating clients.
- Callers can correlate evidence without logging raw evaluated content.
- Stage-specific policies can evolve without creating endpoint-specific domain
  models.
