# ADR-0005: Use a findings-only HTTP contract for remote detectors

- Status: Accepted
- Date: 2026-09-15

## Context

ADR-0004 requires model-backed and provider-specific detectors to remain
replaceable out-of-process services behind a versioned detector port. A Python
adapter cannot be implemented safely until detector authors and the Go
orchestrator share precise request, response, identity, capability, size, and
error semantics.

## Decision

Remote detectors implement the HTTP/JSON contract under
[`api/detector/v1/`](../../api/detector/v1/). The v1 routes are
`POST /v1/detect`, `POST /v1/detect:batch`, `GET /v1/metadata`,
`GET /health/live`, and `GET /health/ready`.

Detection responses contain normalized findings and immutable detector/model
identity. They never contain an enforcement action or policy decision. Both
single and batch responses echo the caller's request and evaluation identifiers.
Batch responses preserve request order and cardinality. A batch-level failure
fails the whole HTTP request; v1 does not define partial batch success.

Metadata advertises stages, content types, languages, size limits, taxonomy,
threshold recommendations, span and batch support, determinism, and immutable
preprocessing identity. The future adapter must validate metadata against its
configured expectations before considering a detector ready.

Protocol errors use bounded machine-readable codes and must not echo evaluated
content. Transport authentication, detector credentials, policy aggregation,
deadlines, retries, and failure-mode decisions remain orchestrator or deployment
responsibilities and are not delegated through this wire payload.

## Consequences

- Detector implementations can use Python or any other runtime without exposing
  runtime-specific types to the Go domain.
- A detector cannot turn model output, configuration, tenant metadata, or
  findings into Run, model, tool, Workspace, or memory authority.
- Protocol v1 can be tested before a remote adapter exists. Incompatible payload
  or semantic changes require a new protocol version.
- The adapter, deadlines, failure policies, and live endpoint conformance remain
  separate implementation work.
