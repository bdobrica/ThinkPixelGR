# ADR-0007: Use allowlisted, content-safe observability events

- Status: Accepted
- Date: 2026-09-15

## Context

Guardrail evaluations process prompts, tool data, retrieved material, model
output, and credentials that detectors may identify as sensitive. Audit,
metrics, and tracing are necessary for security review and operation, but a
generic request logger or arbitrary attribute map would create a second,
poorly-controlled store for that sensitive input.

The implementation also needs to remain independent of a specific audit store,
metrics collector, or tracing vendor.

## Decision

The evaluator and HTTP boundary emit telemetry through an explicit
observability port. The initial adapter provides:

- versioned JSON audit events through the process logger;
- Prometheus text metrics at `GET /metrics`;
- W3C `traceparent` continuation and structured spans.

Audit and span types use an allowlist of typed fields. They include stable
evaluation, tenant, principal, policy, and detector identifiers and a SHA-256
digest of the caller-supplied request identifier;
bounded outcomes and failure codes; finding category, confidence, and severity;
action; counts; and timings. They have no fields for request content,
transformed content, finding attributes or locations, HTTP authorization
headers, credential values, raw errors, detector responses, request metadata,
or target payloads.

Content hashes are also excluded by default because low-entropy or known input
can be recovered by comparison. Adding content sampling, content-derived
values, or arbitrary telemetry attributes requires a separate opt-in design
with authorization, retention, and disclosure controls.

Metrics use bounded route, status, stage, outcome, action, failure-code, and
failure-mode dimensions. Configured detector IDs and finding categories are
permitted. Request IDs, evaluation IDs, principal IDs, tenant IDs, selected
profiles, and policy expressions are not metric labels. `/metrics` requires the
separate `metricsReader` API capability when authentication is enabled.

An invalid incoming `traceparent` is discarded rather than logged or echoed.
The service creates a new trace and returns its server span context. The built-in
adapter emits trace spans at debug level. Telemetry emission is best effort and
does not change a guardrail decision or grant authority.

## Consequences

- Structured audit output can be routed to a durable store by deployment
  logging infrastructure; stdout is not itself an authoritative audit store.
- A future OpenTelemetry, remote-write, or durable audit adapter can replace the
  built-in adapter without adding vendor types to evaluation domain objects.
- Operators can correlate an evaluation without retaining the evaluated input.
- Detailed payload debugging is deliberately unavailable in default telemetry.
- Retention, access control, delivery guarantees, and audit-backend failure
  policy require explicit deployment or future adapter configuration.
