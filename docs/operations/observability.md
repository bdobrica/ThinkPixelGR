# Observability operations

ThinkPixelGR emits content-safe JSON logs and serves Prometheus metrics on the
main HTTP listener. Telemetry is deliberately metadata-only by default.

## Audit events

Every authenticated evaluation attempt emits a `thinkpixelgr.audit/v1` event
with type `evaluation` and outcome `completed` or `rejected`. Authentication
failures emit an `api_access` denial. Completed evaluation events may include:

- evaluation, tenant, and authenticated principal identifiers plus a SHA-256
  digest of the caller-supplied request identifier;
- stage, action, and immutable applied policy identifiers;
- detector ID, finding category, confidence, and severity;
- bounded detector failure code, scope, and failure mode;
- total, policy, and detector timing values.

Rejected events contain only identifiers decoded before rejection and a bounded
error code. Raw errors are not recorded.

Audit events never include request or transformed content, finding attributes
or locations, request metadata, target data, authorization headers, tokens,
matched secrets, or raw detector/provider responses. Content hashes are not
emitted by default. stdout delivery is best effort; deployments requiring
durable or tamper-evident audit must collect the JSON stream into an
appropriately protected backend.

## Metrics

With `metricsReader: true`, scrape the endpoint using that principal's Bearer
credential:

```bash
curl --fail-with-body http://localhost:8080/metrics \
  -H "Authorization: Bearer ${THINKPIXELGR_DEMO_TOKEN}"
```

The endpoint exports:

- `thinkpixelgr_http_requests_total` by method, bounded route, and status;
- `thinkpixelgr_evaluations_total` by stage, outcome, and action;
- `thinkpixelgr_evaluation_duration_seconds` histogram by stage;
- `thinkpixelgr_detector_duration_seconds` histogram by configured detector ID;
- `thinkpixelgr_findings_total` by configured category;
- `thinkpixelgr_detector_failures_total` by bounded code and failure mode.

Metrics intentionally omit request, evaluation, principal, tenant, profile, and
policy-expression labels. This avoids content disclosure and unbounded
cardinality. Detector IDs and categories are expected to come from reviewed
configuration or a contract-conforming detector taxonomy.

## Tracing

The HTTP service accepts W3C `traceparent`, continues valid version `00`
contexts, and returns the server span context in the response header. Invalid
headers are ignored and replaced with a new trace context; their values are not
logged.

Spans cover the HTTP request, guardrail evaluation, policy resolution, local
detector execution, decision aggregation, transformations, and audit emission.
The built-in adapter writes structured span events at debug level. Enable them
with `THINKPIXELGR_LOG_LEVEL=debug`. Span attributes are restricted to bounded
operation, stage, policy ID, and detector ID fields.

Telemetry never expands Run, model, tool, Workspace, memory, or side-effect
authority and does not alter evaluation or failure-mode decisions.
