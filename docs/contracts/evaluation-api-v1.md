# Evaluation API v1 compatibility notes

The canonical machine-readable contract is [`api/openapi.yaml`](../../api/openapi.yaml).
These notes record compatible clarifications and additions within `/v1`.

## Authentication and tenant authorization

Deployments can protect `POST /v1/evaluations` and `GET /v1/policies` with the
OpenAPI `BearerAuth` scheme. The shipped configuration enables authentication;
deployments retaining the explicit disabled mode remain wire-compatible with
anonymous v1 clients. Health endpoints remain anonymous in either mode.

With authentication enabled, a missing or invalid credential returns `401`
with a Bearer challenge. A valid principal that lacks the requested tenant
scope or policy-list capability returns `403`. `tenant_id` is caller-provided
routing context that MUST be checked against the server-established principal;
it is not identity evidence. Omission requires an explicit tenantless scope.

The `subject`, `target`, `metadata`, content, and guardrail selector objects are
untrusted inputs to evaluation. They MUST NOT establish or expand API, tenant,
Run, model, tool, Workspace, memory, credential, or side-effect authority. A
guardrail decision has no such authority either: `allow` means only that the
applied guardrail policies did not reject the evaluated content.

Bearer authentication, `401`, and `403` are additive v1 contract capabilities.
Enabling authentication is an operationally significant deployment change, so
operators must distribute credentials before switching existing clients.

## Trace propagation and metrics

Evaluation clients may send a W3C `traceparent` header. ThinkPixelGR continues a
valid version `00` context and returns the server span context in `traceparent`.
An invalid value is ignored and replaced, not logged or echoed.

`GET /metrics` is an additive, Prometheus-compatible operational endpoint. In
authenticated deployments it requires the independent `metricsReader`
capability. Metric labels exclude request, evaluation, principal, tenant,
profile, and raw policy-expression values. Neither telemetry nor possession of
the metrics capability changes evaluation or Run/tool authority.

## Contract validation

The OpenAPI document is parsed, reference-resolved, and semantically validated
by `make contract-test`. Live integration responses are also checked against
their declared response schemas by `make integration-test`. Singleton `enum`
forms are used where they are semantically equivalent to JSON Schema `const` so
the OpenAPI 3.1 contract remains compatible with the repository validator; this
does not change any accepted wire value.

## Finding attributes

`Finding.attributes` is an optional object containing structured, non-content
evidence such as the violated limit, selector, schema location, or secret
pattern identifier. Implementations MUST NOT include a matched secret or raw
evaluated content in attributes.

Adding this optional response property is backward compatible for clients that
follow the OpenAPI contract. Clients MUST ignore response properties they do not
understand. Existing `locations` remain byte offsets into textual content;
detectors that report structural rather than textual locations use an
`attributes.path` value instead.

## Deterministic request-size measurement

For HTTP evaluations, `request_bytes` is the number of bytes in the received
JSON request body, including insignificant JSON whitespace. In-process callers
that do not provide a transport byte count are measured using the compact JSON
encoding of the evaluation request. The service-wide HTTP body ceiling remains
independent of policy-selected request limits.

## Deadlines and detector failures

Every compiled policy has a `timeout`; omission resolves to 100 milliseconds.
Every detector invocation also has a `timeout`; omission inherits the policy
timeout. A detector timeout can narrow but cannot extend its containing policy's
remaining budget; configuration that sets a detector timeout above its policy
timeout is rejected. Policy time includes all detector work performed for that
policy. Once it expires, remaining detectors in that policy are skipped.

Every policy has a `failureMode` of `open`, `closed`, or `monitor`; omission
resolves to the security-preserving `closed` mode. Published policies SHOULD set
the mode and both timeout levels explicitly because changing any of them changes
policy behavior and therefore requires a new immutable policy revision.

Detector and policy execution failures are returned in the optional
`detector_failures` response array. They are not findings and do not trigger the
policy's ordinary finding action:

| Failure mode | Decision effect |
|---|---|
| `open` | Records the failure without escalating the decision. |
| `closed` | Escalates the decision to `block`. |
| `monitor` | Escalates an otherwise `allow` decision to `monitor`. A stronger finding or failure decision still wins. |

A detector-scoped failure does not stop later detectors while policy time
remains. A policy-scoped timeout stops the remaining detectors in that policy,
then evaluation continues with other effective policies when the caller's
overall context still permits it.

Each failure records the immutable policy ID, detector ID when one was invoked,
scope, bounded code, effective failure mode, applicable timeout, and whether the
remote condition may be retryable. It MUST NOT contain a raw error, provider
response, evaluated content, or matched secret. Codes are `POLICY_TIMEOUT`,
`DETECTOR_TIMEOUT`, `DETECTOR_UNAVAILABLE`, `DETECTOR_INVALID_RESPONSE`,
`DETECTOR_UNSUPPORTED_INPUT`, and `DETECTOR_INTERNAL_ERROR`.

Policy and detector failures are successful evaluations and return HTTP 200,
including fail-closed blocks. Cancellation or expiration of the caller's overall
request context aborts evaluation instead of applying a policy failure mode; the
HTTP service returns 504 when it can still write a response.

`timing.detectors` records time by detector ID and `timing.policies` records time
by canonical policy ID. Millisecond values may be zero for sub-millisecond work.
The `detector_failures` and `timing.policies` properties are backward-compatible
additions to v1. Clients MUST ignore response properties they do not understand.
