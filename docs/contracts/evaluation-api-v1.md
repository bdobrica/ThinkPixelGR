# Evaluation API v1 compatibility notes

The canonical machine-readable contract is [`api/openapi.yaml`](../../api/openapi.yaml).
These notes record compatible clarifications and additions within `/v1`.

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
