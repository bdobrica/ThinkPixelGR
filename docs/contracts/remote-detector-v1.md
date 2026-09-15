# Remote detector protocol v1

The OpenAPI and draft 2020-12 JSON Schema documents are compiled and validated
by `make contract-test`, including every published example. The schema uses
singleton `enum` and `oneOf` expressions in place of equivalent `const` and
multi-type expressions where needed for OpenAPI validator interoperability;
accepted and rejected wire values are unchanged.

The normative artifacts are the [OpenAPI document](../../api/detector/v1/openapi.yaml)
and [JSON Schema bundle](../../api/detector/v1/schema.json). Published examples
and the executable schema conformance suite live beside them under
[`api/detector/v1/`](../../api/detector/v1/).

## Boundary and security

A remote detector reports observations. It MUST NOT return `allow`, `block`,
`redact`, another enforcement action, or any authorization decision. ThinkPixelGR
maps findings to policy decisions, and its caller remains the enforcement point.

`configuration` is detector-specific policy input. It MUST NOT contain
credentials or be interpreted as authority. Request metadata is deliberately
limited to tenant and trace correlation. Services MUST NOT log content by
default, and findings, attributes, errors, and telemetry MUST NOT echo raw
content, matched credentials, or secrets.

The transport can carry sensitive content. Deployments MUST authenticate
callers, restrict network access, and protect the channel; those mechanisms are
deployment concerns and are intentionally outside the portable payload schema.

## Detection

`POST /v1/detect` accepts one `DetectionRequest`. `request_id` belongs to the
original caller and `evaluation_id` belongs to ThinkPixelGR. A successful
response MUST echo both values exactly. HTTP 200 means detection completed; an
empty `findings` array is a successful no-finding result.

Finding locations use UTF-8 byte offsets with an exclusive `end`, matching the
evaluation API. A service MUST omit locations when it cannot produce reliable
spans. Confidence is normalized to the inclusive range 0 through 1. Categories
MUST be drawn from the taxonomy advertised by `/v1/metadata`.

Detector `id` and `version` identify the externally visible implementation;
`revision` identifies its immutable build or artifact. A model-backed detector
supplies a model name and immutable model revision; a detector without a model
sets `model` to `null`. Raw provider responses, logits, credentials, and
runtime-specific types do not cross this boundary.

## Batch detection

`POST /v1/detect:batch` accepts a non-empty ordered request array. When batch is
supported, a successful response MUST have the same cardinality and order, and
each item MUST preserve both correlation identifiers. A processing failure fails
the whole request using the error envelope; v1 does not expose partial results.

The endpoint MUST exist even when `capabilities.batch` is false. In that case
`limits.max_batch_size` MUST be zero and the endpoint returns HTTP 400 with
`UNSUPPORTED_OPERATION`. When batch is true, `max_batch_size` MUST be positive.

## Metadata and limits

`GET /v1/metadata` is the authoritative capability declaration for a running
detector revision. `protocol_version` is `1.0`. `preprocessing_revision` changes
whenever preprocessing behavior changes. An empty `supported_languages` array
means the detector is language-independent.

`limits.max_input_bytes` is the largest accepted HTTP body for `/v1/detect`.
For a batch it is the largest compact JSON encoding of an individual request;
the service MAY also impose a bounded total batch-body limit. Inputs above a
published limit return HTTP 413 with `REQUEST_TOO_LARGE`.

The future Go adapter MUST compare configured detector identity, required stage,
content type, language, and batching needs with metadata before sending content.
A metadata mismatch makes the detector unavailable; it must not silently reduce
coverage.

## Health and errors

`GET /health/live` reports whether the process is alive. `GET /health/ready`
returns 200 with `status: ok` only after the immutable detector/model artifacts
are loaded and work can be accepted; it returns 503 with `status: not_ready`
otherwise.

Errors use `INVALID_REQUEST`, `REQUEST_TOO_LARGE`, `UNSUPPORTED_STAGE`,
`UNSUPPORTED_CONTENT_TYPE`, `UNSUPPORTED_OPERATION`, `OVERLOADED`, or
`INTERNAL_ERROR`. Known correlation identifiers SHOULD be included. HTTP 429
represents bounded-capacity rejection, and HTTP 503 represents temporary
unavailability. `retryable` describes the remote condition only; the
orchestrator may retry solely when the operation is safe and remains within its
evaluation deadline.

Detection has no side effects and is safe to retry at the protocol level, but a
non-deterministic detector is not required to return byte-identical findings.

The Go adapter MUST bind each remote call to the detector context supplied by
the evaluator. Remote timeout, unavailable, unsupported-input, and invalid
response conditions map to the evaluation API's content-free
`detector_failures` evidence. The policy-selected failure mode remains local to
ThinkPixelGR and MUST NOT be sent to or decided by the remote detector.
