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
