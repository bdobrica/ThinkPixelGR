# Verification gates

`make verify` is the repository's aggregate local and CI gate. It runs formatting
checks and `go vet`, then the following independently callable test targets:

| Target | Scope |
|---|---|
| `make unit-test` | Go service, policy, detector, authentication, and observability packages. |
| `make contract-test` | Semantic validation of both OpenAPI documents, compilation and fixture validation of the detector JSON Schema, and contract invariants. |
| `make integration-test` | The complete in-memory HTTP boundary using the shipped configuration, Bearer authentication, tenant authorization, deterministic evaluation/redaction, W3C tracing, audit output, and Prometheus metrics. Live request and response bodies are checked against the public OpenAPI schemas. |

The integration target deliberately uses Go's in-memory HTTP transport. It
exercises the production handler stack without requiring a listening socket,
containers, external services, external credentials, or network access. This
keeps the required gate deterministic in restricted CI environments.

OpenAPI validation uses `kin-openapi` as a test dependency. A maintained
semantic parser is justified here because hand-written YAML checks cannot
reliably validate reference resolution and OpenAPI object rules. Detector
payload semantics remain validated with the draft 2020-12 JSON Schema compiler.

Remote detector implementations, containers, live identity providers, and
production telemetry backends remain explicit future or deployment-specific
checks; this gate does not claim to exercise them.
