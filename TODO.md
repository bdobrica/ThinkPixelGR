# ThinkPixelGR implementation ledger

This file tracks current implementation and release work. Architectural intent
belongs in [`PLAN.md`](PLAN.md); accepted decisions and durable reference
material belong under [`docs/`](docs/README.md).

## Completed foundation

- [x] Publish the initial OpenAPI 3.1 evaluation contract.
- [x] Implement the Go HTTP service and health endpoints.
- [x] Load and validate versioned YAML policies and profiles at startup.
- [x] Resolve platform, tenant, profile, and request-selected policies.
- [x] Implement regex and keyword detectors with deterministic aggregation.
- [x] Return `allow`, `block`, `redact`, and `monitor` decisions.
- [x] Add unit and HTTP-handler tests.
- [x] Provide container and Compose development entry points.
- [x] Establish durable ADRs and a root `make verify` gate.

## Next implementation slice

- [x] Complete Phase 1 deterministic detectors: request limits, allow/deny lists,
  JSON Schema validation, and structured secret detection.
- [x] Define and test the remote detector wire contract before adding Python
  detector adapters.
- [x] Enforce per-policy and per-detector deadlines and document fail-open,
  fail-closed, and monitor-on-failure behavior in the public contract.
- [x] Add authentication and tenant authorization without treating a guardrail
  decision as Run or tool authority.
- [x] Add structured audit events, metrics, and tracing that exclude raw content
  and secrets by default.
- [ ] Add contract validation and integration tests to `make verify` when their
  implementations land.

## Later phases

- [ ] Add replaceable model-backed detector services.
- [ ] Add live, atomic policy reload and an authoritative policy-store adapter.
- [ ] Add production deployment, operational, security, and release evidence.
- [ ] Add streaming and speculative evaluation only with explicit caller-side
  enforcement semantics.
