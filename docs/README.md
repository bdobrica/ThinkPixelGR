# ThinkPixelGR documentation

ThinkPixelGR is a guardrails evaluator. Its public contract is the versioned
wire API; callers remain responsible for enforcing returned decisions and for
authorization of Runs, tools, models, Workspaces, and memory.

## Decisions

- [ADR-0001: Evaluator, not proxy](adr/0001-evaluator-not-proxy.md)
- [ADR-0002: Versioned evaluation API and canonical stages](adr/0002-versioned-evaluation-api-and-stages.md)
- [ADR-0003: Policy resolution and versioning](adr/0003-policy-resolution-and-versioning.md)
- [ADR-0004: Detector ports and failure semantics](adr/0004-detector-ports-and-failure-semantics.md)
- [ADR-0005: Versioned remote detector HTTP contract](adr/0005-versioned-remote-detector-http-contract.md)

## Contracts and implementation intent

- [OpenAPI contract](../api/openapi.yaml)
- [Evaluation API v1 compatibility notes](contracts/evaluation-api-v1.md)
- [Deterministic detector configuration](contracts/deterministic-detectors-v1.md)
- [Remote detector protocol v1](contracts/remote-detector-v1.md)
- [Repository alignment](../ALIGNMENT.md)
- [Implementation plan](../PLAN.md)
- [Implementation ledger](../TODO.md)

Add durable material under `architecture/`, `contracts/`, `security/`,
`operations/`, or `evidence/` as those areas acquire implemented content. Empty
directories are intentionally not kept for symmetry alone.
