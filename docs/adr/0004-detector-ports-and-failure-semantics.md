# ADR-0004: Isolate detectors and make failure semantics explicit

- Status: Accepted
- Date: 2026-08-30

## Context

Deterministic checks fit naturally in the Go service, while model-backed checks
need Python or other specialized runtimes. Embedding those runtimes would couple
the evaluator lifecycle and supply chain to every detector implementation.
Detector failure is security-relevant and cannot be hidden behind a default.

## Decision

Detectors produce findings; policy aggregation converts findings into a
decision. Deterministic detectors may run in process behind a detector
interface. Model-backed or provider-specific detectors run out of process and
are reached through a versioned detector port and adapter. Their credentials,
runtime types, and raw provider responses do not enter the core domain model.

Each detector invocation has an explicit deadline and a policy-selected failure
mode: fail open, fail closed, or monitor on failure. The effective mode and
failure evidence must be observable without persisting raw evaluated content.
Retries are permitted only when bounded by the evaluation deadline and safe for
the detector contract.

The current bootstrap implements only synchronous in-process regex and keyword
detectors. Remote detector protocol, isolation, deadlines, and configurable
failure modes must be added with contract and failure-path tests before they are
claimed as supported.

## Consequences

- Python and future detector runtimes remain independently deployable and
  replaceable.
- A detector outage has deliberate, testable behavior for each policy.
- Remote detector work cannot bypass the public-contract and evidence
  requirements merely for implementation convenience.
