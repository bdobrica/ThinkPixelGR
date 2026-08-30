# ADR-0001: Keep ThinkPixelGR an evaluator, not a proxy

- Status: Accepted
- Date: 2026-08-30

## Context

Guardrail checks are needed around model, tool, retrieval, and ingestion flows.
Making this service proxy those flows would also make it responsible for model
providers, streaming, retries, credentials, tool execution, and authorization.
Those responsibilities belong to callers and other ThinkPixel components.

## Decision

ThinkPixelGR evaluates content and returns findings, optional transformations,
and a policy decision. The caller enforces the result. ThinkPixelGR does not
proxy provider traffic, execute tools, or grant Run, tool, model, Workspace, or
memory authority. An `allow` decision only means that the evaluated guardrail
policies did not reject the content; it is never an authorization grant.

Integrations use the versioned wire API and remain optional and replaceable.
Provider- and ThinkPixel-specific behavior must stay outside the core domain.

## Consequences

- Callers must fail safely when evaluation is unavailable and must enforce any
  returned block or transformation according to their configured policy.
- A transformed tool operation requires the tool enforcement point to authorize
  the materially changed operation again.
- ThinkPixelGR can be deployed as a shared service or sidecar without becoming
  part of the model or tool data plane.
