# ADR-0003: Resolve immutable policies with mandatory precedence

- Status: Accepted
- Date: 2026-08-30

## Context

Clients need reusable profiles and explicit policy selection, while platform
and tenant operators need controls that untrusted callers cannot disable.
Evaluation evidence must identify the exact policy versions used.

## Decision

Policies and profiles use canonical identifiers of the form `<id>@<version>`.
For an evaluation, ThinkPixelGR builds the effective set in this order:

1. platform-mandatory policies;
2. tenant-mandatory policies;
3. policies referenced by the selected profile;
4. policies explicitly selected by the request.

Duplicate identifiers are evaluated once. Policies that do not apply to the
requested stage are omitted. Unknown policy or profile identifiers reject the
request; they never silently degrade evaluation. Caller selections may add
evaluation but cannot remove mandatory policies.

When findings produce different actions, the current deterministic severity
order is `block`, `redact`, `monitor`, then `allow`. The response records every
applied canonical policy identifier.

## Consequences

- A recorded decision can be tied to immutable policy versions.
- Content and client-selected metadata cannot expand authority or weaken
  mandatory evaluation.
- Policy-store and reload mechanisms may change behind an adapter without
  changing resolution semantics.
