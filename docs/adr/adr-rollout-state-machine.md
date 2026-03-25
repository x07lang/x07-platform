# ADR: Rollout state machine + control surface

## Status

Accepted.

## Context

Rollouts are coordinated across:

- `x07-platform` (execution and status),
- a hosted control plane (policy, SLO evaluation, and incident-driven triggers),
- and agent tooling (`x07-mcp`) that must call a stable interface.

The public wire shapes are governed by `lp.rollout.*` contracts.

## Decision

The rollout status model uses a **single state field** (do not introduce development-process wording into public schemas).

### Rollout states (v1)

Rollout state is one of:

- `queued`
- `shifting`
- `paused`
- `promoted`
- `rolled_back`
- `failed`

### Rollout strategies (v1)

- `canary` (progressive shift)
- `blue_green` (two revisions, switch over)

### Control actions (v1)

The control surface supports:

- `start` (create and begin a rollout)
- `pause` (hold steady)
- `promote` (finalize)
- `abort` (stop without promotion)
- `rollback` (return to previous revision with a reason/evidence record)

### Responsibility boundary (Option B)

SLO evaluation runs in the hosted control plane. That component stores SLO snapshots and can request rollbacks; `x07-platform` executes the rollback action and records the rollout transition.

## Consequences

- Rollout state is comparable across OSS and hosted surfaces.
- Agent tools can be conservative and safe: list/status before mutating actions, explicit confirmations for rollback.
