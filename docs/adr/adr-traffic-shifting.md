# ADR: Kubernetes traffic shifting mechanism

## Status

Accepted.

## Context

For HTTP workloads, controlled rollout strategies require a traffic shifting mechanism. Kubernetes offers multiple options with different maturity and ecosystem support.

`x07-platform` has an OSS Kubernetes lane that must work on common clusters without proprietary dependencies.

## Decision

### Preferred mechanism: Gateway API weights

When available, use Gateway API `HTTPRoute` weighted backends for traffic splitting between revisions.

Reasons:

- explicit traffic weights as first-class Kubernetes resources,
- clear status surfaces in the API,
- portable across gateway implementations that implement the standard.

### Fallback mechanism: Ingress + rolling update

When Gateway API is not available, use:

- `Ingress` for reachability (single backend per route), and
- `Deployment` rolling update settings for “safe enough” progressive rollout.

The OSS Kubernetes lane prioritizes deterministic reconciliation and stable operator experience over implementing every traffic shifting feature on every ingress controller.

## Consequences

- Rollout implementations may be gated per target capability (Gateway API present vs not).
- The platform’s status/explain surfaces must state which mechanism is active for a deployment.
