# Workload telemetry identity (Kubernetes)

This document defines the canonical identity labels and OpenTelemetry resource attributes used by `x07-platform` workloads on Kubernetes so that:

- dashboards and SLO evaluation can filter consistently,
- support tooling can pivot by stable IDs,
- and label cardinality stays controlled.

## Canonical Kubernetes labels

These labels are applied to every pod template created by the Kubernetes workload lane:

- `lp.environment_id`
- `lp.deployment_id`
- `lp.service_id`

The platform also applies `x07.io/*` labels for internal classification (workload id, cell key/kind, ingress kind).

## Canonical OpenTelemetry resource attributes

Workload containers receive:

- `LP_ENVIRONMENT_ID`, `LP_DEPLOYMENT_ID`, `LP_SERVICE_ID` via the downward API (from labels), and
- `OTEL_RESOURCE_ATTRIBUTES` set to include:
  - `service.name=$(LP_SERVICE_ID)`
  - `deployment.environment=$(LP_ENVIRONMENT_ID)`
  - `lp.environment_id=$(LP_ENVIRONMENT_ID)`
  - `lp.deployment_id=$(LP_DEPLOYMENT_ID)`
  - `lp.service_id=$(LP_SERVICE_ID)`

## Cardinality guardrails

Do not promote high-cardinality values (request ids, user ids, trace ids) to Kubernetes labels. Keep them as log fields and/or trace attributes.

