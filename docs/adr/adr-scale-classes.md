# ADR: Scale classes

## Status

Accepted.

## Context

`x07-platform` runs workload packs on Kubernetes by mapping each workload cell onto a small set of well-understood operational shapes. The mapping must be:

- predictable (operators should know what to expect from a given class),
- configurable with a small number of knobs,
- and observable (status + telemetry identity must be stable across environments).

## Decision

Every deployable workload cell declares a `scale_class` (carried through `x07.workload.pack` and surfaced on Kubernetes as `x07.io/scale-class` plus `X07_WORKLOAD_SCALE_CLASS`).

The platform treats scale classes as **operational intent**, not as an implementation detail. Each class has a default mapping, and a bounded set of supported scaling signals.

### Scale classes (v1)

#### `replicated-http`

Goal: horizontally scaled HTTP/API service.

- **Kubernetes mapping:** `Deployment` + `Service` + `Ingress` (path-based routing).
- **Readiness semantics:** traffic should not flow until readiness passes.
- **Scaling signals:** CPU-backed HPA; optional request-concurrency hints are carried as metadata.

Non-goals:

- traffic splitting between revisions (canary/blue-green) as part of the OSS Kubernetes lane.

#### `partitioned-consumer`

Goal: consumer group processing events from a bus (Kafka/AMQP/etc.).

- **Kubernetes mapping:** `Deployment`.
- **Scaling signals:** CPU-backed HPA; lag/depth-based scaling via KEDA when configured.
- **Capacity guardrails:** max replicas and stabilization windows are required to avoid thrash.
- **Lag scaling contract:** when `autoscaling.consumer_lag` is present, the platform emits a KEDA `ScaledObject` of type `kafka`. This requires:
  - KEDA installed on the cluster (CRD `scaledobjects.keda.sh`), and
  - a Kubernetes Secret named `sanitize_k8s_name(binding_ref)` that includes bootstrap servers under one of: `bootstrap_servers`, `bootstrapServers`, `bootstrap.servers`.

Non-goals:

- partition assignment enforcement by the platform (the consumer runtime owns assignment).

#### `singleton-orchestrator`

Goal: exactly one active orchestrator per service/environment, with safe failover.

- **Kubernetes mapping:** `Deployment` with replicas ≥ 2 **plus** a Kubernetes `Lease` used for leader election.
- **Platform responsibility:** create/attach the `Lease` and RBAC needed for a pod to participate in leader election, and surface the observed leader in status when the `Lease` is being updated.
- **Leader-election contract:** the workload is expected to honor:
  - `X07_LEADER_ELECTION_ENABLED=true`
  - `X07_LEADER_ELECTION_LEASE_NAME=<lease>`
  - `X07_K8S_LEASE_NAMESPACE=<namespace>`

Non-goals:

- enforcing leader behavior for arbitrary container images (the workload runtime must honor the leader-election contract).

#### `leased-worker`

Goal: a pool of workers where work ownership is modeled as a finite set of leases (no double-processing).

- **Kubernetes mapping:** `Deployment` plus a deterministic set of `Lease` objects.
- **Platform responsibility:** create the `Lease` objects and RBAC, and surface lease holder/renewal summary in status.
- **Lease pool contract:** the workload is expected to honor:
  - `X07_WORK_LEASES_ENABLED=true`
  - `X07_WORK_LEASE_NAMES=<comma-separated lease names>`
  - `X07_K8S_LEASE_NAMESPACE=<namespace>`

Non-goals:

- implementing the work protocol itself (the workload must claim/renew leases).

#### `burst-batch`

Goal: scheduled or on-demand batch jobs with idempotency and recovery hooks.

- **Kubernetes mapping:** `CronJob` for scheduled runs.
- **Recovery contract:** each run is assigned a deterministic `run_id` (and a derived `checkpoint_key`) that the workload uses to dedupe and resume safely.
  - `X07_JOB_RUN_ID` is derived from the Kubernetes job name.
  - `X07_JOB_CHECKPOINT_KEY` is derived from `LP_DEPLOYMENT_ID` + `X07_JOB_RUN_ID`.

Non-goals:

- a general-purpose workflow engine in the OSS Kubernetes lane.

#### `embedded-kernel`

Goal: execute an embedded-kernel artifact where the kernel/runtime is packaged in a specialized form.

- **Kubernetes mapping:** depends on the produced artifact; the first supported mapping is intentionally narrow and documented alongside the artifact type.

## Consequences

- The platform may reject unsupported combinations (for example: missing leader-election config for `singleton-orchestrator`).
- Operators get a stable mental model: “class → resources → scaling signals → status”.
- New classes must be added deliberately (ADR + contract updates + tests).
