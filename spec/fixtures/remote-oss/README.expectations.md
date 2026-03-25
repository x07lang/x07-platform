# Remote OSS fixture expectations

This directory contains only the **expected outputs** used by the addendum CI script.

The actual scenario inputs continue to come from:
- the existing baseline pack fixture under `spec/fixtures/baseline/pack_min/`
- the unhealthy rollback pack fixture under `spec/fixtures/remote-oss/common/pack_app_min_spin/`
- the existing baseline change request fixture under `spec/fixtures/deploy_loop/common/change_request.app_min.json`
- the live compose-backed wasmCloud stack plus OTLP collector export

## Parity cases

- `remote_promote/` validates successful remote acceptance, run, query, and normalized parity from real candidate telemetry.
- `remote_rollback/` validates rollback semantics from the unhealthy spin workload and real candidate telemetry.
- `remote_pause_rerun/` validates manual pause followed by new execution creation.
- `remote_query/` validates all query views against the same remote execution.
- `remote_query_index_rebuild/` validates that derived query state can be rebuilt from authoritative artifacts.

## Negative cases

- `remote_missing_secret/`
- `remote_upload_digest_mismatch/`
- `remote_capabilities_mismatch/`
- `remote_lease_conflict/`
- `remote_incident_trace_missing/`

## Capability handshake

- `remote_capabilities/expected/v1.capabilities.json` is the template for `GET /v1/capabilities`.
