# Phase D-OSS fixture expectations

This directory contains only the **expected outputs** used by the addendum CI script.

The actual scenario inputs continue to come from:
- the existing Phase A pack fixture (`spec/fixtures/phaseA/pack_min/`)
- the existing Phase B change request fixture (`spec/fixtures/phaseB/common/change_request.app_min.json`)
- the remote stack's seeded runtime/router/incident fixture state

## Parity cases

- `remote_promote/` validates successful remote acceptance, run, query, and normalized parity.
- `remote_rollback/` validates rollback semantics.
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
