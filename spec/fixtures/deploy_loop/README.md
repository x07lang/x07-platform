# Phase B fixtures

This fixture set drives the Phase B CI gate for deterministic local progressive delivery.

Required scenarios:

- `promote/` - candidate passes SLO checks and is promoted
- `rollback/` - candidate fails SLO checks and is rolled back
- `retry_exhausted/` - analysis remains inconclusive until retry budget is exhausted
- `stop_during_pause/` - deployment is stopped while a pause step is active and ends as aborted
- `query/` - summary / timeline / decisions / artifacts / full queries work over the derived SQLite index

Common rules:

- all scenarios pin `--now-unix-ms`
- routed requests set `X-LP-Route-Key`
- all reports are `lp.cli.report@0.1.0`
- all report templates use `"__ANY__"` as a wildcard for dynamic ids, digests, ports, and version strings
- promote / rollback / retry / query run with `--pause-scale 0`
- stop_during_pause uses a small positive pause scale so the CI script can issue `deploy stop` while a pause step is active
