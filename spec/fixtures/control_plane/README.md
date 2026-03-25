# Control-plane fixture set

This fixture set is the first-pass CI/golden surface for the control-plane additions:

- incident capture (`incident capture`, `incident list`, `incident get`)
- regression generation (`regress from-incident`)
- app list (`app list`)
- manual controls (`deploy pause`, `deploy rerun`, `app kill`, `app unkill`, `platform kill`, `platform unkill`)
- UI/API smoke (`x07lp-driver ui-serve` serving `/api/apps` and `/api/incidents/:incident_id`)

Templates under `expected/` use `__ANY__` placeholders and are meant for the wildcard matcher
already used by `scripts/ci/deploy_loop.sh`.
