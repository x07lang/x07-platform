# Query

`deploy query` supports two resolution modes:

- `--deployment-id <exec_id>`
- `--app-id <id> --env <env> --latest`

Views:
- `summary`
- `timeline`
- `decisions`
- `artifacts`
- `full`

The result schema is `lp.deploy.query.result@0.1.0`.
The full view embeds a normalized `lp.deploy.execution@0.1.0` document and uses the derived SQLite index under the state directory.

Query resolution flows through `lp.engine.deploy_run_v1`, with routing, metrics, and index reads delegated to the corresponding adapter modules.

Query validation and derived-index failures use stable diagnostics:

- `LP_QUERY_INVALID`
- `LP_DECISION_INDEX_ERROR`
