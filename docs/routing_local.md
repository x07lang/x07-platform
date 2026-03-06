# Routing

Local routing uses a single public listener per deployment execution.

Routing queries flow through `lp.adapters.routing_v1` and `lp.impl.routing.devserver_v1`.

Requests are split deterministically by hashing `X-LP-Route-Key` into 100 buckets and comparing the bucket to `candidate_weight_pct`.

Routing state is reflected in:
- `lp.deploy.execution.meta.local@0.1.0`
- the derived query/index views returned by `deploy query`
