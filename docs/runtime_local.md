# Runtime

The local runtime starts supervised `x07-wasm app serve` processes for `stable` and `candidate` slots under the deployment state directory.

Runtime requests flow through `lp.adapters.runtime_v1` and `lp.impl.runtime.wasmtime_v1`.

State is materialized under:
- `.x07lp/runtime/<exec_id>/stable/`
- `.x07lp/runtime/<exec_id>/candidate/`

Runtime details are surfaced through `lp.deploy.execution.meta.local@0.1.0`:
- target app/environment
- slot revisions
- public listener
- runtime slot status and health
