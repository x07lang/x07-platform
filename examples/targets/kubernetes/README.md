# Kubernetes Target Profile Example

This directory contains a reference `lp.target.profile@0.1.0` document for a Kubernetes-backed control-plane attachment.

The profile keeps the same remote control-plane boundary as the existing OSS target:

- `base_url` points at the target control plane
- `auth.token_ref` resolves a bearer token used for the remote API
- `runtime_provider` and `routing_provider` advertise Kubernetes-specific adapters
- `cluster_ref` and `default_namespace` identify the destination cluster scope

The example is intentionally provider-neutral. It does not assume a specific ingress controller, GitOps system, or cluster vendor. Adjust the provider ids, OCI registry, and TLS inputs to match the control plane you attach.

Import the profile with:

```bash
./scripts/x07lp-driver target add --profile examples/targets/kubernetes/target.example.json
```

## Local K3s path

For local development on macOS or Linux with Docker, use K3s through `k3d` and expose the ingress loadbalancer on a host port:

```bash
k3d cluster create x07lp --agents 1 -p 8081:80@loadbalancer
kubectl config current-context
kubectl get ingressclass
```

The local target profile still uses the public `lp.target.profile@0.1.0` shape, so it keeps `base_url` and `auth.token_ref` even though the current OSS workload lane talks to Kubernetes directly rather than a separate remote API. A minimal local profile looks like:

```json
{
  "schema_version": "lp.target.profile@0.1.0",
  "name": "k3s-local",
  "kind": "k8s",
  "base_url": "http://127.0.0.1:8081",
  "api_version": "v1",
  "auth": {
    "kind": "static_bearer",
    "token_ref": "file:///tmp/x07lp-k3s-config/tokens/k3s-local.token"
  },
  "tls": {
    "mode": "system"
  },
  "runtime_provider": "lp.impl.runtime.k8s_v1",
  "routing_provider": "lp.impl.routing.k8s_ingress_v1",
  "cluster_ref": "k3d-x07lp",
  "default_namespace": "x07-local"
}
```

Then run the local workload smoke:

```bash
bash scripts/ci/workload-k3s-smoke.sh
```

Or use the target-suite entrypoint:

```bash
bash scripts/ci/target-conformance.sh k8s
```

Or drive it manually:

```bash
./scripts/x07lp-driver target-add --profile /tmp/x07lp-k3s.target.json
./scripts/x07lp-driver target-use --name k3s-local
./scripts/x07lp-driver workload accept --pack-manifest /tmp/workload/workload.pack.json --target k3s-local --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload run --workload svc_api_cell_v1 --target k3s-local --profile prod --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload query --workload svc_api_cell_v1 --target k3s-local --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload stop --workload svc_api_cell_v1 --target k3s-local --state-dir /tmp/x07lp-state
```
