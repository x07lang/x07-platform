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
