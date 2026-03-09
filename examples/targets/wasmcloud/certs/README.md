# Dev TLS Material

Run `../scripts/gen-dev-cert.sh` from this directory's parent to generate the local CA and leaf certificate used by the reference stack.

Generated files land in `certs/out/`:

- `dev-ca.pem`
- `dev-ca.key.pem`
- `dev-cert.pem`
- `dev-cert.key.pem`

Only the PEM certificates are meant to be shared with clients. Keep the key files local and uncommitted.
