#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/examples/targets/wasmcloud/certs/out}"

CA_KEY="$OUT_DIR/dev-ca.key.pem"
CA_CERT="$OUT_DIR/dev-ca.pem"
LEAF_KEY="$OUT_DIR/dev-cert.key.pem"
LEAF_CSR="$OUT_DIR/dev-cert.csr.pem"
LEAF_CERT="$OUT_DIR/dev-cert.pem"
LEAF_EXT="$OUT_DIR/dev-cert.ext"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

openssl req \
  -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days 3650 \
  -nodes \
  -subj "/CN=x07lp wasmcloud dev ca" \
  -keyout "$CA_KEY" \
  -out "$CA_CERT" >/dev/null 2>&1

cat >"$LEAF_EXT" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
DNS.2=gateway
IP.1=127.0.0.1
EOF

openssl req \
  -new \
  -newkey rsa:4096 \
  -nodes \
  -subj "/CN=x07lp wasmcloud gateway" \
  -keyout "$LEAF_KEY" \
  -out "$LEAF_CSR" >/dev/null 2>&1

openssl x509 \
  -req \
  -in "$LEAF_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -days 825 \
  -sha256 \
  -extfile "$LEAF_EXT" \
  -out "$LEAF_CERT" >/dev/null 2>&1

chmod 600 "$CA_KEY" "$LEAF_KEY"
chmod 644 "$CA_CERT" "$LEAF_CERT"
rm -f "$LEAF_CSR" "$LEAF_EXT" "$OUT_DIR/dev-ca.srl"

PIN_HEX="$(
  openssl x509 -in "$LEAF_CERT" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | xxd -p -c 256
)"

printf 'generated dev CA: %s\n' "$CA_CERT"
printf 'generated gateway cert: %s\n' "$LEAF_CERT"
printf 'pinned_spki_sha256=sha256:%s\n' "$PIN_HEX"
