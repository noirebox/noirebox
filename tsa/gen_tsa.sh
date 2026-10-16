#!/usr/bin/env bash
# Generates the NoireBox local TSA material (RFC 3161 via OpenSSL).
#
# Two-certificate chain (the setup OpenSSL requires):
#   - self-signed root (CA:TRUE)  → the trust anchor
#   - TSA leaf (CA:FALSE, EKU TimeStamping) → the token signer
# Root + leaf are served together (bundle): `openssl ts -verify`
# consumes them as-is (-CAfile bundle -untrusted bundle).
#
# TOFU model documented in ADR 006: the bundle travels inside every anchor;
# a serious deployment pins it on the verifier side.
#
# Usage: ./tsa/gen_tsa.sh <directory>
set -euo pipefail
DIR="${1:-tsa/material}"
mkdir -p "$DIR"

if [ -f "$DIR/tsa_cert.pem" ]; then
  echo "[=] TSA already generated in $DIR — nothing to do."
  exit 0
fi

# 1. Root (self-signed CA)
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$DIR/root.key" -out "$DIR/root.pem" \
  -subj "/O=NoireBox Local TSA/CN=NoireBox TSA Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  >/dev/null 2>&1

# 2. TSA leaf (CA:FALSE + EKU TimeStamping) signed by the root
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/tsa.key" -out "$DIR/tsa.csr" \
  -subj "/O=NoireBox Local TSA/CN=NoireBox TSA Signer" \
  >/dev/null 2>&1
openssl x509 -req -in "$DIR/tsa.csr" \
  -CA "$DIR/root.pem" -CAkey "$DIR/root.key" -CAcreateserial -days 3650 \
  -out "$DIR/tsa_cert.pem" \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n") \
  >/dev/null 2>&1

# 3. Root + leaf bundle: served by /cert, embedded in the anchors
cat "$DIR/root.pem" "$DIR/tsa_cert.pem" > "$DIR/tsa_bundle.pem"

# 4. Config for the openssl ts -reply responder
cat > "$DIR/tsa.conf" <<EOF
[tsa]
default_tsa = tsa_config1
[tsa_config1]
dir = $DIR
serial = $DIR/tsa.srl
signer_cert = $DIR/tsa_cert.pem
signer_key = $DIR/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.57556.1
digests = sha1, sha256, sha384, sha512
crypto_device = builtin
chain = $DIR/root.pem
EOF

echo "[✓] TSA generated: root + leaf + bundle in $DIR"
echo "    → Start the server:  .venv/bin/python tsa/tsa_server.py --material $DIR --port 3318"
