#!/bin/sh
# Create a disposable, signed, deterministic Nuclei template for the staged
# acceptance. Runs offline inside the runtime image. The signing identity is a
# throwaway key pair; it is never installed in the image or a user key store, and
# unsigned templates stay refused by the application's -dut policy.
set -eu
out=${1:-/nuclei}
mkdir -p "$out/templates"
cat > "$out/templates/receipt.yaml" <<'TEMPLATE'
id: xalgorix-staged-receipt
info:
  name: Staged lab request receipt
  author: xalgorix
  severity: info
  tags: fixture
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "<title>Lab</title>"
TEMPLATE
work=$(mktemp -d)
openssl ecparam -name prime256v1 -genkey -noout -out "$work/key.pem" 2>/dev/null
openssl req -new -x509 -key "$work/key.pem" -subj "/CN=Xalgorix staged fixture" -days 2 -addext keyUsage=digitalSignature -out "$work/cert.pem" 2>/dev/null
python3 - "$work" "$out" <<'PY'
import re, sys
work, out = sys.argv[1:3]
def relabel(src, old, new, dest):
    text = open(src).read().replace("-----BEGIN %s-----" % old, "-----BEGIN %s-----" % new).replace("-----END %s-----" % old, "-----END %s-----" % new)
    open(dest, "w").write(text)
relabel(work + "/key.pem", "EC PRIVATE KEY", "PD NUCLEI USER PRIVATE KEY", work + "/nuclei-key.pem")
relabel(work + "/cert.pem", "CERTIFICATE", "PD NUCLEI USER CERTIFICATE", out + "/certificate.pem")
PY
NUCLEI_USER_PRIVATE_KEY=$(cat "$work/nuclei-key.pem") NUCLEI_USER_CERTIFICATE=$(cat "$out/certificate.pem") \
  nuclei -t "$out/templates" -sign -duc -ni >/dev/null 2>&1
grep -q '# digest:' "$out/templates/receipt.yaml" || { echo 'template was not signed' >&2; exit 1; }
rm -rf "$work"
echo "signed template ready"
