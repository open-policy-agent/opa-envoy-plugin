#!/usr/bin/env bash
# This script is used to generate TLS certs that can be used with opa-envoy-plugin built
# with Go 1.15+. (That version of Go declines CN=<domain name> for server identification,
# but requires proper SNI settings, using subjectAltName (SAN).
#
# After running the script, the output of `base64 opa-envoy.crt` and `base64 opa-envoy.key`
# need to be pasted into examples/istio/quick_start.yaml:
# - The cert and key goes into tls.crt and tls.key of the server-cert Secret,
# - The cert also goes into clientConfig.caBundle of the webhook 'opa-istio-admission-controller'.

cat > v3.txt <<- EOF
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
extendedKeyUsage = serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName = DNS:admission-controller.opa-istio.svc
EOF

openssl req -x509 \
  -subj "/CN=OPA Envoy plugin" \
  -nodes \
  -newkey rsa:4096 \
  -days 1826 \
  -keyout root.key \
  -out root.crt
openssl genrsa -out opa-envoy.key 4096
openssl req -new \
  -key opa-envoy.key \
  -subj "/CN=opa-envoy" \
  -reqexts SAN \
  -config <(cat /etc/ssl/openssl.cnf \
      <(printf "\n[SAN]\nsubjectAltName=DNS:admissin-controller.opa-istio.svc")) \
  -sha256 \
  -out opa-envoy.csr
openssl x509 -req \
  -extfile v3.txt \
  -CA root.crt \
  -CAkey root.key \
  -CAcreateserial \
  -days 1825 \
  -sha256 \
  -in opa-envoy.csr \
  -out opa-envoy.crt

rm v3.txt opa-envoy.csr root.key root.srl
