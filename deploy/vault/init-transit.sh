#!/bin/sh
# One-shot setup of Vault transit for auth-service (compose profile `kms`, ADR 0007).
# Idempotent: safe to run on every `docker compose up`.
#
#   - transit key `auth-jwt` (RSA 3072, not exportable), rotated by Vault every 30 days
#   - policy `auth-signer`: read the key's public versions and sign, nothing else
#     (it cannot rotate, export, delete or reconfigure the key)
#   - a periodic token with only that policy, written to /keys/vault-token (0400),
#     which auth-service reads; it renews the token itself
set -eu

: "${VAULT_ADDR:?}" "${VAULT_TOKEN:?}"
KEY="${JWT_VAULT_KEY:-auth-jwt}"
TOKEN_FILE="${TOKEN_FILE:-/keys/vault-token}"

vault secrets list -format=json | grep -q '"transit/"' || vault secrets enable transit
if ! vault read -format=json "transit/keys/${KEY}" >/dev/null 2>&1; then
  vault write -f "transit/keys/${KEY}" type=rsa-3072 exportable=false
fi
vault write "transit/keys/${KEY}/config" auto_rotate_period="${AUTO_ROTATE_PERIOD:-720h}" >/dev/null

vault policy write auth-signer - <<POLICY
path "transit/keys/${KEY}" { capabilities = ["read"] }
path "transit/sign/${KEY}/*" { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
POLICY

umask 077
vault token create -policy=auth-signer -orphan -period=24h -field=token > "${TOKEN_FILE}.tmp"
mv "${TOKEN_FILE}.tmp" "${TOKEN_FILE}"
chmod 0400 "${TOKEN_FILE}"
echo "transit key ${KEY} ready; signer token written to ${TOKEN_FILE}"
