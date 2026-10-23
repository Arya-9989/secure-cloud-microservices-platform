# 0007. Signing keys in a KMS (Vault transit) with automated, overlap-safe rotation

- Status: accepted
- Date: 2026-10-23

## Context

auth-service signs every access token with an RSA private key read from a file (a Docker volume, or a Kubernetes Secret). Anyone who can read that file or the pod's memory can mint tokens for any user, offline and forever. Rotation is manual: generate a key, publish the old public key with `JWT_ADDITIONAL_PUBLIC_KEY_FILES`, switch, and remove it later. A mistake in the order of those steps invalidates every token in circulation, or keeps a retired key trusted indefinitely.

## Options considered

1. **Keep the file, automate rotation with a CronJob.** It still exposes the private key to the process and to anyone with access to the Secret.
2. **Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault).** The key never leaves the HSM-backed service and signing is an API call. Using it needs a cloud account, so it isn't testable here without credentials. 🔑
3. **HashiCorp Vault transit.** The same model (sign through an API, keys never exportable, versioned keys with `rotate` and `auto_rotate_period`), it runs locally in dev mode for compose and CI, and it's widely used on-premises.

## Decision

Vault transit as the reference KMS, behind a small signer interface, so a cloud KMS is a new class rather than a redesign.

- **`Signer` interface** (`accounts/kms.py`): a `kid` plus `sign(message) -> signature`.
  - `LocalSigner` is today's PEM file, still the default.
  - `VaultTransitSigner` calls `POST /v1/transit/sign/<key>/sha2-256` with `pkcs1v15` and an explicit `key_version`.

  Tokens are assembled by auth-service (header, payload, signature), so PyJWT never needs the private key. The `kid` stays the RFC 7638 thumbprint of the version's public key.
- **Overlap-safe rotation**, worked out from the key versions Vault reports (`creation_time` per version). This is the part that makes rotation safe to automate:
  1. **Publish before use.** A new version appears in the JWKS immediately but signs only after `JWT_KEY_PUBLISH_AHEAD_SECONDS` (default 360 s: longer than a resource server's 5-minute JWKS cache plus the 30 s key-set refresh). By then every cache has seen it. (orders-service would cope anyway, because an unknown `kid` triggers a refetch, but other consumers may not.)
  2. **Retire after expiry.** A version that stopped signing at time *T* stays in the JWKS until *T* + the longest token lifetime + clock skew + a minute's margin. Every token it signed has expired by then.
  3. When no version is old enough yet (a brand-new key), the oldest one signs, so bootstrap never stalls.

  Together: **no token issued before a rotation fails verification after it**, and no key is trusted longer than needed. The function is pure (versions, now, settings) and unit-tested across a full timeline.
- **Automation:** Vault rotates the key itself (`auto_rotate_period`, 30 days in the compose setup). `manage.py rotate_signing_key` rotates on demand (for example after an incident), and `--show` prints which version signs and which are published and until when.
- **Cut-over from a file key** (the role of `JWT_ADDITIONAL_PUBLIC_KEY_FILES`): compose always publishes the PEM key's public half. When `JWT_SIGNER=vault` is switched on, tokens signed by the file key keep verifying until they expire.
- **Least privilege:** the Vault token auth-service uses only has `read` on `transit/keys/auth-jwt` and `update` on `transit/sign/auth-jwt/*`. It can't rotate, export or delete the key; rotation uses a separate admin token. The token is read from a file (`VAULT_TOKEN_FILE`), never an environment variable.
- **Failure handling:** Vault calls have a 2 s timeout and two retries with backoff. If Vault is unreachable, the last good key set keeps serving the JWKS (verification is unaffected), and issuing tokens answers `503` with `Retry-After` instead of `500`.
- **Compose:** profile `kms` (Vault dev mode plus a one-shot `vault-init` that creates the key, the policy and the token), switched on with `JWT_SIGNER=vault`. Dev mode keeps everything in memory, which is fine for local and CI use only.

## Consequences

- The private key never exists in auth-service's process, image, volume or Secret. Minting a token requires a live, audited call to Vault.
- Every token issuance costs one Vault round trip (about a millisecond locally). Key-set reads are cached for 30 s.
- **AWS KMS (documented, not implemented 🔑):** an `AwsKmsSigner` would call `kms:Sign` with `RSASSA_PKCS1_V1_5_SHA_256` on an RSA_3072 key, use `GetPublicKey` for the JWKS, and use key aliases for rotation (AWS doesn't rotate asymmetric keys automatically, so the "versions" would be successive keys behind an alias, fed to the same planner). It needs an AWS account and credentials, so it isn't built or claimed here.
