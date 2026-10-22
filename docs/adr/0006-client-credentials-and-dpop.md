# 0006. Client credentials with DPoP-bound tokens for service-to-service calls

- Status: accepted
- Date: 2026-10-23

## Context

Only people can call the APIs today: tokens come from a password login and carry a user's roles. A warehouse (fulfilment) system needs to move orders to `SHIPPED` and `DELIVERED` without a human account, and without the power of an administrator. Bearer tokens have a known weakness for machine credentials, which tend to sit in logs, proxies and crash dumps: whoever holds one can use it. We want the token bound to a key the client keeps, so a leaked token alone is useless.

## Options considered

1. **OAuth 2.0 client credentials (RFC 6749 §4.4) issuing plain bearer tokens.** Simple, but a stolen token is as good as the client.
2. **mTLS-bound tokens (RFC 8705).** The token carries the thumbprint of the client certificate, and the resource server compares it with the TLS session. Here TLS terminates at Traefik, so orders-service never sees the handshake. The gateway would have to verify the client certificate and forward it in a header, which orders-service must trust. That adds a client PKI and a header-trust boundary, and the binding lives in infrastructure that isn't otherwise needed.
3. **DPoP (RFC 9449).** The client signs a small JWT for every request with its own key. The token carries the key's thumbprint (`cnf.jkt`), and the server checks that the proof matches the token, the method and the URL, is fresh, isn't replayed and carries a server nonce. It works through any number of TLS-terminating proxies because the binding is in the application layer, and Spring Security 7.1 verifies DPoP proofs natively.

## Decision

DPoP, implemented on both sides.

- **auth-service (authorization server):**
  - `POST /api/v1/auth/oauth/token`, `grant_type=client_credentials`, form-encoded.
  - Client authentication is HTTP Basic (`client_secret_basic`). Secrets are stored as Argon2 hashes, and an unknown client costs the same hash as a wrong secret, so timing doesn't reveal which client ids exist.
  - Clients are rows in `OAuthClient`: scopes from a catalogue that's disjoint from user scopes (today only `orders:fulfil`), allowed audiences (RFC 8707 `resource`) and `require_dpop` (default on).
  - The DPoP proof is checked: `typ`, an asymmetric `alg`, a public-only `jwk`, the signature, `htm`/`htu`, `iat` within 60 s, a server nonce (`use_dpop_nonce` + `DPoP-Nonce` when it's missing or stale) and `jti` replay, through the shared database cache, so all workers and replicas see every proof.
  - Tokens last 5 minutes, carry `client_id`, `scope`, `aud` = the requested resource and `cnf.jkt`, and have no refresh token. Errors use the RFC 6749 §5.2 JSON shape.
- **orders-service (resource server):**
  - Spring Security's DPoP support, with the proof validators replaced: `jti` replay in PostgreSQL (`dpop_proof_jti`, shared by every replica), `iat` within 60 s, and a stateless HMAC nonce (shared secret `PLATFORM_SECURITY_DPOP_NONCE_SECRET`, valid for the current and previous window). A missing or stale nonce is answered with `401`, `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce`.
  - A DPoP-bound token presented as `Bearer` is rejected (RFC 9449 §7.1: no downgrade).
  - Audience: tokens must be for the platform API (user tokens) or for this resource (`urn:secure-platform:orders-service`). The fulfilment API requires *all* of: scope `orders:fulfil`, this resource as audience, and a DPoP-bound token. Customer and admin APIs require a token issued to a person (it carries `roles`), so a client token can't act as a customer whatever its scopes.
  - The access-token decoder now accepts only `typ` `JWT`, `at+jwt` or none. Spring's default checks no type at all, so in principle a DPoP proof (`dpop+jwt`) signed by a key in the JWKS could have been accepted as an access token.
  - New endpoints: `GET /api/v1/fulfilment/orders?status=CONFIRMED` (the work queue) and `PATCH /api/v1/fulfilment/orders/{id}/status` (only `SHIPPED` or `DELIVERED`, following the existing state machine).
- **Bootstrap:** `ensure_oauth_client` (idempotent, like `bootstrap_admin`) creates the `fulfilment` client in compose from `FULFILMENT_CLIENT_SECRET`, which `init_env.py` generates.

## Consequences

- A stolen fulfilment token is useless without the client's private key. A stolen proof works for one method, one URL and under a minute, and only once.
- Every DPoP request costs one signature verification and one insert into the `jti` table, which is purged on a schedule. That's acceptable for machine traffic; user traffic is unchanged.
- The first call after a nonce rotation (every 5 minutes) takes one extra round trip (`use_dpop_nonce`, then retry). That's how RFC 9449 nonces work, and the client helper handles it.
- mTLS-bound tokens remain possible later for clients that already hold certificates. The resource metadata advertises `tls_client_certificate_bound_access_tokens: false` honestly until then.
