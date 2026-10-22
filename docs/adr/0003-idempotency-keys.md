# 0003. Idempotency keys for placing orders

- Status: accepted
- Date: 2026-10-23

## Context

`POST /api/v1/orders` isn't idempotent. A client whose request times out can't tell whether the order was placed, and retrying can place it twice. That happens with mobile networks, gateway timeouts and client retry policies alike. We follow the IETF draft *The Idempotency-Key HTTP Header Field* (draft-ietf-httpapi-idempotency-key-header): the client sends a unique key per logical operation and may retry with it safely.

Requirements: keys are scoped to the caller; reusing a key for a different request is an error (422); concurrent duplicates must yield exactly one order; the original response is replayed; and keys expire.

## Options considered

1. **Check, then insert** (`SELECT` the key; if it's absent, place the order and insert the key). This races: two concurrent requests both see no key and both place an order.
2. **Advisory lock per key** (`pg_advisory_xact_lock(hash(customer, key))`). It's correct, but the uniqueness guarantee lives in application code and a hash collision serialises unrelated keys.
3. **Place the order, insert the key, and roll back on a unique violation.** Correct too, but every duplicate does the full work and is resolved through an exception that aborts the transaction.
4. **Claim the key first, with the primary key as the lock.** `INSERT … ON CONFLICT (customer_id, idempotency_key) DO UPDATE … WHERE expired RETURNING`, in the same transaction that places the order and stores the response. PostgreSQL makes a second insert of the same key *wait* for the first transaction:
   - if that transaction commits, the conflict resolves to "already exists" and the stored response is replayed;
   - if it rolls back (for example, a 422 for an unknown SKU), the waiter claims the key and runs the request itself.

## Decision

Option 4.

- **Table `idempotency_keys`:**
  - primary key `(customer_id, idempotency_key)`, where the customer is the token's `sub`, so keys are per principal and one customer can't probe or replay another's;
  - the request fingerprint (`SHA-256` of the method, path and canonical JSON of the *parsed* request, so whitespace and field order don't matter);
  - the response status and body, the order id, `created_at` and `expires_at`.

  Claim, order and stored response commit together, so no other transaction ever sees a claimed key without its response.
- **Header:** `Idempotency-Key` is optional. It's 8–128 characters of `[A-Za-z0-9._:-]`, either bare or as a structured-field string (`"…"`). A malformed key gets a `400`.
- **Outcomes:**
  - first use: the order is placed and `201` returned (the response is stored);
  - same key, same request: the stored `201` is replayed with the original order id and `Location`, plus `Idempotent-Replayed: true`;
  - same key, different request: `422`;
  - a duplicate still waiting after `lock-timeout` (default 5 s, `SET LOCAL lock_timeout`) because the first request hasn't finished: `409` with `Retry-After: 1`, as the draft recommends for in-flight requests.
- **Only successful responses are stored.** A request that fails validation leaves no key behind, so the client can fix the request and retry with the same key.
- **TTL:** 24 hours by default (`PLATFORM_ORDERS_IDEMPOTENCY_TTL`). The claim takes over an *expired* row in place, so an old key can be reused after the TTL, and a scheduled job deletes expired rows in batches. Replays return the response as it was then, even if the order was cancelled since. That's the point of a replay.

## Consequences

- A duplicate costs one indexed insert attempt and one primary-key read. The happy path adds one insert and one update to the order's transaction.
- A waiting duplicate holds a database connection for at most the lock timeout. With the pool at 10 connections, a burst of in-flight duplicates of one key can briefly crowd out other requests. The lock timeout bounds that.
- Clients that never send the header keep today's behaviour.
