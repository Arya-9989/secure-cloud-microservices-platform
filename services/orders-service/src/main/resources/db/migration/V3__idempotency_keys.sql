-- Idempotency-Key support for POST /api/v1/orders (docs/adr/0003-idempotency-keys.md).
--
-- The primary key is what makes duplicates safe: a second INSERT of the same
-- (customer, key) waits for the first transaction and then sees its row. A key is
-- claimed, its order placed and its response stored in one transaction, so a row
-- without a response is never visible to another transaction.
CREATE TABLE idempotency_keys (
    customer_id      VARCHAR(64)  NOT NULL,
    idempotency_key  VARCHAR(128) NOT NULL,
    request_hash     CHAR(64)     NOT NULL,
    response_status  SMALLINT     CHECK (response_status BETWEEN 200 AND 299),
    response_body    TEXT,
    order_id         UUID         REFERENCES orders (id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ  NOT NULL,
    expires_at       TIMESTAMPTZ  NOT NULL,
    CONSTRAINT idempotency_keys_pk PRIMARY KEY (customer_id, idempotency_key),
    CONSTRAINT idempotency_keys_ttl_ck CHECK (expires_at > created_at),
    CONSTRAINT idempotency_keys_response_ck
        CHECK ((response_status IS NULL) = (response_body IS NULL))
);

-- The purge job deletes expired keys oldest first.
CREATE INDEX idempotency_keys_expires_idx ON idempotency_keys (expires_at);
