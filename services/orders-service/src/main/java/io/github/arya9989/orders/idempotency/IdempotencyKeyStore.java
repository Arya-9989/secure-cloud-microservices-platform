package io.github.arya9989.orders.idempotency;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * SQL for {@code idempotency_keys}. Every method runs in the caller's transaction.
 *
 * <p>The claim is a single {@code INSERT … ON CONFLICT DO UPDATE … WHERE expired}: PostgreSQL makes
 * a concurrent insert of the same primary key wait for the transaction holding it, so the primary
 * key serialises duplicates without a check-then-insert race.
 */
@Repository
class IdempotencyKeyStore {

  /** What was stored for a key: the request it belongs to and the response to replay. */
  record StoredResponse(String requestHash, int status, String body, UUID orderId) {}

  private final JdbcClient jdbc;

  IdempotencyKeyStore(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  /** Bounds how long the rest of this transaction waits for row locks (SET LOCAL). */
  void limitLockWait(Duration timeout) {
    jdbc.sql("SELECT set_config('lock_timeout', :timeout, true)")
        .param("timeout", timeout.toMillis() + "ms")
        .query(String.class)
        .single();
  }

  /**
   * Claims {@code key} for this transaction. Returns {@code false} when a live claim exists (the
   * caller replays it); an expired one is taken over in place. Blocks while another transaction
   * holds an uncommitted claim of the same key.
   */
  boolean claim(String customerId, String key, String requestHash, Instant now, Instant expiresAt) {
    return jdbc.sql(
            """
            INSERT INTO idempotency_keys
                (customer_id, idempotency_key, request_hash, created_at, expires_at)
            VALUES (:customer, :key, :hash, :now, :expires)
            ON CONFLICT (customer_id, idempotency_key) DO UPDATE
               SET request_hash = EXCLUDED.request_hash,
                   created_at = EXCLUDED.created_at,
                   expires_at = EXCLUDED.expires_at,
                   response_status = NULL,
                   response_body = NULL,
                   order_id = NULL
             WHERE idempotency_keys.expires_at <= EXCLUDED.created_at
            RETURNING customer_id
            """)
        .param("customer", customerId)
        .param("key", key)
        .param("hash", requestHash)
        .param("now", utc(now))
        .param("expires", utc(expiresAt))
        .query(String.class)
        .optional()
        .isPresent();
  }

  Optional<StoredResponse> find(String customerId, String key) {
    return jdbc.sql(
            """
            SELECT request_hash, response_status, response_body, order_id
              FROM idempotency_keys
             WHERE customer_id = :customer AND idempotency_key = :key
               AND response_body IS NOT NULL
            """)
        .param("customer", customerId)
        .param("key", key)
        .query(
            (rs, row) ->
                new StoredResponse(
                    rs.getString("request_hash"),
                    rs.getInt("response_status"),
                    rs.getString("response_body"),
                    rs.getObject("order_id", UUID.class)))
        .optional();
  }

  void complete(String customerId, String key, int status, String body, UUID orderId) {
    int updated =
        jdbc.sql(
                """
                UPDATE idempotency_keys
                   SET response_status = :status, response_body = :body, order_id = :order
                 WHERE customer_id = :customer AND idempotency_key = :key
                """)
            .param("status", status)
            .param("body", body)
            .param("order", orderId)
            .param("customer", customerId)
            .param("key", key)
            .update();
    if (updated != 1) {
      throw new IllegalStateException("idempotency key vanished inside its own transaction");
    }
  }

  /**
   * Deletes up to {@code limit} expired keys, oldest first. Rows locked by a request taking an
   * expired key over are skipped rather than waited for.
   */
  int purgeExpired(Instant now, int limit) {
    return jdbc.sql(
            """
            DELETE FROM idempotency_keys
             WHERE ctid IN (SELECT ctid FROM idempotency_keys
                             WHERE expires_at <= :now
                             ORDER BY expires_at
                             LIMIT :limit
                               FOR UPDATE SKIP LOCKED)
            """)
        .param("now", utc(now))
        .param("limit", limit)
        .update();
  }

  private static OffsetDateTime utc(Instant instant) {
    return instant.atOffset(ZoneOffset.UTC);
  }
}
