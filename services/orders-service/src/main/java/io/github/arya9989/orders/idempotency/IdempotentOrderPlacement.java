package io.github.arya9989.orders.idempotency;

import io.github.arya9989.orders.idempotency.IdempotencyKeyStore.StoredResponse;
import io.github.arya9989.orders.order.OrderDtos.CreateOrderRequest;
import io.github.arya9989.orders.order.OrderDtos.OrderResponse;
import io.github.arya9989.orders.order.OrderService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

/**
 * Places an order at most once per {@code (customer, Idempotency-Key)}.
 *
 * <p>The key is claimed, the order placed and its response stored in one transaction (see {@link
 * IdempotencyKeyStore#claim}). A retry with the same key and the same request gets the stored
 * response back; with a different request it is rejected; while the first request is still running
 * it waits for at most {@code lock-timeout} and is then told to retry.
 */
@Service
public class IdempotentOrderPlacement {

  private static final Logger log = LoggerFactory.getLogger(IdempotentOrderPlacement.class);
  private static final String OPERATION = "POST /api/v1/orders\n";

  /** PostgreSQL's lock_not_available: a statement waited longer than lock_timeout. */
  static final String LOCK_TIMEOUT_SQLSTATE = "55P03";

  /** The order, and whether it is a replay of an earlier response. */
  public record Result(OrderResponse order, boolean replayed) {}

  private final OrderService orders;
  private final IdempotencyKeyStore store;
  private final IdempotencyProperties properties;
  private final EntityManager entityManager;
  private final JsonMapper json;
  private final Clock clock;
  private final Counter created;
  private final Counter replayed;
  private final Counter mismatched;
  private final Counter inProgress;

  IdempotentOrderPlacement(
      OrderService orders,
      IdempotencyKeyStore store,
      IdempotencyProperties properties,
      EntityManager entityManager,
      JsonMapper json,
      Clock clock,
      MeterRegistry meters) {
    this.orders = orders;
    this.store = store;
    this.properties = properties;
    this.entityManager = entityManager;
    this.json = json;
    this.clock = clock;
    this.created = outcome(meters, "created");
    this.replayed = outcome(meters, "replayed");
    this.mismatched = outcome(meters, "mismatch");
    this.inProgress = outcome(meters, "in_progress");
  }

  private static Counter outcome(MeterRegistry meters, String outcome) {
    return Counter.builder("orders.idempotency.requests")
        .description("Order requests that carried an Idempotency-Key, by outcome")
        .tag("outcome", outcome)
        .register(meters);
  }

  @Transactional
  public Result place(String customerId, @Nullable IdempotencyKey key, CreateOrderRequest request) {
    if (key == null) {
      return new Result(orders.place(customerId, request), false);
    }
    String fingerprint = fingerprint(request);
    Instant now = clock.instant();
    boolean claimed;
    try {
      store.limitLockWait(properties.lockTimeout());
      claimed = store.claim(customerId, key.value(), fingerprint, now, now.plus(properties.ttl()));
    } catch (DataAccessException e) {
      if (!isLockTimeout(e)) {
        throw e;
      }
      // The request that first used this key has not committed yet.
      inProgress.increment();
      throw new IdempotencyKeyInProgressException();
    }

    if (!claimed) {
      StoredResponse stored =
          store
              .find(customerId, key.value())
              .orElseThrow(() -> new IllegalStateException("claimed key without a response"));
      if (!MessageDigest.isEqual(bytes(stored.requestHash()), bytes(fingerprint))) {
        mismatched.increment();
        throw new IdempotencyKeyReusedException();
      }
      replayed.increment();
      log.atInfo()
          .addKeyValue("order_id", stored.orderId())
          .log("Replayed order response for a repeated Idempotency-Key");
      return new Result(json.readValue(stored.body(), OrderResponse.class), true);
    }

    OrderResponse order = orders.place(customerId, request);
    entityManager.flush(); // the stored response references the new order row
    store.complete(
        customerId,
        key.value(),
        HttpStatus.CREATED.value(),
        json.writeValueAsString(order),
        order.id());
    created.increment();
    return new Result(order, false);
  }

  /**
   * SHA-256 over the operation and the canonical JSON of the <em>parsed</em> request, so formatting
   * and field order do not matter but any change to the lines does.
   */
  String fingerprint(CreateOrderRequest request) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(OPERATION.getBytes(StandardCharsets.UTF_8));
      sha256.update(json.writeValueAsBytes(request));
      return HexFormat.of().formatHex(sha256.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by every Java platform", e);
    }
  }

  /** Spring does not translate SQLState 55P03, so it is detected on the cause chain. */
  static boolean isLockTimeout(Throwable failure) {
    for (Throwable t = failure; t != null; t = t.getCause()) {
      if (t instanceof SQLException sql && LOCK_TIMEOUT_SQLSTATE.equals(sql.getSQLState())) {
        return true;
      }
    }
    return false;
  }

  private static byte[] bytes(String hex) {
    return hex.getBytes(StandardCharsets.US_ASCII);
  }

  /** The key was used before for a different request (HTTP 422). */
  public static class IdempotencyKeyReusedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    IdempotencyKeyReusedException() {
      super(
          "This Idempotency-Key was already used for a different request."
              + " Use a new key for a new order.");
    }
  }

  /** The request that first used the key is still being processed (HTTP 409). */
  public static class IdempotencyKeyInProgressException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    IdempotencyKeyInProgressException() {
      super("A request with this Idempotency-Key is still being processed. Retry shortly.");
    }
  }
}
