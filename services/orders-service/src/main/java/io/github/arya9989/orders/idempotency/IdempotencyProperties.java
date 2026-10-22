package io.github.arya9989.orders.idempotency;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Idempotency keys for {@code POST /api/v1/orders} (docs/adr/0003-idempotency-keys.md).
 *
 * @param ttl how long a key and its stored response are kept; a retry after this places a new order
 * @param lockTimeout how long a duplicate waits for the request that first used its key before it
 *     gets 409 (the first request is still running)
 * @param purgeInterval pause between runs of the job that deletes expired keys
 * @param purgeBatchSize expired keys deleted per statement
 */
@Validated
@ConfigurationProperties("platform.orders.idempotency")
public record IdempotencyProperties(
    @NotNull @DefaultValue("24h") Duration ttl,
    @NotNull @DefaultValue("5s") Duration lockTimeout,
    @NotNull @DefaultValue("10m") Duration purgeInterval,
    @Min(1) @Max(10_000) @DefaultValue("1000") int purgeBatchSize) {

  public IdempotencyProperties {
    if (ttl.isNegative() || ttl.isZero()) {
      throw new IllegalArgumentException("platform.orders.idempotency.ttl must be positive");
    }
    if (lockTimeout.toMillis() < 1) {
      throw new IllegalArgumentException(
          "platform.orders.idempotency.lock-timeout must be at least 1ms");
    }
  }
}
