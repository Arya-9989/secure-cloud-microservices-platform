package io.github.arya9989.orders.idempotency;

import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Deletes expired idempotency keys every {@code purge-interval}, in batches, so the table stays the
 * size of one TTL's worth of orders. Replicas may run it concurrently: each batch skips rows
 * another transaction has locked, and deleting an already deleted row is a no-op.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class IdempotencyKeyPurger implements SchedulingConfigurer {

  private static final Logger log = LoggerFactory.getLogger(IdempotencyKeyPurger.class);

  /** Upper bound on batches per run, so one run cannot monopolise a connection. */
  static final int MAX_BATCHES_PER_RUN = 100;

  private final IdempotencyKeyStore store;
  private final IdempotencyProperties properties;
  private final TransactionTemplate transactions;
  private final Clock clock;

  IdempotencyKeyPurger(
      IdempotencyKeyStore store,
      IdempotencyProperties properties,
      TransactionTemplate transactions,
      Clock clock) {
    this.store = store;
    this.properties = properties;
    this.transactions = transactions;
    this.clock = clock;
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar registrar) {
    registrar.addFixedDelayTask(this::purgeExpired, properties.purgeInterval());
  }

  /** Runs one purge and returns the number of keys deleted. */
  public int purgeExpired() {
    int total = 0;
    for (int batch = 0; batch < MAX_BATCHES_PER_RUN; batch++) {
      Integer deleted =
          transactions.execute(
              status -> store.purgeExpired(clock.instant(), properties.purgeBatchSize()));
      int count = deleted == null ? 0 : deleted;
      total += count;
      if (count < properties.purgeBatchSize()) {
        break;
      }
    }
    if (total > 0) {
      log.atInfo().addKeyValue("deleted", total).log("Purged expired idempotency keys");
    }
    return total;
  }
}
