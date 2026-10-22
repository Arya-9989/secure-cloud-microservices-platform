package io.github.arya9989.orders.dpop;

import io.github.arya9989.orders.config.PlatformSecurityProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.concurrent.Callable;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.support.SimpleValueWrapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

/**
 * The DPoP {@code jti} replay cache that Spring Security's {@code DPoPProofReplayValidator} writes
 * to, kept in PostgreSQL so every replica sees every proof. Spring's default is an in-memory map
 * per instance, where a proof replayed to another replica would pass.
 *
 * <p>Only {@link #putIfAbsent} matters to the validator; it is one {@code INSERT … ON CONFLICT}, so
 * two simultaneous uses of one proof cannot both succeed. Expired rows are purged every minute.
 */
@Component
public class JdbcDpopReplayCache implements Cache, SchedulingConfigurer {

  private static final Logger log = LoggerFactory.getLogger(JdbcDpopReplayCache.class);
  private static final Object PRESENT = Boolean.TRUE;

  private final JdbcClient jdbc;
  private final Clock clock;
  private final Duration retention;

  public JdbcDpopReplayCache(JdbcClient jdbc, Clock clock, PlatformSecurityProperties properties) {
    this.jdbc = jdbc;
    this.clock = clock;
    // A proof is accepted while |now - iat| <= max age, so it must be remembered for 2x that.
    this.retention = properties.dpop().proofMaxAge().multipliedBy(2).plusSeconds(5);
  }

  @Override
  public String getName() {
    return "dpop-proof-jti";
  }

  @Override
  public Object getNativeCache() {
    return jdbc;
  }

  @Override
  public @Nullable ValueWrapper putIfAbsent(Object key, @Nullable Object value) {
    boolean inserted =
        jdbc.sql(
                """
                INSERT INTO dpop_proof_jti (proof_hash, expires_at) VALUES (:hash, :expires)
                ON CONFLICT (proof_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
                 WHERE dpop_proof_jti.expires_at <= :now
                RETURNING proof_hash
                """)
            .param("hash", hash(key))
            .param("expires", clock.instant().plus(retention).atOffset(ZoneOffset.UTC))
            .param("now", clock.instant().atOffset(ZoneOffset.UTC))
            .query(String.class)
            .optional()
            .isPresent();
    return inserted ? null : new SimpleValueWrapper(PRESENT);
  }

  @Override
  public @Nullable ValueWrapper get(Object key) {
    boolean present =
        jdbc.sql("SELECT 1 FROM dpop_proof_jti WHERE proof_hash = :hash AND expires_at > :now")
            .param("hash", hash(key))
            .param("now", clock.instant().atOffset(ZoneOffset.UTC))
            .query(Integer.class)
            .optional()
            .isPresent();
    return present ? new SimpleValueWrapper(PRESENT) : null;
  }

  @Override
  public <T> @Nullable T get(Object key, @Nullable Class<T> type) {
    throw new UnsupportedOperationException("the replay cache only answers seen / not seen");
  }

  @Override
  public <T> T get(Object key, Callable<T> valueLoader) {
    throw new UnsupportedOperationException("the replay cache only answers seen / not seen");
  }

  @Override
  public void put(Object key, @Nullable Object value) {
    putIfAbsent(key, value);
  }

  @Override
  public void evict(Object key) {
    jdbc.sql("DELETE FROM dpop_proof_jti WHERE proof_hash = :hash")
        .param("hash", hash(key))
        .update();
  }

  @Override
  public void clear() {
    jdbc.sql("DELETE FROM dpop_proof_jti").update();
  }

  /** Deletes expired entries; returns how many. */
  public int purgeExpired() {
    int deleted =
        jdbc.sql("DELETE FROM dpop_proof_jti WHERE expires_at <= :now")
            .param("now", clock.instant().atOffset(ZoneOffset.UTC))
            .update();
    if (deleted > 0) {
      log.atDebug().addKeyValue("deleted", deleted).log("Purged expired DPoP proof ids");
    }
    return deleted;
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar registrar) {
    registrar.addFixedDelayTask(this::purgeExpired, Duration.ofMinutes(1));
  }

  private static String hash(Object key) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(key.toString().getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by every Java platform", e);
    }
  }
}
