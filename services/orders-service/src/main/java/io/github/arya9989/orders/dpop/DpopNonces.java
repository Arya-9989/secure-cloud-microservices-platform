package io.github.arya9989.orders.dpop;

import io.github.arya9989.orders.config.PlatformSecurityProperties;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Server-issued DPoP nonces (RFC 9449 section 9), stateless: {@code <window>.<HMAC(window)>}.
 *
 * <p>A nonce is valid in the window it was issued for and the next one, so a client that just
 * received one always has at least one full lifetime to use it. Replicas sharing the secret accept
 * each other's nonces without any shared state.
 */
@Component
public class DpopNonces {

  private static final Logger log = LoggerFactory.getLogger(DpopNonces.class);
  static final int MIN_SECRET_BYTES = 32;
  private static final int MAC_BYTES = 18;

  private final byte[] secret;
  private final long lifetimeMillis;
  private final Clock clock;

  @Autowired
  public DpopNonces(PlatformSecurityProperties properties, Clock clock) {
    this(properties.dpop(), clock);
  }

  DpopNonces(PlatformSecurityProperties.Dpop dpop, Clock clock) {
    this.secret = secret(dpop.nonceSecret());
    this.lifetimeMillis = dpop.nonceLifetime().toMillis();
    this.clock = clock;
    if (lifetimeMillis < 1_000) {
      throw new IllegalArgumentException("platform.security.dpop.nonce-lifetime must be >= 1s");
    }
  }

  private static byte[] secret(@Nullable String configured) {
    if (configured == null || configured.isBlank()) {
      log.warn(
          "PLATFORM_SECURITY_DPOP_NONCE_SECRET is not set: using a random per-instance secret."
              + " Set a shared one when running more than one replica.");
      byte[] random = new byte[MIN_SECRET_BYTES];
      new SecureRandom().nextBytes(random);
      return random;
    }
    byte[] decoded = Base64.getUrlDecoder().decode(configured.strip()); // base64url, no padding
    if (decoded.length < MIN_SECRET_BYTES) {
      throw new IllegalArgumentException(
          "platform.security.dpop.nonce-secret must decode to at least 32 bytes");
    }
    return decoded;
  }

  public String issue() {
    return forWindow(window());
  }

  public boolean isValid(@Nullable String nonce) {
    if (nonce == null || nonce.length() > 64) {
      return false;
    }
    long current = window();
    byte[] presented = nonce.getBytes(StandardCharsets.US_ASCII);
    // Constant-time comparisons against both acceptable windows.
    boolean valid = false;
    for (long w : new long[] {current, current - 1}) {
      valid |= MessageDigest.isEqual(presented, forWindow(w).getBytes(StandardCharsets.US_ASCII));
    }
    return valid;
  }

  private long window() {
    return clock.millis() / lifetimeMillis;
  }

  private String forWindow(long window) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret, "HmacSHA256"));
      byte[] tag = mac.doFinal(("dpop-nonce:" + window).getBytes(StandardCharsets.US_ASCII));
      return window
          + "."
          + Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(tag, MAC_BYTES));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 is required by every Java platform", e);
    }
  }
}
