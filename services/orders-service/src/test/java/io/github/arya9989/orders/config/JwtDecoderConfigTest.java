package io.github.arya9989.orders.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import io.github.arya9989.orders.support.JwksTestServer;
import io.github.arya9989.orders.support.TestTokens;
import io.micrometer.observation.ObservationRegistry;
import java.net.URI;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * The decoder exactly as production builds it, against a real HTTP JWKS endpoint: which tokens it
 * accepts, and how it behaves when the auth service rotates keys, is attacked with forged key ids,
 * is down, or hangs.
 */
class JwtDecoderConfigTest {

  private static final PlatformSecurityProperties.Jwks DEFAULTS =
      new PlatformSecurityProperties.Jwks(
          Duration.ofMinutes(5),
          Duration.ofSeconds(10),
          Duration.ofMinutes(20),
          Duration.ofSeconds(2));

  private final RSAKey signingKey = TestTokens.newRsaKey();
  private final JwksTestServer jwks = JwksTestServer.start(signingKey);

  @AfterEach
  void stop() {
    jwks.close();
  }

  private JwtDecoder decoder(PlatformSecurityProperties.Jwks settings) {
    return JwtDecoderConfig.build(
        new PlatformSecurityProperties(
            TestTokens.ISSUER,
            TestTokens.AUDIENCE,
            URI.create(jwks.jwkSetUri()),
            Duration.ofSeconds(30),
            settings),
        ObservationRegistry.NOOP);
  }

  private String validToken() {
    return TestTokens.user(signingKey, UUID.randomUUID().toString());
  }

  @Test
  void acceptsAWellFormedToken() {
    Jwt jwt = decoder(DEFAULTS).decode(validToken());

    assertThat(jwt.getAudience()).containsExactly(TestTokens.AUDIENCE);
  }

  @Test
  void rejectsATokenWithoutAnExpiry() {
    String token =
        TestTokens.custom(signingKey, UUID.randomUUID().toString(), c -> c.expirationTime(null));

    assertThatThrownBy(() -> decoder(DEFAULTS).decode(token))
        .isInstanceOf(JwtException.class)
        .hasMessageContaining("exp");
  }

  @Test
  void forgedKeyIdsCannotTurnEveryRequestIntoAJwksFetch() {
    JwtDecoder decoder = decoder(DEFAULTS);
    decoder.decode(validToken()); // warm the cache: one fetch
    int before = jwks.requestCount();
    RSAKey attacker = TestTokens.newRsaKey();
    JWTClaimsSet claims = TestTokens.claims("mallory", "USER", TestTokens.USER_SCOPES).build();

    for (int i = 0; i < 20; i++) {
      String forged = TestTokens.sign(attacker, UUID.randomUUID().toString(), claims);
      // Still "bad token" (401) once the refetch budget is spent, never a server error.
      assertThatThrownBy(() -> decoder.decode(forged)).isInstanceOf(BadJwtException.class);
    }

    assertThat(jwks.requestCount() - before)
        .as("refetches caused by 20 unknown key ids")
        .isLessThanOrEqualTo(2);
    assertThat(decoder.decode(validToken()).getSubject()).isNotBlank();
  }

  @Test
  void aNewlyPublishedSigningKeyIsPickedUpWithoutRestart() {
    JwtDecoder decoder = decoder(DEFAULTS);
    decoder.decode(validToken());
    RSAKey next = TestTokens.newRsaKey();

    jwks.publish(next); // rotation: the auth service publishes the next key, then signs with it

    assertThat(decoder.decode(TestTokens.user(next, "alice")).getSubject()).isEqualTo("alice");
    assertThat(decoder.decode(validToken()).getSubject()).isNotBlank();
  }

  @Test
  void cachedKeysKeepVerifyingWhileTheJwksEndpointIsDown() throws InterruptedException {
    JwtDecoder decoder =
        decoder(
            new PlatformSecurityProperties.Jwks(
                Duration.ofMillis(300),
                Duration.ofMillis(100),
                Duration.ofMinutes(20),
                Duration.ofSeconds(2)));
    decoder.decode(validToken());

    jwks.failWith(503);
    Thread.sleep(600); // the cached key set is now stale

    assertThat(decoder.decode(validToken()).getSubject())
        .as("an auth-service outage must not reject still-valid tokens")
        .isNotBlank();
  }

  @Test
  void withNoCachedKeysAndTheJwksEndpointDownTokensAreNotReportedAsBad() {
    jwks.failWith(503);

    assertThatThrownBy(() -> decoder(DEFAULTS).decode(validToken()))
        .isInstanceOf(JwtException.class)
        .isNotInstanceOf(BadJwtException.class); // mapped to 503 by the security handlers
  }

  @Test
  void aHangingJwksEndpointFailsFastInsteadOfBlockingRequests() {
    JwtDecoder decoder =
        decoder(
            new PlatformSecurityProperties.Jwks(
                Duration.ofMinutes(5),
                Duration.ofSeconds(10),
                Duration.ofMinutes(20),
                Duration.ofMillis(500)));
    jwks.delayResponses(Duration.ofSeconds(10));
    long started = System.nanoTime();

    assertThatThrownBy(() -> decoder.decode(validToken())).isInstanceOf(JwtException.class);

    assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
  }
}
