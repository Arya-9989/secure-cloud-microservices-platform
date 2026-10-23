package io.github.arya9989.orders.config;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import io.micrometer.observation.ObservationRegistry;
import java.net.MalformedURLException;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Verifies access tokens offline against the auth service's JWKS.
 *
 * <ul>
 *   <li>Only RS256 is accepted, so a token cannot downgrade itself to {@code none} or an HMAC
 *       algorithm. {@code iss}, {@code aud}, {@code sub} and {@code exp} are required. The {@code
 *       aud} must be the platform API (tokens issued to people) or this service's own resource
 *       identifier (tokens issued to services); which APIs each may call is decided in {@link
 *       SecurityConfig}.
 *   <li>The JOSE {@code typ} must be {@code JWT}, {@code at+jwt} or absent. Spring checks no type
 *       by default, so a DPoP proof ({@code dpop+jwt}) is never mistaken for an access token.
 *   <li>The key set is cached ({@code cacheTtl}). A token with an unknown {@code kid} triggers a
 *       refetch, which is what makes signing-key rotation on the auth service transparent here, but
 *       refetches are rate limited so forged key ids cannot make every request call the auth
 *       service.
 *   <li>If the JWKS endpoint is unreachable, the last good key set keeps working for {@code
 *       outageTolerance}, so the auth service is not a single point of failure for reads.
 *   <li>Each JWKS request has a short timeout, so a hanging auth service cannot stall requests.
 *   <li>Each fetch is observed ({@link ObservedJwksRetriever}): a timer, and with tracing on a
 *       child span that propagates the trace to the auth service.
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
public class JwtDecoderConfig {

  /** JWK sets larger than this are rejected; ours is a few hundred bytes per key. */
  static final int JWKS_SIZE_LIMIT_BYTES = 64 * 1024;

  /** RFC 9068 {@code at+jwt}, plain {@code JWT} (our issuer's default) or no {@code typ}. */
  static final DefaultJOSEObjectTypeVerifier<SecurityContext> ACCESS_TOKEN_TYPES =
      new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT, new JOSEObjectType("at+jwt"), null);

  @Bean
  JwtDecoder jwtDecoder(
      PlatformSecurityProperties properties, ObjectProvider<ObservationRegistry> observations) {
    return build(properties, observations.getIfAvailable(() -> ObservationRegistry.NOOP));
  }

  /** The production decoder, built outside a Spring context (tests). */
  static JwtDecoder build(PlatformSecurityProperties properties, ObservationRegistry observations) {
    NimbusJwtDecoder decoder =
        NimbusJwtDecoder.withJwkSource(jwkSource(properties, observations))
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(ACCESS_TOKEN_TYPES))
            .build();
    decoder.setJwtValidator(tokenValidator(properties));
    return decoder;
  }

  static JWKSource<SecurityContext> jwkSource(
      PlatformSecurityProperties properties, ObservationRegistry observations) {
    PlatformSecurityProperties.Jwks jwks = properties.jwks();
    int timeoutMillis = Math.toIntExact(jwks.timeout().toMillis());
    try {
      JWKSource<SecurityContext> source =
          JWKSourceBuilder.<SecurityContext>create(
                  properties.jwkSetUri().toURL(),
                  new ObservedJwksRetriever(
                      timeoutMillis, timeoutMillis, JWKS_SIZE_LIMIT_BYTES, observations))
              .cache(jwks.cacheTtl().toMillis(), jwks.timeout().toMillis() + 1_000)
              .refreshAheadCache(false) // refetch on expiry; outage tolerance covers failures
              .rateLimited(jwks.refetchMinInterval().toMillis())
              .outageTolerant(jwks.outageTolerance().toMillis())
              .build();
      return new RateLimitMeansNoMatchingKey(source);
    } catch (MalformedURLException e) {
      throw new IllegalStateException("platform.security.jwk-set-uri is not a URL", e);
    }
  }

  static OAuth2TokenValidator<Jwt> tokenValidator(PlatformSecurityProperties properties) {
    JwtTimestampValidator timestamps = new JwtTimestampValidator(properties.clockSkew());
    timestamps.setAllowEmptyExpiryClaim(false); // a token without exp would never expire
    return new DelegatingOAuth2TokenValidator<>(
        List.of(
            timestamps,
            new JwtIssuerValidator(properties.issuer()),
            new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD,
                aud ->
                    aud != null
                        && (aud.contains(properties.audience())
                            || aud.contains(properties.resource()))),
            new JwtClaimValidator<String>(
                JwtClaimNames.SUB, sub -> sub != null && !sub.isBlank())));
  }

  /**
   * When the refetch budget is spent, a token whose {@code kid} is not in the cached key set is
   * simply a token without a matching key: rejected as invalid (401). Without this, the rate-limit
   * signal would surface as a key-source failure, which is reported as the service being unable to
   * verify tokens (503), and forged key ids could produce a stream of server errors.
   */
  record RateLimitMeansNoMatchingKey(JWKSource<SecurityContext> delegate)
      implements JWKSource<SecurityContext> {

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext context) throws KeySourceException {
      try {
        return delegate.get(selector, context);
      } catch (RateLimitReachedException e) {
        return List.of();
      }
    }
  }
}
