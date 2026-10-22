package io.github.arya9989.orders.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * How this resource server trusts access tokens.
 *
 * @param issuer expected {@code iss} claim; must match the auth service exactly
 * @param audience expected value in the {@code aud} claim
 * @param jwkSetUri where the auth service publishes its signing keys (JWKS)
 * @param clockSkew tolerated clock drift when checking {@code exp} / {@code nbf}
 * @param jwks how the key set is fetched and cached
 */
@Validated
@ConfigurationProperties("platform.security")
public record PlatformSecurityProperties(
    @NotBlank String issuer,
    @NotBlank String audience,
    @NotNull URI jwkSetUri,
    @DefaultValue("30s") Duration clockSkew,
    @Valid @DefaultValue Jwks jwks) {

  /**
   * JWKS fetching and caching.
   *
   * @param cacheTtl how long a fetched key set is used before it is fetched again; matches the auth
   *     service's {@code Cache-Control: max-age=300}
   * @param refetchMinInterval a token with an unknown {@code kid} triggers a refetch, but at most
   *     two per interval, so forged key ids cannot turn every request into a call to the auth
   *     service
   * @param outageTolerance how long after the last successful fetch the cached key set keeps
   *     verifying tokens while the JWKS endpoint cannot be reached. At least {@code cacheTtl} plus
   *     the access-token lifetime (5 + 15 minutes), so reads keep working through an auth-service
   *     outage for as long as the tokens they carry are valid
   * @param timeout connect and read timeout of one JWKS request
   */
  public record Jwks(
      @DefaultValue("5m") Duration cacheTtl,
      @DefaultValue("10s") Duration refetchMinInterval,
      @DefaultValue("20m") Duration outageTolerance,
      @DefaultValue("2s") Duration timeout) {}
}
