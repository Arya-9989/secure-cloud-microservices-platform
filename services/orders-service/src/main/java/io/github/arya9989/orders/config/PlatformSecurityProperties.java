package io.github.arya9989.orders.config;

import jakarta.validation.constraints.NotBlank;
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
 */
@Validated
@ConfigurationProperties("platform.security")
public record PlatformSecurityProperties(
    @NotBlank String issuer,
    @NotBlank String audience,
    URI jwkSetUri,
    @DefaultValue("30s") Duration clockSkew) {}
