package io.github.arya9989.orders.config;

import java.util.List;
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
 * <p>Only RS256 is accepted, so a token cannot downgrade itself to {@code none} or an HMAC
 * algorithm. Keys are fetched lazily and cached by Nimbus; an unknown {@code kid} triggers a
 * refetch, which is what makes signing-key rotation on the auth service transparent here.
 */
@Configuration(proxyBeanMethods = false)
public class JwtDecoderConfig {

  @Bean
  JwtDecoder jwtDecoder(PlatformSecurityProperties properties) {
    NimbusJwtDecoder decoder =
        NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri().toString())
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
    decoder.setJwtValidator(tokenValidator(properties));
    return decoder;
  }

  static OAuth2TokenValidator<Jwt> tokenValidator(PlatformSecurityProperties properties) {
    return new DelegatingOAuth2TokenValidator<>(
        List.of(
            new JwtTimestampValidator(properties.clockSkew()),
            new JwtIssuerValidator(properties.issuer()),
            new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains(properties.audience())),
            new JwtClaimValidator<String>(
                JwtClaimNames.SUB, sub -> sub != null && !sub.isBlank())));
  }
}
