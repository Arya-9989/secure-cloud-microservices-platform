package io.github.arya9989.orders.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtAuthenticationConverterTest {

  private static final String RESOURCE = "urn:secure-platform:orders-service";

  private static Jwt.Builder jwt() {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .subject("6f1c3d1e-0000-4000-8000-000000000001")
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(60));
  }

  @Test
  void mapsScopesAndRolesToAuthorities() {
    AbstractAuthenticationToken auth =
        SecurityConfig.jwtAuthenticationConverter(RESOURCE)
            .convert(
                jwt()
                    .claim("scope", "orders:read orders:admin")
                    .claim("roles", List.of("ADMIN"))
                    .build());

    assertThat(auth).isNotNull();
    assertThat(auth.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .containsExactlyInAnyOrder(
            "SCOPE_orders:read", "SCOPE_orders:admin", "ROLE_ADMIN", SecurityConfig.PERSON);
    assertThat(auth.getName()).isEqualTo("6f1c3d1e-0000-4000-8000-000000000001");
  }

  @Test
  void tokenWithoutRolesOrScopesHasNoAuthorities() {
    AbstractAuthenticationToken auth =
        SecurityConfig.jwtAuthenticationConverter(RESOURCE)
            .convert(jwt().claim("email", "x@y.z").build());

    assertThat(auth).isNotNull();
    assertThat(auth.getAuthorities()).isEmpty();
  }

  @Test
  void aDpopBoundServiceTokenIsMarkedAsSuchAndNeverAsAPerson() {
    AbstractAuthenticationToken auth =
        SecurityConfig.jwtAuthenticationConverter(RESOURCE)
            .convert(
                jwt()
                    .audience(List.of(RESOURCE))
                    .claim("client_id", "fulfilment")
                    .claim("scope", "orders:fulfil")
                    .claim("roles", List.of("ADMIN")) // must be ignored on a client token
                    .claim("cnf", Map.of("jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"))
                    .build());

    assertThat(auth).isNotNull();
    assertThat(auth.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .containsExactlyInAnyOrder(
            "SCOPE_orders:fulfil", SecurityConfig.SERVICE_AUDIENCE, SecurityConfig.DPOP_BOUND);
  }

  @Test
  void aBlankOrMissingConfirmationIsNotABinding() {
    AbstractAuthenticationToken blank =
        SecurityConfig.jwtAuthenticationConverter(RESOURCE)
            .convert(jwt().claim("cnf", Map.of("jkt", " ")).build());
    AbstractAuthenticationToken other =
        SecurityConfig.jwtAuthenticationConverter(RESOURCE)
            .convert(jwt().claim("cnf", Map.of("x5t#S256", "abc")).build());

    assertThat(blank.getAuthorities()).isEmpty();
    assertThat(other.getAuthorities()).isEmpty();
  }
}
