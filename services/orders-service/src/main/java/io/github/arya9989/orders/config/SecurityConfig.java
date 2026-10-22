package io.github.arya9989.orders.config;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

import io.github.arya9989.orders.web.AuthenticatedUserFilter;
import io.github.arya9989.orders.web.ProblemDetailsSecurityHandlers;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * Stateless OAuth2 resource server.
 *
 * <p>Authorization is expressed as URL rules so the whole policy is visible in one place:
 *
 * <ul>
 *   <li>{@code SCOPE_orders:read} / {@code SCOPE_orders:write} gate the customer API;
 *   <li>the admin API requires <em>both</em> the {@code ADMIN} role and the {@code orders:admin}
 *       scope (defence in depth: a mis-scoped token or a mis-assigned role alone is not enough);
 *   <li>anything not listed is denied.
 * </ul>
 *
 * Resource ownership (a customer may only see their own orders) is enforced in the service layer by
 * querying with the token's {@code sub}.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

  static final String ROLES_CLAIM = "roles";

  /**
   * One policy for every response. The Swagger UI page is the only HTML this service serves; its
   * scripts and styles are same-origin files and its icons are data: URIs, so nothing needs {@code
   * 'unsafe-inline'} or {@code 'unsafe-eval'}.
   */
  static final String CONTENT_SECURITY_POLICY =
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
          + "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
          + "frame-ancestors 'none'";

  static final List<String> SCOPES = List.of("orders:read", "orders:write", "orders:admin");

  @Bean
  SecurityFilterChain apiSecurity(HttpSecurity http, ProblemDetailsSecurityHandlers problems)
      throws Exception {
    http.csrf(AbstractHttpConfigurer::disable) // bearer tokens only: no ambient credentials
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .requestCache(AbstractHttpConfigurer::disable)
        .headers(
            h ->
                h.contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                    .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                    .crossOriginOpenerPolicy(c -> c.policy(CrossOriginOpenerPolicy.SAME_ORIGIN)))
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(EndpointRequest.to("health", "info", "prometheus"))
                    .permitAll()
                    .requestMatchers("/docs/orders/**")
                    .permitAll()
                    .requestMatchers("/error")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/v1/products/**", "/api/v1/orders/**")
                    .hasAuthority("SCOPE_orders:read")
                    .requestMatchers(HttpMethod.POST, "/api/v1/orders/**")
                    .hasAuthority("SCOPE_orders:write")
                    .requestMatchers("/api/v1/admin/**")
                    .access(allOf(hasRole("ADMIN"), hasAuthority("SCOPE_orders:admin")))
                    .anyRequest()
                    .denyAll())
        .oauth2ResourceServer(
            oauth ->
                oauth
                    .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                    // RFC 9728 document at /.well-known/oauth-protected-resource, advertised in
                    // WWW-Authenticate. Describe only what this API really supports.
                    .protectedResourceMetadata(
                        metadata ->
                            metadata.protectedResourceMetadataCustomizer(
                                m ->
                                    m.resourceName("Orders Service API")
                                        .scopes(s -> s.addAll(SCOPES))
                                        .tlsClientCertificateBoundAccessTokens(false)))
                    .authenticationEntryPoint(problems)
                    .accessDeniedHandler(problems)
                    // 503 rather than 500 when the signing keys cannot be fetched.
                    .withObjectPostProcessor(
                        new ObjectPostProcessor<BearerTokenAuthenticationFilter>() {
                          @Override
                          public <O extends BearerTokenAuthenticationFilter> O postProcess(
                              O filter) {
                            filter.setAuthenticationFailureHandler(problems);
                            return filter;
                          }
                        }))
        .exceptionHandling(e -> e.authenticationEntryPoint(problems).accessDeniedHandler(problems))
        .addFilterAfter(new AuthenticatedUserFilter(), BearerTokenAuthenticationFilter.class);
    return http.build();
  }

  /**
   * Maps {@code scope} to {@code SCOPE_*} authorities and {@code roles} to {@code ROLE_*}, and uses
   * the token subject (the auth service's user id) as the principal name.
   */
  public static Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
    return jwt -> {
      Collection<GrantedAuthority> authorities = new ArrayList<>(scopes.convert(jwt));
      List<String> roles = jwt.getClaimAsStringList(ROLES_CLAIM);
      if (roles != null) {
        roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .forEach(authorities::add);
      }
      return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    };
  }
}
