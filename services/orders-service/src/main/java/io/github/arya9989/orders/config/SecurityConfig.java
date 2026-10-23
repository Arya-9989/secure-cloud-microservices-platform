package io.github.arya9989.orders.config;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

import io.github.arya9989.orders.dpop.DpopBindingFilter;
import io.github.arya9989.orders.dpop.DpopNonces;
import io.github.arya9989.orders.dpop.DpopProblemHandler;
import io.github.arya9989.orders.dpop.DpopProofVerification;
import io.github.arya9989.orders.web.AuthenticatedUserFilter;
import io.github.arya9989.orders.web.ProblemDetailsSecurityHandlers;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * Stateless OAuth2 resource server.
 *
 * <p>Authorization is expressed as URL rules so the whole policy is visible in one place:
 *
 * <ul>
 *   <li>{@code SCOPE_orders:read} / {@code SCOPE_orders:write} gate the customer API, which also
 *       requires a token issued to a person (it carries {@code roles}): a service's token cannot
 *       act as a customer whatever its scopes;
 *   <li>the admin API requires <em>both</em> the {@code ADMIN} role and the {@code orders:admin}
 *       scope (defence in depth: a mis-scoped token or a mis-assigned role alone is not enough);
 *   <li>the fulfilment API (service to service) requires scope {@code orders:fulfil}, this
 *       service's resource identifier as audience and a DPoP-bound token (RFC 9449, see
 *       docs/adr/0006-client-credentials-and-dpop.md);
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

  /** Granted when the token was issued to a person: {@code roles}, and no {@code client_id}. */
  public static final String PERSON = "TOKEN_PERSON";

  /** Granted when {@code aud} is this service's own resource identifier (tokens for services). */
  public static final String SERVICE_AUDIENCE = "TOKEN_AUDIENCE_SERVICE";

  /**
   * Granted when the token is bound to a DPoP key ({@code cnf.jkt}). Spring Security checked the
   * request's proof against it, and {@link DpopBindingFilter} rejects bound tokens sent as Bearer.
   */
  public static final String DPOP_BOUND = "TOKEN_DPOP_BOUND";

  /**
   * One policy for every response. The Swagger UI page is the only HTML this service serves; its
   * scripts and styles are same-origin files and its icons are data: URIs, so nothing needs {@code
   * 'unsafe-inline'} or {@code 'unsafe-eval'}.
   */
  static final String CONTENT_SECURITY_POLICY =
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
          + "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
          + "frame-ancestors 'none'";

  static final List<String> SCOPES =
      List.of("orders:read", "orders:write", "orders:admin", "orders:fulfil");

  @Bean
  SecurityFilterChain apiSecurity(
      HttpSecurity http,
      ProblemDetailsSecurityHandlers problems,
      PlatformSecurityProperties properties,
      DpopProofVerification dpopVerification,
      DpopNonces dpopNonces,
      DpopProblemHandler dpopProblems)
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
                    .access(allOf(hasAuthority("SCOPE_orders:read"), hasAuthority(PERSON)))
                    .requestMatchers(HttpMethod.POST, "/api/v1/orders/**")
                    .access(allOf(hasAuthority("SCOPE_orders:write"), hasAuthority(PERSON)))
                    .requestMatchers("/api/v1/admin/**")
                    .access(allOf(hasRole("ADMIN"), hasAuthority("SCOPE_orders:admin")))
                    .requestMatchers(HttpMethod.GET, "/api/v1/fulfilment/orders")
                    .access(fulfilment())
                    .requestMatchers(HttpMethod.PATCH, "/api/v1/fulfilment/orders/*/status")
                    .access(fulfilment())
                    .anyRequest()
                    .denyAll())
        .oauth2ResourceServer(
            oauth ->
                oauth
                    .jwt(
                        jwt ->
                            jwt.jwtAuthenticationConverter(
                                jwtAuthenticationConverter(properties.resource())))
                    // DPoP-bound tokens, with the proof checks of DpopProofVerification.
                    .dPoP(dpop -> dpop.authenticationFailureHandler(dpopProblems))
                    // RFC 9728 document at /.well-known/oauth-protected-resource, advertised in
                    // WWW-Authenticate. Describe only what this API really supports.
                    .protectedResourceMetadata(
                        metadata ->
                            metadata.protectedResourceMetadataCustomizer(
                                m ->
                                    m.resourceName("Orders Service API")
                                        .scopes(s -> s.addAll(SCOPES))
                                        .claim(
                                            "dpop_signing_alg_values_supported",
                                            List.of("ES256", "PS256", "RS256"))
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
                        })
                    .withObjectPostProcessor(
                        new ObjectPostProcessor<DPoPAuthenticationProvider>() {
                          @Override
                          public <O extends DPoPAuthenticationProvider> O postProcess(O provider) {
                            provider.setDPoPProofVerifierFactory(dpopVerification.decoderFactory());
                            return provider;
                          }
                        }))
        .exceptionHandling(e -> e.authenticationEntryPoint(problems).accessDeniedHandler(problems))
        // After every authentication filter (Bearer and DPoP), before authorization.
        .addFilterBefore(new DpopBindingFilter(dpopNonces, dpopProblems), AuthorizationFilter.class)
        .addFilterAfter(new AuthenticatedUserFilter(), DpopBindingFilter.class);
    return http.build();
  }

  private static AuthorizationManager<RequestAuthorizationContext> fulfilment() {
    return allOf(
        hasAuthority("SCOPE_orders:fulfil"),
        hasAuthority(SERVICE_AUDIENCE),
        hasAuthority(DPOP_BOUND));
  }

  /**
   * Maps {@code scope} to {@code SCOPE_*} authorities and {@code roles} to {@code ROLE_*}, adds the
   * token-kind authorities ({@link #PERSON}, {@link #SERVICE_AUDIENCE}, {@link #DPOP_BOUND}), and
   * uses the token subject (a user id, or a client id) as the principal name.
   */
  public static Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter(
      String resource) {
    JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
    return jwt -> {
      Collection<GrantedAuthority> authorities = new ArrayList<>(scopes.convert(jwt));
      List<String> roles = jwt.getClaimAsStringList(ROLES_CLAIM);
      if (roles != null && !roles.isEmpty() && !jwt.hasClaim("client_id")) {
        roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .forEach(authorities::add);
        authorities.add(new SimpleGrantedAuthority(PERSON));
      }
      List<String> audience = jwt.getAudience();
      if (audience != null && audience.contains(resource)) {
        authorities.add(new SimpleGrantedAuthority(SERVICE_AUDIENCE));
      }
      Map<String, Object> cnf = jwt.getClaimAsMap("cnf");
      if (cnf != null && cnf.get("jkt") instanceof String jkt && !jkt.isBlank()) {
        authorities.add(new SimpleGrantedAuthority(DPOP_BOUND));
      }
      return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    };
  }
}
