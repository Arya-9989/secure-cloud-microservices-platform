package io.github.arya9989.orders.config;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.arya9989.orders.catalog.ProductController;
import io.github.arya9989.orders.catalog.ProductRepository;
import io.github.arya9989.orders.dpop.DpopNonces;
import io.github.arya9989.orders.dpop.DpopProblemHandler;
import io.github.arya9989.orders.dpop.DpopProofVerification;
import io.github.arya9989.orders.dpop.JdbcDpopReplayCache;
import io.github.arya9989.orders.idempotency.IdempotentOrderPlacement;
import io.github.arya9989.orders.order.AdminOrderController;
import io.github.arya9989.orders.order.FulfilmentController;
import io.github.arya9989.orders.order.OrderController;
import io.github.arya9989.orders.order.OrderService;
import io.github.arya9989.orders.web.ApiExceptionHandler;
import io.github.arya9989.orders.web.ProblemDetailsSecurityHandlers;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The authorization matrix, tested at the HTTP layer with the real {@link SecurityConfig} but
 * pre-authenticated tokens. Token <em>validation</em> is covered by the integration tests.
 */
@WebMvcTest({
  OrderController.class,
  AdminOrderController.class,
  ProductController.class,
  FulfilmentController.class
})
@Import({
  SecurityConfig.class,
  ProblemDetailsSecurityHandlers.class,
  ApiExceptionHandler.class,
  AppConfig.class,
  DpopNonces.class,
  DpopProofVerification.class,
  DpopProblemHandler.class
})
@EnableConfigurationProperties(PlatformSecurityProperties.class)
class AuthorizationRulesTest {

  @Autowired MockMvc mvc;
  @MockitoBean OrderService orders;
  @MockitoBean IdempotentOrderPlacement placement;
  @MockitoBean ProductRepository products;
  @MockitoBean JwtDecoder jwtDecoder;
  @MockitoBean JdbcDpopReplayCache replayCache;

  private static final String VALID_ORDER =
      """
      {"lines": [{"sku": "KB-001", "quantity": 1}]}
      """;

  @BeforeEach
  void stubService() {
    given(orders.listForCustomer(any(), any())).willReturn(Page.empty());
    given(orders.listAll(any(), any())).willReturn(Page.empty());
  }

  /** A token issued to a person, with these authorities. */
  private static JwtRequestPostProcessor token(String... authorities) {
    return serviceToken(
        Stream.concat(Arrays.stream(authorities), Stream.of(SecurityConfig.PERSON))
            .toArray(String[]::new));
  }

  /** A token issued to a service: no person authority unless listed. */
  private static JwtRequestPostProcessor serviceToken(String... authorities) {
    return jwt()
        .jwt(j -> j.subject("user-123"))
        .authorities(
            Arrays.stream(authorities)
                .map(SimpleGrantedAuthority::new)
                .toArray(GrantedAuthority[]::new));
  }

  @Nested
  class FulfilmentApi {

    private static final String[] BOUND_SERVICE = {
      "SCOPE_orders:fulfil", SecurityConfig.SERVICE_AUDIENCE, SecurityConfig.DPOP_BOUND
    };

    @Test
    void aDpopBoundServiceTokenForThisResourceIsAllowed() throws Exception {
      mvc.perform(get("/api/v1/fulfilment/orders").with(serviceToken(BOUND_SERVICE)))
          .andExpect(status().isOk());
    }

    @Test
    void everyOneOfScopeAudienceAndBindingIsRequired() throws Exception {
      for (int missing = 0; missing < BOUND_SERVICE.length; missing++) {
        int skip = missing;
        String[] partial =
            java.util.stream.IntStream.range(0, BOUND_SERVICE.length)
                .filter(i -> i != skip)
                .mapToObj(i -> BOUND_SERVICE[i])
                .toArray(String[]::new);
        mvc.perform(get("/api/v1/fulfilment/orders").with(serviceToken(partial)))
            .andExpect(status().isForbidden());
      }
    }

    @Test
    void anAdministratorIsNotAFulfilmentService() throws Exception {
      mvc.perform(
              get("/api/v1/fulfilment/orders")
                  .with(token("ROLE_ADMIN", "SCOPE_orders:admin", "SCOPE_orders:write")))
          .andExpect(status().isForbidden());
    }

    @Test
    void aServiceTokenCannotUseTheCustomerApiWhateverItsScopes() throws Exception {
      mvc.perform(
              get("/api/v1/orders").with(serviceToken("SCOPE_orders:read", "SCOPE_orders:write")))
          .andExpect(status().isForbidden());
      mvc.perform(
              post("/api/v1/orders")
                  .with(serviceToken("SCOPE_orders:read", "SCOPE_orders:write"))
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(VALID_ORDER))
          .andExpect(status().isForbidden());
    }

    @Test
    void fulfilmentMayOnlyShipOrDeliver() throws Exception {
      for (String status : new String[] {"CANCELLED", "CONFIRMED", "PENDING", "LOST"}) {
        mvc.perform(
                patch("/api/v1/fulfilment/orders/" + UUID.randomUUID() + "/status")
                    .with(serviceToken(BOUND_SERVICE))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"status\":\"" + status + "\"}"))
            .andExpect(status().isBadRequest());
      }
    }
  }

  @Nested
  class Unauthenticated {

    @Test
    void customerApiRequiresAToken() throws Exception {
      mvc.perform(get("/api/v1/orders"))
          .andExpect(status().isUnauthorized())
          .andExpect(
              header()
                  .string(
                      "WWW-Authenticate",
                      "Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\""))
          .andExpect(header().exists("X-Request-ID"))
          .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
          .andExpect(jsonPath("$.status").value(401))
          .andExpect(jsonPath("$.request_id").exists());
    }

    @Test
    void protectedResourceMetadataIsPublic() throws Exception {
      // RFC 9728: tells clients which authorization server and token formats this API accepts.
      mvc.perform(get("/.well-known/oauth-protected-resource"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.resource").value("http://localhost"))
          .andExpect(jsonPath("$.bearer_methods_supported[0]").value("header"))
          .andExpect(jsonPath("$.scopes_supported.length()").value(4))
          .andExpect(jsonPath("$.scopes_supported[3]").value("orders:fulfil"))
          .andExpect(jsonPath("$.dpop_signing_alg_values_supported[0]").value("ES256"))
          .andExpect(jsonPath("$.tls_client_certificate_bound_access_tokens").value(false));
    }

    @Test
    void adminApiRequiresAToken() throws Exception {
      mvc.perform(get("/api/v1/admin/orders")).andExpect(status().isUnauthorized());
    }

    @Test
    void anInvalidTokenIsUnauthorized() throws Exception {
      given(jwtDecoder.decode("forged")).willThrow(new BadJwtException("Signed JWT rejected"));

      mvc.perform(get("/api/v1/orders").header("Authorization", "Bearer forged"))
          .andExpect(status().isUnauthorized())
          .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void unavailableSigningKeysAreAServiceErrorNotABadToken() throws Exception {
      // e.g. a cold JWKS cache while the auth service is down: the token may well be valid, so
      // the client must not be told to discard it (401), and it is not a server bug (500).
      given(jwtDecoder.decode("valid-looking"))
          .willThrow(new JwtException("Couldn't retrieve remote JWK set"));

      mvc.perform(get("/api/v1/orders").header("Authorization", "Bearer valid-looking"))
          .andExpect(status().isServiceUnavailable())
          .andExpect(header().exists("Retry-After"))
          .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
          .andExpect(jsonPath("$.status").value(503))
          .andExpect(jsonPath("$.request_id").exists());
    }
  }

  @Nested
  class Scopes {

    @Test
    void readScopeAllowsReading() throws Exception {
      mvc.perform(get("/api/v1/orders").with(token("SCOPE_orders:read")))
          .andExpect(status().isOk());
      mvc.perform(get("/api/v1/products").with(token("SCOPE_orders:read")))
          .andExpect(status().isOk());
    }

    @Test
    void writeScopeAloneCannotRead() throws Exception {
      mvc.perform(get("/api/v1/orders").with(token("SCOPE_orders:write")))
          .andExpect(status().isForbidden())
          .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void readScopeAloneCannotWrite() throws Exception {
      mvc.perform(
              post("/api/v1/orders")
                  .with(token("SCOPE_orders:read"))
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(VALID_ORDER))
          .andExpect(status().isForbidden());
    }

    @Test
    void unmappedRoutesAndMethodsAreDenied() throws Exception {
      JwtRequestPostProcessor everything =
          token("SCOPE_orders:read", "SCOPE_orders:write", "SCOPE_orders:admin", "ROLE_ADMIN");
      mvc.perform(delete("/api/v1/orders/" + UUID.randomUUID()).with(everything))
          .andExpect(status().isForbidden());
      mvc.perform(get("/api/v1/internal/secrets").with(everything))
          .andExpect(status().isForbidden());
    }
  }

  @Nested
  class AdminApi {

    @Test
    void regularUserIsForbidden() throws Exception {
      mvc.perform(
              get("/api/v1/admin/orders")
                  .with(token("ROLE_USER", "SCOPE_orders:read", "SCOPE_orders:write")))
          .andExpect(status().isForbidden());
    }

    @Test
    void adminRoleWithoutAdminScopeIsForbidden() throws Exception {
      mvc.perform(get("/api/v1/admin/orders").with(token("ROLE_ADMIN", "SCOPE_orders:read")))
          .andExpect(status().isForbidden());
    }

    @Test
    void adminScopeWithoutAdminRoleIsForbidden() throws Exception {
      mvc.perform(get("/api/v1/admin/orders").with(token("ROLE_USER", "SCOPE_orders:admin")))
          .andExpect(status().isForbidden());
    }

    @Test
    void adminRoleAndScopeAreAllowed() throws Exception {
      mvc.perform(get("/api/v1/admin/orders").with(token("ROLE_ADMIN", "SCOPE_orders:admin")))
          .andExpect(status().isOk());
    }

    @Test
    void statusUpdateIsAdminOnly() throws Exception {
      mvc.perform(
              patch("/api/v1/admin/orders/" + UUID.randomUUID() + "/status")
                  .with(token("ROLE_USER", "SCOPE_orders:write"))
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"status\":\"SHIPPED\"}"))
          .andExpect(status().isForbidden());
    }
  }

  @Nested
  class Validation {

    @Test
    void emptyOrderIsRejected() throws Exception {
      mvc.perform(
              post("/api/v1/orders")
                  .with(token("SCOPE_orders:write"))
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"lines\": []}"))
          .andExpect(status().isBadRequest())
          .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    void clientCannotSmuggleAPrice() throws Exception {
      mvc.perform(
              post("/api/v1/orders")
                  .with(token("SCOPE_orders:write"))
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(
                      "{\"lines\": [{\"sku\": \"KB-001\", \"quantity\": 1, \"unitPrice\": 0.01}]}"))
          .andExpect(status().isBadRequest());
    }

    @Test
    void malformedIdempotencyKeysAreRejected() throws Exception {
      for (String key :
          new String[] {"short", "has space inside", "a,b-12345678", "\"\"", "x".repeat(129)}) {
        mvc.perform(
                post("/api/v1/orders")
                    .with(token("SCOPE_orders:write"))
                    .header("Idempotency-Key", key)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(VALID_ORDER))
            .andExpect(status().isBadRequest())
            .andExpect(
                jsonPath("$.detail")
                    .value(org.hamcrest.Matchers.containsString("Idempotency-Key")));
      }
    }

    @Test
    void oversizedPageIsRejected() throws Exception {
      mvc.perform(get("/api/v1/orders?size=1000").with(token("SCOPE_orders:read")))
          .andExpect(status().isBadRequest());
    }
  }
}
