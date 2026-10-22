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
import io.github.arya9989.orders.order.AdminOrderController;
import io.github.arya9989.orders.order.OrderController;
import io.github.arya9989.orders.order.OrderService;
import io.github.arya9989.orders.web.ApiExceptionHandler;
import io.github.arya9989.orders.web.ProblemDetailsSecurityHandlers;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The authorization matrix, tested at the HTTP layer with the real {@link SecurityConfig} but
 * pre-authenticated tokens. Token <em>validation</em> is covered by the integration tests.
 */
@WebMvcTest({OrderController.class, AdminOrderController.class, ProductController.class})
@Import({SecurityConfig.class, ProblemDetailsSecurityHandlers.class, ApiExceptionHandler.class})
class AuthorizationRulesTest {

  @Autowired MockMvc mvc;
  @MockitoBean OrderService orders;
  @MockitoBean ProductRepository products;
  @MockitoBean JwtDecoder jwtDecoder;

  private static final String VALID_ORDER =
      """
      {"lines": [{"sku": "KB-001", "quantity": 1}]}
      """;

  @BeforeEach
  void stubService() {
    given(orders.listForCustomer(any(), any())).willReturn(Page.empty());
    given(orders.listAll(any(), any())).willReturn(Page.empty());
  }

  private static JwtRequestPostProcessor token(String... authorities) {
    return jwt()
        .jwt(j -> j.subject("user-123"))
        .authorities(
            Arrays.stream(authorities)
                .map(SimpleGrantedAuthority::new)
                .toArray(GrantedAuthority[]::new));
  }

  @Nested
  class Unauthenticated {

    @Test
    void customerApiRequiresAToken() throws Exception {
      mvc.perform(get("/api/v1/orders"))
          .andExpect(status().isUnauthorized())
          .andExpect(header().string("WWW-Authenticate", "Bearer"))
          .andExpect(header().exists("X-Request-ID"))
          .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
          .andExpect(jsonPath("$.status").value(401))
          .andExpect(jsonPath("$.request_id").exists());
    }

    @Test
    void adminApiRequiresAToken() throws Exception {
      mvc.perform(get("/api/v1/admin/orders")).andExpect(status().isUnauthorized());
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
    void oversizedPageIsRejected() throws Exception {
      mvc.perform(get("/api/v1/orders?size=1000").with(token("SCOPE_orders:read")))
          .andExpect(status().isBadRequest());
    }
  }
}
