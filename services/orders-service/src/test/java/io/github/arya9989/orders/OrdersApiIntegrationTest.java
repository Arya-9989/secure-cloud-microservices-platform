package io.github.arya9989.orders;

import static org.assertj.core.api.Assertions.assertThat;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import io.github.arya9989.orders.support.JwksTestServer;
import io.github.arya9989.orders.support.TestTokens;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * End-to-end inside the JVM: real HTTP, real RS256 tokens verified against a JWKS endpoint, real
 * PostgreSQL migrated by Flyway.
 */
@Testcontainers
@AutoConfigureMetrics // Boot disables metric exporters in tests by default
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {"management.server.port=0", "spring.threads.virtual.enabled=false"})
class OrdersApiIntegrationTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11-alpine");

  static final RSAKey SIGNING_KEY = TestTokens.newRsaKey();
  static final JwksTestServer JWKS = JwksTestServer.start(SIGNING_KEY);

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry registry) {
    registry.add("platform.security.jwk-set-uri", JWKS::jwkSetUri);
  }

  @AfterAll
  static void stopJwks() {
    JWKS.close();
  }

  @LocalServerPort int port;
  @LocalManagementPort int managementPort;

  RestClient http;
  String alice;
  String bob;

  @BeforeEach
  void setUp() {
    http =
        RestClient.builder()
            .baseUrl("http://localhost:" + port)
            .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
            .build();
    alice = UUID.randomUUID().toString();
    bob = UUID.randomUUID().toString();
  }

  private ResponseEntity<String> get(String path, String token) {
    return http.get()
        .uri(path)
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        .retrieve()
        .toEntity(String.class);
  }

  private ResponseEntity<String> post(String path, String token, String body) {
    return http.post()
        .uri(path)
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .body(body == null ? "" : body)
        .retrieve()
        .toEntity(String.class);
  }

  private ResponseEntity<String> patch(String path, String token, String body) {
    return http.patch()
        .uri(path)
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .toEntity(String.class);
  }

  private String placeOrder(String subject) {
    ResponseEntity<String> created =
        post(
            "/api/v1/orders",
            TestTokens.user(SIGNING_KEY, subject),
            "{\"lines\":[{\"sku\":\"KB-001\",\"quantity\":2},{\"sku\":\"MS-002\",\"quantity\":1}]}");
    assertThat(created.getStatusCode().value()).isEqualTo(201);
    return JsonPath.read(created.getBody(), "$.id");
  }

  @Nested
  class CustomerFlow {

    @Test
    void catalogIsSeededByFlywayAndHidesInactiveProducts() {
      ResponseEntity<String> response =
          get("/api/v1/products", TestTokens.user(SIGNING_KEY, alice));

      assertThat(response.getStatusCode().value()).isEqualTo(200);
      List<String> skus = JsonPath.read(response.getBody(), "$[*].sku");
      assertThat(skus).contains("KB-001", "MS-002").doesNotContain("LEGACY-01");
    }

    @Test
    void placeOrderPricesItServerSideAndReturnsLocation() {
      ResponseEntity<String> created =
          post(
              "/api/v1/orders",
              TestTokens.user(SIGNING_KEY, alice),
              "{\"lines\":[{\"sku\":\"KB-001\",\"quantity\":2},{\"sku\":\"MS-002\",\"quantity\":1}]}");

      assertThat(created.getStatusCode().value()).isEqualTo(201);
      String id = JsonPath.read(created.getBody(), "$.id");
      assertThat(created.getHeaders().getLocation()).hasPath("/api/v1/orders/" + id);
      assertThat(JsonPath.<Double>read(created.getBody(), "$.totalAmount")).isEqualTo(207.50);
      assertThat(JsonPath.<String>read(created.getBody(), "$.status")).isEqualTo("PENDING");
      assertThat(JsonPath.<String>read(created.getBody(), "$.customerId")).isEqualTo(alice);

      ResponseEntity<String> fetched =
          get("/api/v1/orders/" + id, TestTokens.user(SIGNING_KEY, alice));
      assertThat(fetched.getStatusCode().value()).isEqualTo(200);
      assertThat(JsonPath.<List<?>>read(fetched.getBody(), "$.lines")).hasSize(2);
    }

    @Test
    void customersOnlySeeTheirOwnOrders() {
      String aliceOrder = placeOrder(alice);
      String bobToken = TestTokens.user(SIGNING_KEY, bob);

      assertThat(get("/api/v1/orders/" + aliceOrder, bobToken).getStatusCode().value())
          .isEqualTo(404); // not 403: do not reveal that the order exists
      assertThat(
              post("/api/v1/orders/" + aliceOrder + "/cancel", bobToken, null)
                  .getStatusCode()
                  .value())
          .isEqualTo(404);
      ResponseEntity<String> bobsList = get("/api/v1/orders", bobToken);
      assertThat(JsonPath.<Integer>read(bobsList.getBody(), "$.totalItems")).isZero();

      ResponseEntity<String> alicesList =
          get("/api/v1/orders", TestTokens.user(SIGNING_KEY, alice));
      assertThat(JsonPath.<List<String>>read(alicesList.getBody(), "$.items[*].id"))
          .containsExactly(aliceOrder);
    }

    @Test
    void pendingOrderCanBeCancelledOnce() {
      String id = placeOrder(alice);
      String token = TestTokens.user(SIGNING_KEY, alice);

      ResponseEntity<String> cancelled = post("/api/v1/orders/" + id + "/cancel", token, null);
      ResponseEntity<String> again = post("/api/v1/orders/" + id + "/cancel", token, null);

      assertThat(cancelled.getStatusCode().value()).isEqualTo(200);
      assertThat(JsonPath.<String>read(cancelled.getBody(), "$.status")).isEqualTo("CANCELLED");
      assertThat(again.getStatusCode().value()).isEqualTo(409);
    }

    @Test
    void unknownOrInactiveProductsAreUnprocessable() {
      String token = TestTokens.user(SIGNING_KEY, alice);

      ResponseEntity<String> unknown =
          post("/api/v1/orders", token, "{\"lines\":[{\"sku\":\"NOPE-404\",\"quantity\":1}]}");
      ResponseEntity<String> inactive =
          post("/api/v1/orders", token, "{\"lines\":[{\"sku\":\"LEGACY-01\",\"quantity\":1}]}");

      assertThat(unknown.getStatusCode().value()).isEqualTo(422);
      assertThat(JsonPath.<String>read(unknown.getBody(), "$.detail")).contains("NOPE-404");
      assertThat(inactive.getStatusCode().value()).isEqualTo(422);
    }
  }

  @Nested
  class AdminFlow {

    @Test
    void adminMovesOrderThroughLifecycleAndInvalidTransitionsConflict() {
      String id = placeOrder(alice);
      String admin = TestTokens.admin(SIGNING_KEY, UUID.randomUUID().toString());
      String path = "/api/v1/admin/orders/" + id + "/status";

      assertThat(patch(path, admin, "{\"status\":\"CONFIRMED\"}").getStatusCode().value())
          .isEqualTo(200);
      assertThat(patch(path, admin, "{\"status\":\"SHIPPED\"}").getStatusCode().value())
          .isEqualTo(200);
      ResponseEntity<String> backwards = patch(path, admin, "{\"status\":\"PENDING\"}");

      assertThat(backwards.getStatusCode().value()).isEqualTo(409);
      assertThat(JsonPath.<String>read(backwards.getBody(), "$.detail"))
          .contains("SHIPPED", "PENDING");
      ResponseEntity<String> shipped = get("/api/v1/admin/orders?status=SHIPPED", admin);
      assertThat(JsonPath.<List<String>>read(shipped.getBody(), "$.items[*].id")).contains(id);
    }

    @Test
    void customerTokenCannotUseAdminApi() {
      String id = placeOrder(alice);

      ResponseEntity<String> response =
          patch(
              "/api/v1/admin/orders/" + id + "/status",
              TestTokens.user(SIGNING_KEY, alice),
              "{\"status\":\"DELIVERED\"}");

      assertThat(response.getStatusCode().value()).isEqualTo(403);
    }
  }

  @Nested
  class TokenValidation {

    static List<String> rejectedTokens() {
      RSAKey attackerKey = TestTokens.newRsaKey();
      Instant past = Instant.now().minusSeconds(3600);
      String subject = UUID.randomUUID().toString();
      JWTClaimsSet valid = TestTokens.claims(subject, "USER", TestTokens.USER_SCOPES).build();
      return List.of(
          // no expiry: would never expire
          TestTokens.custom(SIGNING_KEY, subject, c -> c.expirationTime(null)),
          // expired
          TestTokens.custom(
              SIGNING_KEY,
              subject,
              c -> c.issueTime(Date.from(past)).expirationTime(Date.from(past.plusSeconds(60)))),
          // wrong issuer
          TestTokens.custom(SIGNING_KEY, subject, c -> c.issuer("https://evil.example.com")),
          // wrong audience
          TestTokens.custom(SIGNING_KEY, subject, c -> c.audience("another-api")),
          // missing subject
          TestTokens.custom(SIGNING_KEY, subject, c -> c.subject(null)),
          // signed by an unknown key that claims to be the trusted kid
          TestTokens.sign(attackerKey, SIGNING_KEY.getKeyID(), valid),
          // algorithm downgrade attempts
          TestTokens.hmac(SIGNING_KEY.getKeyID(), valid),
          TestTokens.unsigned(valid),
          // garbage
          "not-a-jwt");
    }

    @ParameterizedTest
    @MethodSource("rejectedTokens")
    void invalidTokensAreRejected(String token) {
      ResponseEntity<String> response = get("/api/v1/orders", token);

      assertThat(response.getStatusCode().value()).isEqualTo(401);
      assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer");
    }

    @Test
    void keyRotationIsPickedUpFromJwksWithoutRestart() {
      RSAKey rotated = TestTokens.newRsaKey();
      String token = TestTokens.user(rotated, alice);

      JWKS.publish(rotated); // rotation step 1: the auth service publishes the next key

      // Step 2: tokens signed with it arrive; the unknown kid triggers one JWKS refetch.
      assertThat(get("/api/v1/orders", token).getStatusCode().value()).isEqualTo(200);
      assertThat(get("/api/v1/orders", TestTokens.user(SIGNING_KEY, alice)).getStatusCode().value())
          .as("tokens signed by the previous key stay valid during rotation")
          .isEqualTo(200);
    }
  }

  @Nested
  class Operations {

    @Test
    void requestIdIsPropagatedOrGenerated() {
      ResponseEntity<String> echoed =
          http.get()
              .uri("/api/v1/orders")
              .header("X-Request-ID", "e2e-request-0001")
              .retrieve()
              .toEntity(String.class);
      ResponseEntity<String> generated =
          http.get()
              .uri("/api/v1/orders")
              .header("X-Request-ID", "not a valid id!")
              .retrieve()
              .toEntity(String.class);

      assertThat(echoed.getHeaders().getFirst("X-Request-ID")).isEqualTo("e2e-request-0001");
      assertThat(JsonPath.<String>read(echoed.getBody(), "$.request_id"))
          .isEqualTo("e2e-request-0001");
      assertThat(generated.getHeaders().getFirst("X-Request-ID")).hasSize(36);
    }

    @Test
    void apiDocsPageIsThemedAndServedUnderAStrictCsp() {
      ResponseEntity<String> page =
          http.get().uri("/docs/orders/swagger-ui/index.html").retrieve().toEntity(String.class);
      ResponseEntity<String> initializer =
          http.get()
              .uri("/docs/orders/swagger-ui/swagger-initializer.js")
              .retrieve()
              .toEntity(String.class);

      assertThat(page.getStatusCode().value()).isEqualTo(200);
      assertThat(page.getBody())
          .contains("href=\"/assets/docs.css\"")
          .contains("src=\"./swagger-initializer.js\"")
          .doesNotContain("<script>");
      assertThat(page.getHeaders().getFirst("Content-Security-Policy"))
          .contains("script-src 'self'")
          .contains("frame-ancestors 'none'")
          .doesNotContain("unsafe");
      assertThat(initializer.getStatusCode().value()).isEqualTo(200);
      assertThat(initializer.getBody())
          .contains("BaseLayout")
          .contains("/docs/orders/openapi.json");
    }

    @Test
    void healthAndMetricsAreServedOnTheManagementPortOnly() {
      placeOrder(alice);
      RestClient management =
          RestClient.builder()
              .baseUrl("http://localhost:" + managementPort)
              .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
              .build();

      ResponseEntity<String> readiness =
          management.get().uri("/actuator/health/readiness").retrieve().toEntity(String.class);
      ResponseEntity<String> metrics =
          management.get().uri("/actuator/prometheus").retrieve().toEntity(String.class);
      ResponseEntity<String> metricsOnApiPort =
          http.get().uri("/actuator/prometheus").retrieve().toEntity(String.class);

      assertThat(readiness.getStatusCode().value()).isEqualTo(200);
      assertThat(readiness.getBody()).contains("\"UP\"");
      assertThat(metrics.getBody())
          .contains("orders_placed_total")
          .contains("http_server_requests_seconds_bucket");
      assertThat(metricsOnApiPort.getStatusCode().value()).isNotEqualTo(200);
    }
  }
}
