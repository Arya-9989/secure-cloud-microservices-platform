package io.github.arya9989.orders;

import static org.assertj.core.api.Assertions.assertThat;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import io.github.arya9989.orders.dpop.JdbcDpopReplayCache;
import io.github.arya9989.orders.support.JwksTestServer;
import io.github.arya9989.orders.support.TestTokens;
import java.util.Date;
import java.util.UUID;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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
 * The service-to-service API over real HTTP with real RS256 tokens and real DPoP proofs (RFC 9449):
 * the nonce handshake, every proof check, downgrade to Bearer, audience and token-kind separation,
 * and the replay cache in PostgreSQL.
 */
@Testcontainers
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {"management.server.port=0", "spring.threads.virtual.enabled=false"})
class FulfilmentApiIntegrationTest {

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
  @Autowired JdbcDpopReplayCache replayCache;

  RestClient http;
  ECKey clientKey;
  String boundToken;

  @BeforeEach
  void setUp() {
    http =
        RestClient.builder()
            .baseUrl(base())
            .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
            .build();
    clientKey = TestTokens.newEcKey();
    boundToken = serviceToken(clientKey, TestTokens.RESOURCE, "orders:fulfil");
  }

  private String base() {
    return "http://localhost:" + port;
  }

  private static String serviceToken(ECKey key, String audience, String scope) {
    return TestTokens.sign(
        SIGNING_KEY, TestTokens.serviceClaims("fulfilment", scope, audience, key).build());
  }

  private ResponseEntity<String> call(
      HttpMethod method, String path, String scheme, String token, String proof, String body) {
    var request =
        http.method(method).uri(path).header(HttpHeaders.AUTHORIZATION, scheme + " " + token);
    if (proof != null) {
      request = request.header("DPoP", proof);
    }
    if (body != null) {
      request = request.contentType(MediaType.APPLICATION_JSON).body(body);
    }
    return request.retrieve().toEntity(String.class);
  }

  /** The RFC 9449 handshake: the first proof has no nonce and is answered with one. */
  private String nonce() {
    ResponseEntity<String> challenge =
        call(
            HttpMethod.GET,
            "/api/v1/fulfilment/orders",
            "DPoP",
            boundToken,
            proof("GET", "/api/v1/fulfilment/orders", null),
            null);
    assertThat(challenge.getStatusCode().value()).isEqualTo(401);
    return challenge.getHeaders().getFirst("DPoP-Nonce");
  }

  private String proof(String method, String path, String nonce) {
    return proof(method, path, nonce, c -> c);
  }

  private String proof(
      String method, String path, String nonce, UnaryOperator<JWTClaimsSet.Builder> customizer) {
    return TestTokens.dpopProof(clientKey, method, base() + path, boundToken, nonce, customizer);
  }

  private String confirmedOrder() {
    String customer = UUID.randomUUID().toString();
    ResponseEntity<String> created =
        http.post()
            .uri("/api/v1/orders")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.user(SIGNING_KEY, customer))
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"lines\":[{\"sku\":\"KB-001\",\"quantity\":1}]}")
            .retrieve()
            .toEntity(String.class);
    String id = JsonPath.read(created.getBody(), "$.id");
    http.patch()
        .uri("/api/v1/admin/orders/" + id + "/status")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.admin(SIGNING_KEY, "admin-1"))
        .contentType(MediaType.APPLICATION_JSON)
        .body("{\"status\":\"CONFIRMED\"}")
        .retrieve()
        .toBodilessEntity();
    return id;
  }

  @Test
  void theWarehouseShipsAConfirmedOrderWithADpopBoundToken() {
    String id = confirmedOrder();
    String nonce = nonce();
    String path = "/api/v1/fulfilment/orders/" + id + "/status";

    ResponseEntity<String> queue =
        call(
            HttpMethod.GET,
            "/api/v1/fulfilment/orders",
            "DPoP",
            boundToken,
            proof("GET", "/api/v1/fulfilment/orders", nonce),
            null);
    ResponseEntity<String> shipped =
        call(
            HttpMethod.PATCH,
            path,
            "DPoP",
            boundToken,
            proof("PATCH", path, nonce),
            "{\"status\":\"SHIPPED\"}");

    assertThat(queue.getStatusCode().value()).isEqualTo(200);
    assertThat(JsonPath.<java.util.List<String>>read(queue.getBody(), "$.items[*].id"))
        .contains(id);
    assertThat(queue.getHeaders().getFirst("DPoP-Nonce"))
        .as("a fresh nonce for the next proof")
        .isNotBlank();
    assertThat(shipped.getStatusCode().value()).isEqualTo(200);
    assertThat(JsonPath.<String>read(shipped.getBody(), "$.status")).isEqualTo("SHIPPED");
  }

  @Test
  void aMissingOrStaleNonceIsAnsweredWithUseDpopNonce() {
    ResponseEntity<String> missing =
        call(
            HttpMethod.GET,
            "/api/v1/fulfilment/orders",
            "DPoP",
            boundToken,
            proof("GET", "/api/v1/fulfilment/orders", null),
            null);
    ResponseEntity<String> forged =
        call(
            HttpMethod.GET,
            "/api/v1/fulfilment/orders",
            "DPoP",
            boundToken,
            proof("GET", "/api/v1/fulfilment/orders", "1.forged"),
            null);

    for (ResponseEntity<String> response : java.util.List.of(missing, forged)) {
      assertThat(response.getStatusCode().value()).isEqualTo(401);
      assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
          .startsWith("DPoP error=\"use_dpop_nonce\"");
      assertThat(response.getHeaders().getFirst("DPoP-Nonce")).isNotBlank();
      assertThat(response.getHeaders().getContentType().toString())
          .startsWith("application/problem+json");
    }
  }

  @Test
  void aProofIsSingleUse() {
    String nonce = nonce();
    String proof = proof("GET", "/api/v1/fulfilment/orders", nonce);

    ResponseEntity<String> first =
        call(HttpMethod.GET, "/api/v1/fulfilment/orders", "DPoP", boundToken, proof, null);
    ResponseEntity<String> replay =
        call(HttpMethod.GET, "/api/v1/fulfilment/orders", "DPoP", boundToken, proof, null);

    assertThat(first.getStatusCode().value()).isEqualTo(200);
    assertThat(replay.getStatusCode().value()).isEqualTo(401);
    assertThat(replay.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
        .startsWith("DPoP error=\"invalid_dpop_proof\"");
  }

  @Test
  void proofsForAnotherRequestKeyOrTokenAreRejected() {
    String nonce = nonce();
    String path = "/api/v1/fulfilment/orders";
    ECKey impostor = TestTokens.newEcKey();
    String[] proofs = {
      proof("POST", path, nonce), // wrong method
      proof("GET", "/api/v1/fulfilment/orders/other", nonce), // wrong URL
      TestTokens.dpopProof(
          clientKey, "GET", "https://evil.example" + path, boundToken, nonce, c -> c),
      proof("GET", path, nonce, c -> c.issueTime(new Date(System.currentTimeMillis() - 600_000))),
      proof("GET", path, nonce, c -> c.claim("ath", TestTokens.ath("another-token"))),
      // signed by a key that is not the one the token is bound to
      TestTokens.dpopProof(impostor, "GET", base() + path, boundToken, nonce, c -> c),
      "not-a-proof",
    };

    for (String proof : proofs) {
      ResponseEntity<String> response = call(HttpMethod.GET, path, "DPoP", boundToken, proof, null);
      assertThat(response.getStatusCode().value()).as(proof).isEqualTo(401);
      assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).startsWith("DPoP");
    }
  }

  @Test
  void aBoundTokenCannotBeDowngradedToBearer() {
    ResponseEntity<String> response =
        call(HttpMethod.GET, "/api/v1/fulfilment/orders", "Bearer", boundToken, null, null);

    assertThat(response.getStatusCode().value()).isEqualTo(401);
    assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
        .as("rejected by Spring Security or by DpopBindingFilter")
        .contains("error=\"invalid_token\"");
  }

  @Test
  void anUnboundServiceTokenIsNotEnoughForFulfilment() {
    String bearerOnly = serviceToken(null, TestTokens.RESOURCE, "orders:fulfil");

    ResponseEntity<String> response =
        call(HttpMethod.GET, "/api/v1/fulfilment/orders", "Bearer", bearerOnly, null, null);

    assertThat(response.getStatusCode().value()).isEqualTo(403);
  }

  @Test
  void tokensForAnotherServiceOrForPeopleAreRejected() {
    String forBilling = serviceToken(clientKey, "urn:secure-platform:billing", "orders:fulfil");
    String admin = TestTokens.admin(SIGNING_KEY, "admin-1");

    ResponseEntity<String> billing =
        call(
            HttpMethod.GET,
            "/api/v1/fulfilment/orders",
            "DPoP",
            forBilling,
            TestTokens.dpopProof(
                clientKey,
                "GET",
                base() + "/api/v1/fulfilment/orders",
                forBilling,
                nonce(),
                c -> c),
            null);
    ResponseEntity<String> person =
        call(HttpMethod.GET, "/api/v1/fulfilment/orders", "Bearer", admin, null, null);

    assertThat(billing.getStatusCode().value()).as("audience").isEqualTo(401);
    assertThat(person.getStatusCode().value()).as("an admin is not a service").isEqualTo(403);
  }

  @Test
  void aServiceTokenCannotActAsACustomer() {
    String scoped = serviceToken(null, TestTokens.AUDIENCE, "orders:read orders:write");

    ResponseEntity<String> response =
        call(HttpMethod.GET, "/api/v1/orders", "Bearer", scoped, null, null);

    assertThat(response.getStatusCode().value()).isEqualTo(403);
  }

  @Test
  void aDpopProofCannotBePassedOffAsAnAccessToken() {
    // Signed by the trusted key, valid claims: only the JOSE typ says it is a DPoP proof.
    String disguised =
        TestTokens.signWithType(
            SIGNING_KEY,
            "dpop+jwt",
            TestTokens.claims("mallory", "USER", TestTokens.USER_SCOPES).build());

    ResponseEntity<String> response =
        call(HttpMethod.GET, "/api/v1/orders", "Bearer", disguised, null, null);

    assertThat(response.getStatusCode().value()).isEqualTo(401);
  }

  @Test
  void theReplayCacheIsSharedStateInPostgresql() {
    String key = "proof-" + UUID.randomUUID();

    assertThat(replayCache.putIfAbsent(key, true)).as("first use").isNull();
    assertThat(replayCache.putIfAbsent(key, true)).as("any replica sees the replay").isNotNull();
    assertThat(replayCache.get(key)).isNotNull();
    assertThat(replayCache.purgeExpired()).isGreaterThanOrEqualTo(0);
  }
}
