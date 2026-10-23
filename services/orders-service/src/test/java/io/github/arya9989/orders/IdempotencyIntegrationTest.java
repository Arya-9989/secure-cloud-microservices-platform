package io.github.arya9989.orders;

import static org.assertj.core.api.Assertions.assertThat;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.RSAKey;
import io.github.arya9989.orders.idempotency.IdempotencyKeyPurger;
import io.github.arya9989.orders.support.JwksTestServer;
import io.github.arya9989.orders.support.TestTokens;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Idempotency keys over real HTTP and real PostgreSQL: replay, per-customer scope, fingerprint
 * mismatch, concurrent duplicates, in-flight duplicates, failed requests, TTL and purging.
 */
@Testcontainers
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
      "management.server.port=0",
      "spring.threads.virtual.enabled=false",
      "platform.orders.idempotency.lock-timeout=1s"
    })
class IdempotencyIntegrationTest {

  static final String ORDER = "{\"lines\":[{\"sku\":\"KB-001\",\"quantity\":2}]}";

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
  @Autowired JdbcClient jdbc;
  @Autowired DataSource dataSource;
  @Autowired IdempotencyKeyPurger purger;

  RestClient http;
  String alice;
  String key;

  @BeforeEach
  void setUp() {
    http =
        RestClient.builder()
            .baseUrl("http://localhost:" + port)
            .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
            .build();
    alice = UUID.randomUUID().toString();
    key = UUID.randomUUID().toString();
  }

  private ResponseEntity<String> place(String customer, String idempotencyKey, String body) {
    var request =
        http.post()
            .uri("/api/v1/orders")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.user(SIGNING_KEY, customer))
            .contentType(MediaType.APPLICATION_JSON)
            .body(body);
    if (idempotencyKey != null) {
      request = request.header("Idempotency-Key", idempotencyKey);
    }
    return request.retrieve().toEntity(String.class);
  }

  private int ordersOf(String customer) {
    return jdbc.sql("SELECT count(*) FROM orders WHERE customer_id = ?")
        .param(customer)
        .query(Integer.class)
        .single();
  }

  private static String id(ResponseEntity<String> response) {
    return JsonPath.read(response.getBody(), "$.id");
  }

  @Test
  void aRetryWithTheSameKeyReplaysTheOriginalResponse() {
    ResponseEntity<String> first = place(alice, key, ORDER);
    ResponseEntity<String> retry = place(alice, key, ORDER);

    assertThat(first.getStatusCode().value()).isEqualTo(201);
    assertThat(first.getHeaders().getFirst("Idempotent-Replayed")).isNull();
    assertThat(retry.getStatusCode().value()).isEqualTo(201);
    assertThat(retry.getHeaders().getFirst("Idempotent-Replayed")).isEqualTo("true");
    assertThat(retry.getBody()).isEqualTo(first.getBody());
    assertThat(retry.getHeaders().getLocation()).isEqualTo(first.getHeaders().getLocation());
    assertThat(ordersOf(alice)).isEqualTo(1);
  }

  @Test
  void theReplayIsTheResponseAsItWasEvenAfterTheOrderChanged() {
    ResponseEntity<String> first = place(alice, key, ORDER);
    http.post()
        .uri("/api/v1/orders/" + id(first) + "/cancel")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.user(SIGNING_KEY, alice))
        .retrieve()
        .toBodilessEntity();

    ResponseEntity<String> retry = place(alice, key, ORDER);

    assertThat(JsonPath.<String>read(retry.getBody(), "$.status")).isEqualTo("PENDING");
    assertThat(id(retry)).isEqualTo(id(first));
  }

  @Test
  void keysAreScopedToTheCustomer() {
    String bob = UUID.randomUUID().toString();

    ResponseEntity<String> alices = place(alice, key, ORDER);
    ResponseEntity<String> bobs = place(bob, key, ORDER);

    assertThat(bobs.getStatusCode().value()).isEqualTo(201);
    assertThat(bobs.getHeaders().getFirst("Idempotent-Replayed")).isNull();
    assertThat(id(bobs)).isNotEqualTo(id(alices));
    assertThat(JsonPath.<String>read(bobs.getBody(), "$.customerId")).isEqualTo(bob);
  }

  @Test
  void reusingAKeyForADifferentRequestIsRejected() {
    place(alice, key, ORDER);

    ResponseEntity<String> different =
        place(alice, key, "{\"lines\":[{\"sku\":\"KB-001\",\"quantity\":3}]}");

    assertThat(different.getStatusCode().value()).isEqualTo(422);
    assertThat(JsonPath.<String>read(different.getBody(), "$.detail"))
        .contains("different request");
    assertThat(ordersOf(alice)).isEqualTo(1);
  }

  @Test
  void formattingAndFieldOrderDoNotChangeTheRequest() {
    place(alice, key, ORDER);

    ResponseEntity<String> reformatted =
        place(
            alice,
            "\"" + key + "\"",
            "{ \"lines\" : [ { \"quantity\" : 2, \"sku\" : \"KB-001\" } ] }");

    assertThat(reformatted.getStatusCode().value()).isEqualTo(201);
    assertThat(reformatted.getHeaders().getFirst("Idempotent-Replayed")).isEqualTo("true");
  }

  @Test
  void concurrentDuplicatesPlaceExactlyOneOrder() throws Exception {
    int parallel = 8;
    CountDownLatch start = new CountDownLatch(1);
    List<Future<ResponseEntity<String>>> futures = new ArrayList<>();
    try (ExecutorService pool = Executors.newFixedThreadPool(parallel)) {
      for (int i = 0; i < parallel; i++) {
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  return place(alice, key, ORDER);
                }));
      }
      start.countDown();
      List<ResponseEntity<String>> responses = new ArrayList<>();
      for (Future<ResponseEntity<String>> future : futures) {
        responses.add(future.get());
      }

      assertThat(responses).allSatisfy(r -> assertThat(r.getStatusCode().value()).isEqualTo(201));
      Set<String> ids =
          responses.stream().map(IdempotencyIntegrationTest::id).collect(Collectors.toSet());
      assertThat(ids).hasSize(1);
      assertThat(
              responses.stream().filter(r -> r.getHeaders().containsHeader("Idempotent-Replayed")))
          .hasSize(parallel - 1);
      assertThat(ordersOf(alice)).isEqualTo(1);
    }
  }

  @Test
  void aDuplicateOfARequestStillRunningIsToldToRetry() throws Exception {
    // Another transaction holds an uncommitted claim, as a request in progress would.
    try (Connection inFlight = dataSource.getConnection()) {
      inFlight.setAutoCommit(false);
      try (PreparedStatement claim =
          inFlight.prepareStatement(
              "INSERT INTO idempotency_keys (customer_id, idempotency_key, request_hash,"
                  + " created_at, expires_at) VALUES (?, ?, repeat('0', 64), now(),"
                  + " now() + interval '1 hour')")) {
        claim.setString(1, alice);
        claim.setString(2, key);
        claim.executeUpdate();
      }
      long started = System.nanoTime();

      ResponseEntity<String> duplicate = place(alice, key, ORDER);

      assertThat(duplicate.getStatusCode().value()).isEqualTo(409);
      assertThat(duplicate.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("1");
      assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
      inFlight.rollback(); // the "first request" failed: the key is free again
    }

    assertThat(place(alice, key, ORDER).getStatusCode().value()).isEqualTo(201);
    assertThat(ordersOf(alice)).isEqualTo(1);
  }

  @Test
  void aFailedRequestDoesNotUseUpTheKey() {
    ResponseEntity<String> failed =
        place(alice, key, "{\"lines\":[{\"sku\":\"NOPE-404\",\"quantity\":1}]}");
    ResponseEntity<String> fixed = place(alice, key, ORDER);

    assertThat(failed.getStatusCode().value()).isEqualTo(422);
    assertThat(fixed.getStatusCode().value()).isEqualTo(201);
    assertThat(fixed.getHeaders().getFirst("Idempotent-Replayed")).isNull();
    assertThat(ordersOf(alice)).isEqualTo(1);
  }

  @Test
  void anExpiredKeyPlacesANewOrderAndIsPurged() {
    String firstId = id(place(alice, key, ORDER));
    jdbc.sql(
            "UPDATE idempotency_keys SET created_at = now() - interval '2 days',"
                + " expires_at = now() - interval '1 day' WHERE customer_id = ?")
        .param(alice)
        .update();

    ResponseEntity<String> afterTtl = place(alice, key, ORDER);

    assertThat(afterTtl.getStatusCode().value()).isEqualTo(201);
    assertThat(afterTtl.getHeaders().getFirst("Idempotent-Replayed")).isNull();
    assertThat(id(afterTtl)).isNotEqualTo(firstId);
    assertThat(ordersOf(alice)).isEqualTo(2);

    String other = UUID.randomUUID().toString();
    place(alice, other, ORDER);
    jdbc.sql(
            "UPDATE idempotency_keys SET expires_at = now() - interval '1 second',"
                + " created_at = now() - interval '1 day' WHERE idempotency_key = ?")
        .param(other)
        .update();

    assertThat(purger.purgeExpired()).isGreaterThanOrEqualTo(1);
    List<String> left =
        jdbc.sql("SELECT idempotency_key FROM idempotency_keys WHERE customer_id = ?")
            .param(alice)
            .query(String.class)
            .list();
    assertThat(left).containsExactly(key); // the live key survives, the expired one is gone
  }

  @Test
  void requestsWithoutAKeyBehaveAsBefore() {
    place(alice, null, ORDER);
    place(alice, null, ORDER);

    assertThat(ordersOf(alice)).isEqualTo(2);
    assertThat(
            jdbc.sql("SELECT count(*) FROM idempotency_keys WHERE customer_id = ?")
                .param(alice)
                .query(Integer.class)
                .single())
        .isZero();
  }
}
