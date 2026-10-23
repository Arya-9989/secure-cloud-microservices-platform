package io.github.arya9989.orders;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.RSAKey;
import io.github.arya9989.orders.support.JwksTestServer;
import io.github.arya9989.orders.support.TestTokens;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Tracing as configured for production, with spans captured in memory instead of exported: the
 * gateway's {@code traceparent} is continued, the JWKS fetch and every SQL statement are children
 * of the request, the trace context reaches the auth service, and log lines carry the ids.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
@Import(TracingIntegrationTest.CapturedSpans.class)
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
      "management.server.port=0",
      "spring.threads.virtual.enabled=false",
      "management.tracing.export.enabled=true",
      "management.tracing.export.otlp.enabled=false",
      "management.opentelemetry.tracing.export.schedule-delay=50ms"
    })
class TracingIntegrationTest {

  static final String TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
  static final String GATEWAY_SPAN_ID = "00f067aa0ba902b7";

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

  @TestConfiguration(proxyBeanMethods = false)
  static class CapturedSpans {
    @Bean
    InMemorySpanExporter inMemorySpanExporter() {
      return InMemorySpanExporter.create();
    }
  }

  @Autowired InMemorySpanExporter spans;
  @LocalServerPort int port;
  RestClient http;

  @BeforeEach
  void setUp() {
    http =
        RestClient.builder()
            .baseUrl("http://localhost:" + port)
            .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
            .build();
    spans.reset();
  }

  private int placeOrder(String traceparent, String token) {
    var request =
        http.post()
            .uri("/api/v1/orders")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"lines\":[{\"sku\":\"KB-001\",\"quantity\":1}]}");
    if (traceparent != null) {
      request = request.header("traceparent", traceparent);
    }
    return request.retrieve().toBodilessEntity().getStatusCode().value();
  }

  private List<SpanData> spansOf(String traceId) {
    return spans.getFinishedSpanItems().stream()
        .filter(s -> s.getTraceId().equals(traceId))
        .toList();
  }

  @Test
  void oneRequestIsOneTraceThroughTheJwksFetchAndTheDatabase(CapturedOutput output) {
    // A key the service has never seen, so this request has to fetch the key set.
    RSAKey nextKey = TestTokens.newRsaKey();
    JWKS.publish(nextKey);
    String token = TestTokens.user(nextKey, UUID.randomUUID().toString());
    int jwksFetchesBefore = JWKS.requestCount();

    int status = placeOrder("00-" + TRACE_ID + "-" + GATEWAY_SPAN_ID + "-01", token);

    assertThat(status).isEqualTo(201);
    assertThat(JWKS.requestCount())
        .as("the unknown kid is fetched")
        .isGreaterThan(jwksFetchesBefore);
    waitUntil(
        () -> spansOf(TRACE_ID).stream().anyMatch(s -> s.getKind() == SpanKind.SERVER),
        Duration.ofSeconds(10));
    List<SpanData> trace = spansOf(TRACE_ID);

    SpanData server = only(trace, s -> s.getKind() == SpanKind.SERVER);
    assertThat(server.getParentSpanId())
        .as("continues the gateway's span")
        .isEqualTo(GATEWAY_SPAN_ID);
    assertThat(server.getName()).isEqualTo("http post /api/v1/orders");

    SpanData jwksFetch = only(trace, s -> s.getName().equals("GET /.well-known/jwks.json"));
    assertThat(jwksFetch.getKind()).isEqualTo(SpanKind.CLIENT);
    assertThat(ancestors(trace, jwksFetch)).contains(server.getSpanId());
    assertThat(JWKS.lastRequestHeader("traceparent"))
        .as("the auth service receives the same trace, parented on the fetch span")
        .isEqualTo("00-" + TRACE_ID + "-" + jwksFetch.getSpanId() + "-01");

    List<SpanData> queries = trace.stream().filter(s -> s.getName().startsWith("query")).toList();
    assertThat(queries).as("SQL statements are child spans").isNotEmpty();
    assertThat(queries)
        .allSatisfy(q -> assertThat(ancestors(trace, q)).contains(server.getSpanId()));
    assertThat(queries.toString())
        .as("parameter values are never recorded")
        .doesNotContain("KB-001");

    assertThat(output.getOut()).contains("\"trace_id\":\"" + TRACE_ID + "\"");
  }

  @Test
  void requestsTheGatewayDidNotSampleAreNotRecorded() {
    String token = TestTokens.user(SIGNING_KEY, UUID.randomUUID().toString());
    String unsampledTrace = "5bf92f3577b34da6a3ce929d0e0e4736";

    assertThat(placeOrder("00-" + unsampledTrace + "-" + GATEWAY_SPAN_ID + "-00", token))
        .isEqualTo(201);
    assertThat(placeOrder(null, token)).as("no trace context: a root span").isEqualTo(201);

    sleep(Duration.ofMillis(500)); // several export intervals
    assertThat(spans.getFinishedSpanItems()).isEmpty();
  }

  private static void waitUntil(BooleanSupplier condition, Duration timeout) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (!condition.getAsBoolean()) {
      assertThat(System.nanoTime()).as("condition not met within %s", timeout).isLessThan(deadline);
      sleep(Duration.ofMillis(50));
    }
  }

  private static void sleep(Duration duration) {
    try {
      Thread.sleep(duration);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  private static SpanData only(List<SpanData> trace, java.util.function.Predicate<SpanData> match) {
    List<SpanData> found = trace.stream().filter(match).toList();
    assertThat(found).as("spans in %s", trace).hasSize(1);
    return found.get(0);
  }

  /** Span ids from {@code span}'s parent up to the trace root, within the captured trace. */
  private static List<String> ancestors(List<SpanData> trace, SpanData span) {
    java.util.ArrayList<String> chain = new java.util.ArrayList<>();
    String parent = span.getParentSpanId();
    while (parent != null) {
      chain.add(parent);
      String current = parent;
      parent =
          trace.stream()
              .filter(s -> s.getSpanId().equals(current))
              .map(SpanData::getParentSpanId)
              .findFirst()
              .orElse(null);
    }
    return chain;
  }
}
