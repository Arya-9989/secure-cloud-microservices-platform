package io.github.arya9989.orders.config;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.transport.Kind;
import io.micrometer.observation.transport.SenderContext;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The Nimbus JWKS retriever, unchanged (same timeouts and size limit), with each fetch recorded as
 * a client observation named {@code jwks.fetch}.
 *
 * <p>With tracing on, the fetch becomes a child span of the request that triggered it and carries
 * the W3C {@code traceparent}, so auth-service's span joins the same trace. The observation also
 * yields a {@code jwks_fetch_seconds} timer, which shows how often forged or rotated key ids make
 * the service call the auth service. Without a tracer (tracing off, tests) it costs a timer only.
 */
final class ObservedJwksRetriever extends DefaultResourceRetriever {

  static final String OBSERVATION = "jwks.fetch";

  private final ObservationRegistry registry;

  /** Headers the tracing handler injected for the fetch running on this thread. */
  private final ThreadLocal<Map<String, String>> propagationHeaders = new ThreadLocal<>();

  ObservedJwksRetriever(
      int connectTimeoutMillis,
      int readTimeoutMillis,
      int sizeLimit,
      ObservationRegistry registry) {
    super(connectTimeoutMillis, readTimeoutMillis, sizeLimit);
    this.registry = registry;
  }

  @Override
  public Resource retrieveResource(URL url) throws IOException {
    Map<String, String> headers = new LinkedHashMap<>();
    SenderContext<Map<String, String>> context =
        new SenderContext<>((carrier, key, value) -> carrier.put(key, value), Kind.CLIENT);
    context.setCarrier(headers);
    context.setRemoteServiceAddress(url.getHost() + ":" + url.getPort());
    Observation observation =
        Observation.createNotStarted(OBSERVATION, () -> context, registry)
            .contextualName("GET " + url.getPath())
            .lowCardinalityKeyValue(KeyValue.of("server.address", url.getHost()))
            .start(); // the tracing handler fills `headers` here
    propagationHeaders.set(headers);
    Observation.Scope scope = observation.openScope();
    try {
      return super.retrieveResource(url);
    } catch (IOException | RuntimeException e) {
      observation.error(e);
      throw e;
    } finally {
      scope.close();
      propagationHeaders.remove();
      observation.stop();
    }
  }

  @Override
  protected HttpURLConnection openHTTPConnection(URL url) throws IOException {
    HttpURLConnection connection = super.openHTTPConnection(url);
    Map<String, String> headers = propagationHeaders.get();
    if (headers != null) {
      headers.forEach(connection::setRequestProperty);
    }
    return connection;
  }
}
