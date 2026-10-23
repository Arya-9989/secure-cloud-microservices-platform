package io.github.arya9989.orders.support;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A stand-in for the auth service's {@code /.well-known/jwks.json}, backed by the JDK's built-in
 * HTTP server so tests exercise the real Nimbus JWKS fetching and caching code path. It can also
 * play an auth service that is down ({@link #failWith}) or hanging ({@link #delayResponses}).
 */
public final class JwksTestServer implements AutoCloseable {

  private final HttpServer server;
  private final ExecutorService executor = Executors.newCachedThreadPool();
  private final List<JWK> publishedKeys = new CopyOnWriteArrayList<>();
  private final AtomicInteger requests = new AtomicInteger();
  private final Map<String, String> lastHeaders = new ConcurrentHashMap<>();
  private volatile int failureStatus;
  private volatile Duration delay = Duration.ZERO;

  private JwksTestServer(HttpServer server) {
    this.server = server;
  }

  public static JwksTestServer start(RSAKey initialKey) {
    try {
      HttpServer server =
          HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
      JwksTestServer jwks = new JwksTestServer(server);
      jwks.publish(initialKey);
      server.setExecutor(jwks.executor); // a delayed response must not block the next request
      server.createContext(
          "/.well-known/jwks.json",
          exchange -> {
            jwks.requests.incrementAndGet();
            jwks.lastHeaders.clear();
            exchange
                .getRequestHeaders()
                .forEach((name, values) -> jwks.lastHeaders.put(name.toLowerCase(), values.get(0)));
            try {
              Thread.sleep(jwks.delay);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
            int failure = jwks.failureStatus;
            if (failure != 0) {
              exchange.sendResponseHeaders(failure, -1);
              exchange.close();
              return;
            }
            byte[] body =
                new JWKSet(List.copyOf(jwks.publishedKeys))
                    .toString(true) // public members only
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) {
              out.write(body);
            }
          });
      server.start();
      return jwks;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Adds a key to the published set, as the auth service does during key rotation. */
  public void publish(RSAKey key) {
    publishedKeys.add(key.toPublicJWK());
  }

  /** Answers every request with {@code status} (e.g. 503), or serves the key set again with 0. */
  public void failWith(int status) {
    this.failureStatus = status;
  }

  /** Holds every response for {@code delay}, like an auth service that accepts but hangs. */
  public void delayResponses(Duration delay) {
    this.delay = delay;
  }

  public String jwkSetUri() {
    return "http://127.0.0.1:" + server.getAddress().getPort() + "/.well-known/jwks.json";
  }

  /** A header of the most recent JWKS request (lower-case name), or null. */
  public String lastRequestHeader(String name) {
    return lastHeaders.get(name.toLowerCase());
  }

  public int requestCount() {
    return requests.get();
  }

  @Override
  public void close() {
    server.stop(0);
    executor.shutdownNow();
  }
}
