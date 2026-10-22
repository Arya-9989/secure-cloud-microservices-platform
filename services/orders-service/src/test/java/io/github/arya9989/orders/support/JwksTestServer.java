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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A stand-in for the auth service's {@code /.well-known/jwks.json}, backed by the JDK's built-in
 * HTTP server so tests exercise the real Nimbus JWKS fetching and caching code path.
 */
public final class JwksTestServer implements AutoCloseable {

  private final HttpServer server;
  private final List<JWK> publishedKeys = new CopyOnWriteArrayList<>();
  private final AtomicInteger requests = new AtomicInteger();

  private JwksTestServer(HttpServer server) {
    this.server = server;
  }

  public static JwksTestServer start(RSAKey initialKey) {
    try {
      HttpServer server =
          HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
      JwksTestServer jwks = new JwksTestServer(server);
      jwks.publish(initialKey);
      server.createContext(
          "/.well-known/jwks.json",
          exchange -> {
            jwks.requests.incrementAndGet();
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

  public String jwkSetUri() {
    return "http://127.0.0.1:" + server.getAddress().getPort() + "/.well-known/jwks.json";
  }

  public int requestCount() {
    return requests.get();
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
