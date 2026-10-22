import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Container HEALTHCHECK for the distroless image, which has no shell or curl. Exits 0 when the
 * given URL answers 2xx within two seconds.
 */
public final class HealthCheck {

  private HealthCheck() {}

  public static void main(String[] args) {
    try {
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
      HttpRequest request =
          HttpRequest.newBuilder(URI.create(args[0])).timeout(Duration.ofSeconds(2)).GET().build();
      int status = client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
      System.exit(status >= 200 && status < 300 ? 0 : 1);
    } catch (Exception e) {
      System.exit(1);
    }
  }
}
