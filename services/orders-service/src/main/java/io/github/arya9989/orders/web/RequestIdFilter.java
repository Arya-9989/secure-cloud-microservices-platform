package io.github.arya9989.orders.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.event.Level;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Correlation and access logging. Runs before Spring Security so even rejected requests carry an
 * {@code X-Request-ID} and produce exactly one structured access-log line.
 *
 * <p>The ID is taken from the gateway/client if it is well-formed (bounded length, safe
 * characters), otherwise generated. It is put in the logging MDC as {@code request_id}, the same
 * field name the Python services use.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

  public static final String HEADER = "X-Request-ID";
  static final String MDC_KEY = "request_id";
  private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9._:-]{8,128}$");
  private static final Set<String> QUIET_PATHS =
      Set.of("/actuator/health/liveness", "/actuator/health/readiness", "/actuator/prometheus");
  private static final Logger ACCESS = LoggerFactory.getLogger("access");

  public static @Nullable String currentRequestId() {
    return MDC.get(MDC_KEY);
  }

  static String resolve(@Nullable String incoming) {
    return incoming != null && VALID.matcher(incoming).matches()
        ? incoming
        : UUID.randomUUID().toString();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String requestId = resolve(request.getHeader(HEADER));
    MDC.put(MDC_KEY, requestId);
    response.setHeader(HEADER, requestId);
    long started = System.nanoTime();
    try {
      chain.doFilter(request, response);
    } finally {
      logAccess(request, response, (System.nanoTime() - started) / 1_000_000.0);
      MDC.remove(MDC_KEY);
    }
  }

  private static void logAccess(
      HttpServletRequest request, HttpServletResponse response, double durationMs) {
    Level level = QUIET_PATHS.contains(request.getRequestURI()) ? Level.DEBUG : Level.INFO;
    Object userId = request.getAttribute(AuthenticatedUserFilter.ATTRIBUTE);
    ACCESS
        .atLevel(level)
        .addKeyValue("http_method", request.getMethod())
        .addKeyValue("http_path", request.getRequestURI())
        .addKeyValue("http_status", response.getStatus())
        .addKeyValue("duration_ms", Math.round(durationMs * 100) / 100.0)
        .addKeyValue("user_id", userId)
        .log("{} {} {}", request.getMethod(), request.getRequestURI(), response.getStatus());
  }
}
