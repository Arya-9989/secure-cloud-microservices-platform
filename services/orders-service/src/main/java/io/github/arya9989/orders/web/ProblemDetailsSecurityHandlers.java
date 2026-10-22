package io.github.arya9989.orders.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * 401/403 responses as RFC 9457 problem documents, so security failures look like every other API
 * error. The RFC 6750 {@code WWW-Authenticate} header is still set by Spring's bearer-token
 * handlers, which we delegate to first.
 *
 * <p>As the bearer-token failure handler it also separates "this token is bad" (401) from "the
 * token cannot be checked right now" (503), e.g. when the signing keys are not cached yet and the
 * auth service is unreachable. A 401 there would tell clients to discard a valid token; Spring's
 * default would surface it as a 500.
 */
@Component
public class ProblemDetailsSecurityHandlers
    implements AuthenticationEntryPoint, AccessDeniedHandler, AuthenticationFailureHandler {

  static final String RETRY_AFTER_SECONDS = "10";
  private static final Logger LOG = LoggerFactory.getLogger(ProblemDetailsSecurityHandlers.class);

  private final BearerTokenAuthenticationEntryPoint entryPoint =
      new BearerTokenAuthenticationEntryPoint();
  private final BearerTokenAccessDeniedHandler deniedHandler = new BearerTokenAccessDeniedHandler();
  private final JsonMapper jsonMapper;

  public ProblemDetailsSecurityHandlers(JsonMapper jsonMapper) {
    this.jsonMapper = jsonMapper;
  }

  @Override
  public void commence(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
      throws IOException {
    entryPoint.commence(request, response, ex);
    write(response, HttpStatus.UNAUTHORIZED, "A valid bearer access token is required.");
  }

  @Override
  public void handle(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
      throws IOException {
    deniedHandler.handle(request, response, ex);
    write(
        response, HttpStatus.FORBIDDEN, "The access token does not grant access to this resource.");
  }

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
      throws IOException {
    if (ex instanceof AuthenticationServiceException) {
      LOG.warn("Cannot verify access tokens: {}", ex.getMessage());
      response.setHeader(HttpHeaders.RETRY_AFTER, RETRY_AFTER_SECONDS);
      write(
          response,
          HttpStatus.SERVICE_UNAVAILABLE,
          "Access tokens cannot be verified right now because the signing keys are unavailable."
              + " Retry the request; the token was not rejected.");
      return;
    }
    commence(request, response, ex);
  }

  private void write(HttpServletResponse response, HttpStatus status, String detail)
      throws IOException {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    String requestId = RequestIdFilter.currentRequestId();
    if (requestId != null) {
      problem.setProperty("request_id", requestId);
    }
    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    jsonMapper.writeValue(response.getOutputStream(), problem);
  }
}
