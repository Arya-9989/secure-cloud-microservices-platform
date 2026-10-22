package io.github.arya9989.orders.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * 401/403 responses as RFC 9457 problem documents, so security failures look like every other API
 * error. The RFC 6750 {@code WWW-Authenticate} header is still set by Spring's bearer-token
 * handlers, which we delegate to first.
 */
@Component
public class ProblemDetailsSecurityHandlers
    implements AuthenticationEntryPoint, AccessDeniedHandler {

  private final BearerTokenAuthenticationEntryPoint entryPoint =
      new BearerTokenAuthenticationEntryPoint();
  private final BearerTokenAccessDeniedHandler deniedHandler = new BearerTokenAccessDeniedHandler();
  private final ObjectMapper objectMapper;

  public ProblemDetailsSecurityHandlers(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
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

  private void write(HttpServletResponse response, HttpStatus status, String detail)
      throws IOException {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    String requestId = RequestIdFilter.currentRequestId();
    if (requestId != null) {
      problem.setProperty("request_id", requestId);
    }
    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    objectMapper.writeValue(response.getOutputStream(), problem);
  }
}
