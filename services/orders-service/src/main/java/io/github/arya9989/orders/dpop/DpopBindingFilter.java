package io.github.arya9989.orders.dpop;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs after authentication and before authorization.
 *
 * <ul>
 *   <li>Rejects a DPoP-bound access token ({@code cnf}) presented with the {@code Bearer} scheme
 *       (RFC 9449 section 7.1): without this, a stolen bound token could be used without the key.
 *   <li>Adds a fresh {@code DPoP-Nonce} to every DPoP request's response, so the client can sign
 *       its next proof without an extra round trip.
 * </ul>
 *
 * Constructed by {@code SecurityConfig}, not a bean: as a bean Spring Boot would also register it
 * as a servlet filter outside the security chain.
 */
public class DpopBindingFilter extends OncePerRequestFilter {

  private final DpopNonces nonces;
  private final DpopProblemHandler problems;

  public DpopBindingFilter(DpopNonces nonces, DpopProblemHandler problems) {
    this.nonces = nonces;
    this.problems = problems;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof JwtAuthenticationToken token
        && token.getToken().hasClaim("cnf")
        && startsWith(authorization, "Bearer ")) {
      SecurityContextHolder.clearContext();
      problems.challenge(
          response,
          "invalid_token",
          "This access token is DPoP-bound: send it as 'Authorization: DPoP' with a DPoP proof.");
      return;
    }
    if (startsWith(authorization, "DPoP ")) {
      response.setHeader(DpopProblemHandler.NONCE_HEADER, nonces.issue());
    }
    chain.doFilter(request, response);
  }

  private static boolean startsWith(@Nullable String header, String scheme) {
    return header != null && header.regionMatches(true, 0, scheme, 0, scheme.length());
  }
}
