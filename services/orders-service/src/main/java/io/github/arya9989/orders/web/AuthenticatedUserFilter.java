package io.github.arya9989.orders.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs inside the security chain, right after bearer-token authentication, and records the caller's
 * subject in the MDC (for application logs) and as a request attribute (for the access log written
 * by {@link RequestIdFilter} after the security context has been cleared).
 */
public class AuthenticatedUserFilter extends OncePerRequestFilter {

  static final String ATTRIBUTE = AuthenticatedUserFilter.class.getName() + ".user_id";
  static final String MDC_KEY = "user_id";

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof JwtAuthenticationToken token) {
      request.setAttribute(ATTRIBUTE, token.getName());
      MDC.put(MDC_KEY, token.getName());
    }
    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove(MDC_KEY);
    }
  }
}
