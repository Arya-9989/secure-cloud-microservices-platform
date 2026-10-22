package io.github.arya9989.orders.dpop;

import io.github.arya9989.orders.web.ProblemDetailsSecurityHandlers;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/**
 * Answers a failed DPoP authentication with RFC 9449's challenge and an RFC 9457 problem body.
 *
 * <p>Spring reports every proof failure as {@code invalid_dpop_proof}; a missing or stale nonce is
 * told apart here (from the validation errors behind it) and answered with {@code use_dpop_nonce}
 * plus a fresh {@code DPoP-Nonce}, so a well-behaved client simply retries. Every DPoP challenge
 * carries a fresh nonce. Key-set outages stay 503, as for bearer tokens.
 */
@Component
public class DpopProblemHandler implements AuthenticationFailureHandler {

  public static final String NONCE_HEADER = "DPoP-Nonce";
  static final String ALGORITHMS = "ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512";

  private final ProblemDetailsSecurityHandlers problems;
  private final DpopNonces nonces;

  public DpopProblemHandler(ProblemDetailsSecurityHandlers problems, DpopNonces nonces) {
    this.problems = problems;
    this.nonces = nonces;
  }

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
      throws IOException {
    if (ex instanceof AuthenticationServiceException) {
      problems.onAuthenticationFailure(request, response, ex); // 503: keys unavailable
      return;
    }
    boolean needsNonce = needsNonce(ex);
    String error =
        needsNonce
            ? DpopProofVerification.USE_DPOP_NONCE
            : ex instanceof OAuth2AuthenticationException oauth
                ? oauth.getError().getErrorCode()
                : "invalid_token";
    String detail =
        needsNonce
            ? "Sign the DPoP proof with the nonce from the DPoP-Nonce header and retry."
            : "The DPoP proof or the DPoP-bound access token is invalid.";
    challenge(response, error, detail);
  }

  /** Writes a 401 with {@code WWW-Authenticate: DPoP error=...} and a fresh nonce. */
  public void challenge(HttpServletResponse response, String error, String detail)
      throws IOException {
    response.setHeader(
        HttpHeaders.WWW_AUTHENTICATE,
        "DPoP error=\""
            + error
            + "\", error_description=\""
            + detail
            + "\", algs=\""
            + ALGORITHMS
            + "\"");
    response.setHeader(NONCE_HEADER, nonces.issue());
    problems.write(response, HttpStatus.UNAUTHORIZED, detail);
  }

  static boolean needsNonce(Throwable failure) {
    for (Throwable t = failure; t != null; t = t.getCause()) {
      if (t instanceof JwtValidationException invalid
          && invalid.getErrors().stream()
              .anyMatch(e -> DpopProofVerification.USE_DPOP_NONCE.equals(e.getErrorCode()))) {
        return true;
      }
    }
    return false;
  }
}
