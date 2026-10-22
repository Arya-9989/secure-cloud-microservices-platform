package io.github.arya9989.orders.idempotency;

import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * A validated {@code Idempotency-Key} header value (draft-ietf-httpapi-idempotency-key-header).
 *
 * <p>The draft defines the value as a structured-field string ({@code "8e03978e-…"}); clients that
 * send it bare (as Stripe-style APIs do) are accepted too. Either way the key must be 8–128
 * characters of {@code [A-Za-z0-9._:-]}, which a UUID satisfies, so it is safe to log and store.
 *
 * @param value the key without surrounding quotes
 */
public record IdempotencyKey(String value) {

  public static final String HEADER = "Idempotency-Key";
  private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9._:-]{8,128}$");

  public IdempotencyKey {
    if (!VALID.matcher(value).matches()) {
      throw new InvalidIdempotencyKeyException();
    }
  }

  /** The key from a header value, or {@code null} when the header is absent. */
  public static @Nullable IdempotencyKey parse(@Nullable String header) {
    if (header == null) {
      return null;
    }
    String value = header.strip();
    if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
      value = value.substring(1, value.length() - 1);
    }
    return new IdempotencyKey(value);
  }

  /** The {@code Idempotency-Key} header is malformed (HTTP 400). */
  public static class InvalidIdempotencyKeyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    InvalidIdempotencyKeyException() {
      super(
          HEADER
              + " must be 8-128 characters of letters, digits and . _ : -"
              + " (a UUID is a good choice).");
    }
  }
}
