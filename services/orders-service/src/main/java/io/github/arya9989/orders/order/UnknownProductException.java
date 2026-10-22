package io.github.arya9989.orders.order;

import java.util.Collection;

/** The order request is well-formed but cannot be fulfilled as asked (HTTP 422). */
public class UnknownProductException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public UnknownProductException(String message) {
    super(message);
  }

  public static UnknownProductException unknown(Collection<String> skus) {
    return new UnknownProductException(
        "Unknown or unavailable product(s): " + String.join(", ", skus.stream().sorted().toList()));
  }
}
