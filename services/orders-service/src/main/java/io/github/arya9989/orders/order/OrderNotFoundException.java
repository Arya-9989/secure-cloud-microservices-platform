package io.github.arya9989.orders.order;

import java.util.UUID;

public class OrderNotFoundException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public OrderNotFoundException(UUID id) {
    super("Order " + id + " was not found.");
  }
}
