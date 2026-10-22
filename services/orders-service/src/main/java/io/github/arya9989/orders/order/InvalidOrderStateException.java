package io.github.arya9989.orders.order;

import java.util.UUID;

public class InvalidOrderStateException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public InvalidOrderStateException(UUID id, OrderStatus from, OrderStatus to) {
    super("Order " + id + " cannot move from " + from + " to " + to + ".");
  }
}
