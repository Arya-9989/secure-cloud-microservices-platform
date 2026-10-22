package io.github.arya9989.orders.order;

import java.util.EnumSet;
import java.util.Set;

/** Order lifecycle. Allowed transitions are declared here and nowhere else. */
public enum OrderStatus {
  PENDING,
  CONFIRMED,
  SHIPPED,
  DELIVERED,
  CANCELLED;

  public Set<OrderStatus> next() {
    return switch (this) {
      case PENDING -> EnumSet.of(CONFIRMED, CANCELLED);
      case CONFIRMED -> EnumSet.of(SHIPPED, CANCELLED);
      case SHIPPED -> EnumSet.of(DELIVERED);
      case DELIVERED, CANCELLED -> EnumSet.noneOf(OrderStatus.class);
    };
  }

  public boolean canTransitionTo(OrderStatus target) {
    return next().contains(target);
  }
}
