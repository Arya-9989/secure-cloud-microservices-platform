package io.github.arya9989.orders.order;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

class OrderStatusTest {

  @ParameterizedTest(name = "{0} -> {1} allowed={2}")
  @CsvSource({
    "PENDING, CONFIRMED, true",
    "PENDING, CANCELLED, true",
    "PENDING, SHIPPED, false",
    "CONFIRMED, SHIPPED, true",
    "CONFIRMED, CANCELLED, true",
    "CONFIRMED, PENDING, false",
    "SHIPPED, DELIVERED, true",
    "SHIPPED, CANCELLED, false",
    "DELIVERED, PENDING, false",
    "CANCELLED, CONFIRMED, false",
  })
  void transitions(OrderStatus from, OrderStatus to, boolean allowed) {
    assertThat(from.canTransitionTo(to)).isEqualTo(allowed);
  }

  @ParameterizedTest
  @EnumSource(
      value = OrderStatus.class,
      names = {"DELIVERED", "CANCELLED"})
  void terminalStatesHaveNoSuccessors(OrderStatus status) {
    assertThat(status.next()).isEmpty();
  }

  @Test
  void noStatusCanTransitionToItself() {
    for (OrderStatus status : OrderStatus.values()) {
      assertThat(status.canTransitionTo(status)).as(status.name()).isFalse();
    }
  }
}
