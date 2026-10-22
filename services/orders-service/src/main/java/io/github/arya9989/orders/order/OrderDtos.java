package io.github.arya9989.orders.order;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Request and response bodies. Entities never leave the service layer. */
public final class OrderDtos {

  private OrderDtos() {}

  public record CreateOrderRequest(
      @NotEmpty @Size(max = 50) List<@Valid @NotNull LineRequest> lines) {}

  public record LineRequest(
      @NotNull @Pattern(regexp = "^[A-Z0-9-]{3,64}$") String sku,
      @NotNull @Min(1) @Max(1000) Integer quantity) {}

  public record UpdateStatusRequest(@NotNull OrderStatus status) {}

  public record LineResponse(
      int lineNumber, String sku, String productName, int quantity, BigDecimal unitPrice) {}

  public record OrderResponse(
      UUID id,
      String customerId,
      OrderStatus status,
      String currency,
      BigDecimal totalAmount,
      List<LineResponse> lines,
      Instant createdAt,
      Instant updatedAt) {

    static OrderResponse from(Order order) {
      return new OrderResponse(
          order.getId(),
          order.getCustomerId(),
          order.getStatus(),
          order.getCurrency(),
          order.getTotalAmount(),
          order.getLines().stream()
              .map(
                  l ->
                      new LineResponse(
                          l.getLineNumber(),
                          l.getSku(),
                          l.getProductName(),
                          l.getQuantity(),
                          l.getUnitPrice()))
              .toList(),
          order.getCreatedAt(),
          order.getUpdatedAt());
    }
  }
}
