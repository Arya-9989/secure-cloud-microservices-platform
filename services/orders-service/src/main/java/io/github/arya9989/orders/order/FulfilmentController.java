package io.github.arya9989.orders.order;

import io.github.arya9989.orders.order.OrderDtos.OrderResponse;
import io.github.arya9989.orders.web.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-to-service API for the warehouse: its work queue and the two moves it may make.
 *
 * <p>Callers are services, not people: scope {@code orders:fulfil}, this service as the token's
 * audience, and a DPoP-bound token (see {@code SecurityConfig}). They can neither confirm nor
 * cancel orders, and the order state machine still decides which moves are valid (409 otherwise).
 */
@RestController
@RequestMapping("/api/v1/fulfilment/orders")
@Tag(name = "fulfilment")
public class FulfilmentController {

  private static final Logger log = LoggerFactory.getLogger(FulfilmentController.class);

  /** The statuses a fulfilment system may set; anything else is rejected as 400. */
  public enum FulfilmentStatus {
    SHIPPED,
    DELIVERED;

    OrderStatus toOrderStatus() {
      return OrderStatus.valueOf(name());
    }
  }

  public record FulfilmentUpdate(@NotNull FulfilmentStatus status) {}

  private final OrderService service;

  public FulfilmentController(OrderService service) {
    this.service = service;
  }

  @GetMapping
  @Operation(
      summary = "Orders waiting for the warehouse (default CONFIRMED)",
      description = "Requires a DPoP-bound client-credentials token with scope orders:fulfil.")
  public PageResponse<OrderResponse> queue(
      @RequestParam(defaultValue = "CONFIRMED") OrderStatus status,
      @RequestParam(defaultValue = "0") @Min(0) int page,
      @RequestParam(defaultValue = "50") @Min(1) @Max(200) int size) {
    PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "createdAt"));
    return PageResponse.of(service.listAll(status, pageable));
  }

  @PatchMapping("/{id}/status")
  @Operation(summary = "Mark an order shipped or delivered (invalid transitions return 409)")
  public OrderResponse update(
      @AuthenticationPrincipal Jwt jwt,
      @PathVariable UUID id,
      @Valid @RequestBody FulfilmentUpdate update) {
    OrderResponse updated = service.updateStatus(id, update.status().toOrderStatus());
    log.atInfo()
        .addKeyValue("order_id", id)
        .addKeyValue("client_id", jwt.getClaimAsString("client_id"))
        .addKeyValue("to", update.status())
        .log("Order status changed by fulfilment client");
    return updated;
  }
}
