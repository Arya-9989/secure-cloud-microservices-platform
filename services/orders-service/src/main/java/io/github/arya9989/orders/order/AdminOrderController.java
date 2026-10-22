package io.github.arya9989.orders.order;

import io.github.arya9989.orders.order.OrderDtos.OrderResponse;
import io.github.arya9989.orders.order.OrderDtos.UpdateStatusRequest;
import io.github.arya9989.orders.web.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.UUID;
import org.jspecify.annotations.Nullable;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Back-office API: requires role ADMIN and scope orders:admin (see SecurityConfig). */
@RestController
@RequestMapping("/api/v1/admin/orders")
@Tag(name = "admin")
public class AdminOrderController {

  private final OrderService service;

  public AdminOrderController(OrderService service) {
    this.service = service;
  }

  @GetMapping
  @Operation(summary = "List all orders, optionally filtered by status")
  public PageResponse<OrderResponse> list(
      @RequestParam(required = false) @Nullable OrderStatus status,
      @RequestParam(defaultValue = "0") @Min(0) int page,
      @RequestParam(defaultValue = "50") @Min(1) @Max(200) int size) {
    PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    return PageResponse.of(service.listAll(status, pageable));
  }

  @PatchMapping("/{id}/status")
  @Operation(summary = "Move an order through its lifecycle (invalid transitions return 409)")
  public OrderResponse updateStatus(
      @PathVariable UUID id, @Valid @RequestBody UpdateStatusRequest request) {
    return service.updateStatus(id, request.status());
  }
}
