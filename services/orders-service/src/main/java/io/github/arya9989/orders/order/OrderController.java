package io.github.arya9989.orders.order;

import io.github.arya9989.orders.order.OrderDtos.CreateOrderRequest;
import io.github.arya9989.orders.order.OrderDtos.OrderResponse;
import io.github.arya9989.orders.web.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.net.URI;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/** Customer-facing API. The customer is always the token subject, never a request parameter. */
@RestController
@RequestMapping("/api/v1/orders")
@Tag(name = "orders")
public class OrderController {

  private final OrderService service;

  public OrderController(OrderService service) {
    this.service = service;
  }

  @PostMapping
  @Operation(summary = "Place an order (scope orders:write)")
  public ResponseEntity<OrderResponse> place(
      @AuthenticationPrincipal Jwt jwt, @Valid @RequestBody CreateOrderRequest request) {
    OrderResponse created = service.place(jwt.getSubject(), request);
    URI location =
        ServletUriComponentsBuilder.fromCurrentRequest()
            .path("/{id}")
            .buildAndExpand(created.id())
            .toUri();
    return ResponseEntity.created(location).body(created);
  }

  @GetMapping
  @Operation(summary = "List the caller's orders, newest first (scope orders:read)")
  public PageResponse<OrderResponse> list(
      @AuthenticationPrincipal Jwt jwt,
      @RequestParam(defaultValue = "0") @Min(0) int page,
      @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
    PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    return PageResponse.of(service.listForCustomer(jwt.getSubject(), pageable));
  }

  @GetMapping("/{id}")
  @Operation(summary = "Get one of the caller's orders (scope orders:read)")
  public OrderResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
    return service.getForCustomer(id, jwt.getSubject());
  }

  @PostMapping("/{id}/cancel")
  @Operation(summary = "Cancel a pending order (scope orders:write)")
  public OrderResponse cancel(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
    return service.cancelForCustomer(id, jwt.getSubject());
  }
}
