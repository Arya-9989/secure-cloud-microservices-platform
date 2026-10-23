package io.github.arya9989.orders.order;

import io.github.arya9989.orders.idempotency.IdempotencyKey;
import io.github.arya9989.orders.idempotency.IdempotentOrderPlacement;
import io.github.arya9989.orders.order.OrderDtos.CreateOrderRequest;
import io.github.arya9989.orders.order.OrderDtos.OrderResponse;
import io.github.arya9989.orders.web.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.net.URI;
import java.util.UUID;
import org.jspecify.annotations.Nullable;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/** Customer-facing API. The customer is always the token subject, never a request parameter. */
@RestController
@RequestMapping("/api/v1/orders")
@Tag(name = "orders")
public class OrderController {

  static final String REPLAYED_HEADER = "Idempotent-Replayed";

  private final OrderService service;
  private final IdempotentOrderPlacement placement;

  public OrderController(OrderService service, IdempotentOrderPlacement placement) {
    this.service = service;
    this.placement = placement;
  }

  @PostMapping
  @Operation(
      summary = "Place an order (scope orders:write)",
      description =
          "Send an Idempotency-Key to make retries safe: repeating the request with the same key"
              + " returns the original 201 (with Idempotent-Replayed: true) instead of placing a"
              + " second order. Keys are per customer and kept for 24 hours. Reusing a key for a"
              + " different request is 422; a duplicate that arrives while the first request is"
              + " still running is 409 with Retry-After.")
  @ApiResponse(
      responseCode = "201",
      description = "Order placed, or the stored response for a repeated Idempotency-Key",
      headers = {
        @Header(name = "Location", description = "URL of the order"),
        @Header(
            name = REPLAYED_HEADER,
            description = "true when this is the stored response of an earlier request")
      })
  public ResponseEntity<OrderResponse> place(
      @AuthenticationPrincipal Jwt jwt,
      @Parameter(
              in = ParameterIn.HEADER,
              description = "Unique per order attempt, 8-128 chars of [A-Za-z0-9._:-], e.g. a UUID",
              example = "8e03978e-40d5-43e8-bc93-6894a57f9324")
          @RequestHeader(name = IdempotencyKey.HEADER, required = false)
          @Nullable String idempotencyKey,
      @Valid @RequestBody CreateOrderRequest request) {
    IdempotentOrderPlacement.Result result =
        placement.place(jwt.getSubject(), IdempotencyKey.parse(idempotencyKey), request);
    URI location =
        ServletUriComponentsBuilder.fromCurrentRequest()
            .path("/{id}")
            .buildAndExpand(result.order().id())
            .toUri();
    ResponseEntity.BodyBuilder response = ResponseEntity.created(location);
    if (result.replayed()) {
      response.header(REPLAYED_HEADER, "true");
    }
    return response.body(result.order());
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
