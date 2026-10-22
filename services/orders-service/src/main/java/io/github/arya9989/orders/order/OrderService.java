package io.github.arya9989.orders.order;

import io.github.arya9989.orders.catalog.Product;
import io.github.arya9989.orders.catalog.ProductRepository;
import io.github.arya9989.orders.order.OrderDtos.CreateOrderRequest;
import io.github.arya9989.orders.order.OrderDtos.LineRequest;
import io.github.arya9989.orders.order.OrderDtos.OrderResponse;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Clock;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OrderService {

  private static final Logger log = LoggerFactory.getLogger(OrderService.class);

  private final OrderRepository orders;
  private final ProductRepository products;
  private final Clock clock;
  private final Counter ordersCreated;
  private final MeterRegistry meters;

  public OrderService(
      OrderRepository orders, ProductRepository products, Clock clock, MeterRegistry meters) {
    this.orders = orders;
    this.products = products;
    this.clock = clock;
    this.meters = meters;
    this.ordersCreated =
        Counter.builder("orders.placed").description("Orders placed").register(meters);
  }

  @Transactional
  public OrderResponse place(String customerId, CreateOrderRequest request) {
    Set<String> skus =
        request.lines().stream().map(LineRequest::sku).collect(Collectors.toUnmodifiableSet());
    Map<String, Product> catalog =
        products.findBySkuInAndActiveTrue(skus).stream()
            .collect(Collectors.toMap(Product::getSku, Function.identity()));

    Set<String> missing = new HashSet<>(skus);
    missing.removeAll(catalog.keySet());
    if (!missing.isEmpty()) {
      throw UnknownProductException.unknown(missing);
    }
    Set<String> currencies =
        catalog.values().stream().map(Product::getCurrency).collect(Collectors.toSet());
    if (currencies.size() > 1) {
      throw new UnknownProductException("All products in an order must share one currency.");
    }

    Order order = Order.place(customerId, currencies.iterator().next(), clock.instant());
    request.lines().forEach(line -> order.addLine(catalog.get(line.sku()), line.quantity()));
    orders.save(order);
    ordersCreated.increment();
    log.atInfo()
        .addKeyValue("order_id", order.getId())
        .addKeyValue("total_amount", order.getTotalAmount())
        .log("Order placed");
    return OrderResponse.from(order);
  }

  @Transactional(readOnly = true)
  public Page<OrderResponse> listForCustomer(String customerId, Pageable pageable) {
    return orders.findByCustomerId(customerId, pageable).map(OrderResponse::from);
  }

  @Transactional(readOnly = true)
  public OrderResponse getForCustomer(UUID id, String customerId) {
    return OrderResponse.from(findOwned(id, customerId));
  }

  /** Customers may cancel only while the order is still pending. */
  @Transactional
  public OrderResponse cancelForCustomer(UUID id, String customerId) {
    Order order = findOwned(id, customerId);
    if (order.getStatus() != OrderStatus.PENDING) {
      throw new InvalidOrderStateException(id, order.getStatus(), OrderStatus.CANCELLED);
    }
    return changeStatus(order, OrderStatus.CANCELLED);
  }

  @Transactional(readOnly = true)
  public Page<OrderResponse> listAll(@Nullable OrderStatus status, Pageable pageable) {
    Page<Order> page =
        status == null ? orders.findAll(pageable) : orders.findByStatus(status, pageable);
    return page.map(OrderResponse::from);
  }

  @Transactional
  public OrderResponse updateStatus(UUID id, OrderStatus target) {
    Order order = orders.findById(id).orElseThrow(() -> new OrderNotFoundException(id));
    return changeStatus(order, target);
  }

  private Order findOwned(UUID id, String customerId) {
    return orders
        .findByIdAndCustomerId(id, customerId)
        .orElseThrow(() -> new OrderNotFoundException(id));
  }

  private OrderResponse changeStatus(Order order, OrderStatus target) {
    OrderStatus from = order.getStatus();
    order.transitionTo(target, clock.instant());
    orders.saveAndFlush(order); // flush now so optimistic-lock conflicts surface as 409 here
    meters.counter("orders.status.changes", "to", target.name()).increment();
    log.atInfo()
        .addKeyValue("order_id", order.getId())
        .addKeyValue("from", from)
        .addKeyValue("to", target)
        .log("Order status changed");
    return OrderResponse.from(order);
  }
}
