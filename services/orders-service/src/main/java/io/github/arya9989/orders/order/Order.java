package io.github.arya9989.orders.order;

import io.github.arya9989.orders.catalog.Product;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/** Order aggregate root. All state changes go through methods that enforce invariants. */
@Entity
@Table(name = "orders")
public class Order {

  @Id private UUID id;

  /** The auth service's user id (JWT {@code sub}) of the customer who placed the order. */
  @Column(name = "customer_id", nullable = false, updatable = false, length = 64)
  private String customerId;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 16)
  private OrderStatus status;

  @Column(nullable = false, length = 3)
  private String currency;

  @Column(name = "total_amount", nullable = false, precision = 12, scale = 2)
  private BigDecimal totalAmount;

  @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
  @OrderBy("lineNumber")
  private List<OrderLine> lines = new ArrayList<>();

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  @Version private long version;

  protected Order() {}

  private Order(UUID id, String customerId, String currency, Instant now) {
    this.id = id;
    this.customerId = customerId;
    this.currency = currency;
    this.status = OrderStatus.PENDING;
    this.totalAmount = BigDecimal.ZERO.setScale(2);
    this.createdAt = now;
    this.updatedAt = now;
  }

  public static Order place(String customerId, String currency, Instant now) {
    return new Order(UUID.randomUUID(), customerId, currency, now);
  }

  void addLine(Product product, int quantity) {
    if (!product.getCurrency().equals(currency)) {
      throw new IllegalArgumentException("Product currency does not match order currency");
    }
    OrderLine line =
        new OrderLine(
            this,
            lines.size() + 1,
            product.getSku(),
            product.getName(),
            quantity,
            product.getUnitPrice());
    lines.add(line);
    totalAmount = totalAmount.add(line.lineTotal());
  }

  void transitionTo(OrderStatus target, Instant now) {
    if (!status.canTransitionTo(target)) {
      throw new InvalidOrderStateException(id, status, target);
    }
    status = target;
    updatedAt = now;
  }

  public boolean isOwnedBy(String subject) {
    return customerId.equals(subject);
  }

  public UUID getId() {
    return id;
  }

  public String getCustomerId() {
    return customerId;
  }

  public OrderStatus getStatus() {
    return status;
  }

  public String getCurrency() {
    return currency;
  }

  public BigDecimal getTotalAmount() {
    return totalAmount;
  }

  public List<OrderLine> getLines() {
    return Collections.unmodifiableList(lines);
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }
}
