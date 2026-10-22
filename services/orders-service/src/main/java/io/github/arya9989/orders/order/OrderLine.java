package io.github.arya9989.orders.order;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.math.BigDecimal;

/** One product line of an order. Name and price are snapshotted at order time. */
@Entity
@Table(name = "order_lines")
public class OrderLine {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "order_id", nullable = false)
  private Order order;

  @Column(name = "line_number", nullable = false)
  private int lineNumber;

  @Column(nullable = false, length = 64)
  private String sku;

  @Column(name = "product_name", nullable = false, length = 200)
  private String productName;

  @Column(nullable = false)
  private int quantity;

  @Column(name = "unit_price", nullable = false, precision = 12, scale = 2)
  private BigDecimal unitPrice;

  protected OrderLine() {}

  OrderLine(
      Order order,
      int lineNumber,
      String sku,
      String productName,
      int quantity,
      BigDecimal unitPrice) {
    this.order = order;
    this.lineNumber = lineNumber;
    this.sku = sku;
    this.productName = productName;
    this.quantity = quantity;
    this.unitPrice = unitPrice;
  }

  BigDecimal lineTotal() {
    return unitPrice.multiply(BigDecimal.valueOf(quantity));
  }

  public int getLineNumber() {
    return lineNumber;
  }

  public String getSku() {
    return sku;
  }

  public String getProductName() {
    return productName;
  }

  public int getQuantity() {
    return quantity;
  }

  public BigDecimal getUnitPrice() {
    return unitPrice;
  }
}
