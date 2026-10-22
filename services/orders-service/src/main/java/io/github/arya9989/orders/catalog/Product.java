package io.github.arya9989.orders.catalog;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;

/**
 * A sellable item. Prices live server-side: clients order by SKU and quantity and never send a
 * price, so totals cannot be tampered with.
 */
@Entity
@Table(name = "products")
public class Product {

  @Id
  @Column(length = 64)
  private String sku;

  @Column(nullable = false, length = 200)
  private String name;

  @Column(name = "unit_price", nullable = false, precision = 12, scale = 2)
  private BigDecimal unitPrice;

  @Column(nullable = false, length = 3)
  private String currency;

  @Column(nullable = false)
  private boolean active;

  protected Product() {}

  public Product(String sku, String name, BigDecimal unitPrice, String currency, boolean active) {
    this.sku = sku;
    this.name = name;
    this.unitPrice = unitPrice;
    this.currency = currency;
    this.active = active;
  }

  public String getSku() {
    return sku;
  }

  public String getName() {
    return name;
  }

  public BigDecimal getUnitPrice() {
    return unitPrice;
  }

  public String getCurrency() {
    return currency;
  }

  public boolean isActive() {
    return active;
  }
}
