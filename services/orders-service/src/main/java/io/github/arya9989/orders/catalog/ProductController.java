package io.github.arya9989.orders.catalog;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/products")
@Tag(name = "catalog")
public class ProductController {

  public record ProductResponse(String sku, String name, BigDecimal unitPrice, String currency) {
    static ProductResponse from(Product product) {
      return new ProductResponse(
          product.getSku(), product.getName(), product.getUnitPrice(), product.getCurrency());
    }
  }

  private final ProductRepository products;

  public ProductController(ProductRepository products) {
    this.products = products;
  }

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(summary = "List orderable products (scope orders:read)")
  public List<ProductResponse> list() {
    return products.findByActiveTrueOrderBySku().stream().map(ProductResponse::from).toList();
  }
}
