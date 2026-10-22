package io.github.arya9989.orders.catalog;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, String> {

  List<Product> findByActiveTrueOrderBySku();

  List<Product> findBySkuInAndActiveTrue(Collection<String> skus);
}
