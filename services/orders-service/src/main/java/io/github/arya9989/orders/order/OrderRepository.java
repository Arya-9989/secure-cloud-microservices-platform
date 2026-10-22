package io.github.arya9989.orders.order;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<Order, UUID> {

  Page<Order> findByCustomerId(String customerId, Pageable pageable);

  /** Ownership is part of the query, so another customer's order is simply "not found". */
  Optional<Order> findByIdAndCustomerId(UUID id, String customerId);

  Page<Order> findByStatus(OrderStatus status, Pageable pageable);
}
