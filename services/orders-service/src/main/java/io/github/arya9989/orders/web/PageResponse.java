package io.github.arya9989.orders.web;

import java.util.List;
import org.springframework.data.domain.Page;

/** Stable pagination envelope (Spring's {@code Page} JSON shape is not a public contract). */
public record PageResponse<T>(List<T> items, int page, int size, long totalItems, int totalPages) {

  public static <T> PageResponse<T> of(Page<T> page) {
    return new PageResponse<>(
        page.getContent(),
        page.getNumber(),
        page.getSize(),
        page.getTotalElements(),
        page.getTotalPages());
  }
}
