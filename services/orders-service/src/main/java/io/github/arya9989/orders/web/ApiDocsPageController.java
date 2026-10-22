package io.github.arya9989.orders.web;

import java.nio.charset.StandardCharsets;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the Swagger UI page with the platform theme in place of the stock {@code index.html}.
 *
 * <p>springdoc redirects {@code /docs/orders/swagger-ui.html} here and still serves every other
 * Swagger UI asset (bundle, styles and the generated {@code swagger-initializer.js}) from the
 * webjar, so the page stays version-agnostic: it only references those assets by relative path. A
 * request mapping outranks springdoc's resource handler for this one path.
 */
@Controller
public class ApiDocsPageController {

  static final String PATH = "/docs/orders/swagger-ui/index.html";
  private static final Resource PAGE = new ClassPathResource("api-docs/index.html");

  @GetMapping(path = PATH, produces = MediaType.TEXT_HTML_VALUE)
  ResponseEntity<Resource> page() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .contentType(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8))
        .body(PAGE);
  }
}
