package io.github.arya9989.orders.web;

import io.github.arya9989.orders.order.InvalidOrderStateException;
import io.github.arya9989.orders.order.OrderNotFoundException;
import io.github.arya9989.orders.order.UnknownProductException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Maps domain exceptions to RFC 9457 problem details and stamps every problem with the request ID.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

  @ExceptionHandler(OrderNotFoundException.class)
  ProblemDetail notFound(OrderNotFoundException ex) {
    return withRequestId(ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage()));
  }

  @ExceptionHandler(InvalidOrderStateException.class)
  ProblemDetail conflict(InvalidOrderStateException ex) {
    return withRequestId(ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage()));
  }

  @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
  ProblemDetail concurrentUpdate(ObjectOptimisticLockingFailureException ex) {
    return withRequestId(
        ProblemDetail.forStatusAndDetail(
            HttpStatus.CONFLICT, "The order was modified concurrently; retry the request."));
  }

  @ExceptionHandler(UnknownProductException.class)
  ProblemDetail unknownProduct(UnknownProductException ex) {
    return withRequestId(
        ProblemDetail.forStatusAndDetail(HttpStatus.UNPROCESSABLE_ENTITY, ex.getMessage()));
  }

  @Override
  protected ResponseEntity<Object> handleExceptionInternal(
      Exception ex,
      @Nullable Object body,
      HttpHeaders headers,
      HttpStatusCode statusCode,
      WebRequest request) {
    if (body instanceof ProblemDetail problem) {
      withRequestId(problem);
    }
    return super.handleExceptionInternal(ex, body, headers, statusCode, request);
  }

  private static ProblemDetail withRequestId(ProblemDetail problem) {
    String requestId = RequestIdFilter.currentRequestId();
    if (requestId != null) {
      problem.setProperty("request_id", requestId);
    }
    return problem;
  }
}
