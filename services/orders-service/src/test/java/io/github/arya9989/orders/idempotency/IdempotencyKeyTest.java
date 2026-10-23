package io.github.arya9989.orders.idempotency;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arya9989.orders.idempotency.IdempotencyKey.InvalidIdempotencyKeyException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class IdempotencyKeyTest {

  @ParameterizedTest
  @ValueSource(
      strings = {
        "8e03978e-40d5-43e8-bc93-6894a57f9324",
        "\"8e03978e-40d5-43e8-bc93-6894a57f9324\"", // RFC 8941 sf-string, as the draft specifies
        "  order-2026-10-23:42  ",
        "a.b_c:d-e"
      })
  void acceptsBareAndQuotedKeys(String header) {
    IdempotencyKey key = IdempotencyKey.parse(header);

    assertThat(key).isNotNull();
    assertThat(key.value()).doesNotContain("\"").doesNotStartWith(" ");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "\"\"",
        "short",
        "contains space",
        "two,keys-1234",
        "new\nline-1234",
        "\"unterminated-1234",
        "ünïcode-12345",
        "../../etc/passwd"
      })
  void rejectsMalformedKeys(String header) {
    assertThatThrownBy(() -> IdempotencyKey.parse(header))
        .isInstanceOf(InvalidIdempotencyKeyException.class);
  }

  @org.junit.jupiter.api.Test
  void enforcesTheLengthLimit() {
    assertThat(IdempotencyKey.parse("k".repeat(128))).isNotNull();
    assertThatThrownBy(() -> IdempotencyKey.parse("k".repeat(129)))
        .isInstanceOf(InvalidIdempotencyKeyException.class);
    assertThat(IdempotencyKey.parse(null)).isNull();
  }
}
