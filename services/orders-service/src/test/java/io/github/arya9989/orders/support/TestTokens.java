package io.github.arya9989.orders.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.UnaryOperator;

/** Mints access tokens shaped exactly like the auth service's, with knobs to break them. */
public final class TestTokens {

  public static final String ISSUER = "urn:secure-platform:auth-service";
  public static final String AUDIENCE = "secure-platform-api";
  public static final String USER_SCOPES = "orders:read orders:write";
  public static final String ADMIN_SCOPES = "orders:read orders:write orders:admin users:admin";

  private TestTokens() {}

  public static RSAKey newRsaKey() {
    try {
      return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  public static JWTClaimsSet.Builder claims(String subject, String role, String scope) {
    Instant now = Instant.now();
    return new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .audience(AUDIENCE)
        .subject(subject)
        .claim("email", subject + "@example.com")
        .claim("roles", List.of(role))
        .claim("scope", scope)
        .issueTime(Date.from(now))
        .notBeforeTime(Date.from(now))
        .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
        .jwtID(UUID.randomUUID().toString());
  }

  public static String user(RSAKey key, String subject) {
    return sign(key, claims(subject, "USER", USER_SCOPES).build());
  }

  public static String admin(RSAKey key, String subject) {
    return sign(key, claims(subject, "ADMIN", ADMIN_SCOPES).build());
  }

  public static String custom(
      RSAKey key, String subject, UnaryOperator<JWTClaimsSet.Builder> customizer) {
    return sign(key, customizer.apply(claims(subject, "USER", USER_SCOPES)).build());
  }

  public static String sign(RSAKey key, JWTClaimsSet claims) {
    return sign(key, key.getKeyID(), claims);
  }

  /** Signs with {@code key} but advertises {@code kid}, e.g. to impersonate a trusted key id. */
  public static String sign(RSAKey key, String kid, JWTClaimsSet claims) {
    try {
      JWSSigner signer = new RSASSASigner(key);
      SignedJWT jwt =
          new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(), claims);
      jwt.sign(signer);
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  /** HS256 token keyed with a shared secret: must never be accepted by an RS256-only decoder. */
  public static String hmac(String kid, JWTClaimsSet claims) {
    try {
      SignedJWT jwt =
          new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(kid).build(), claims);
      jwt.sign(new MACSigner("an-hmac-secret-that-is-at-least-256-bits-long!!"));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  public static String unsigned(JWTClaimsSet claims) {
    return new PlainJWT(claims).serialize();
  }
}
