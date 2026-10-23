package io.github.arya9989.orders.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.UnaryOperator;

/** Mints access tokens shaped exactly like the auth service's, with knobs to break them. */
public final class TestTokens {

  public static final String ISSUER = "urn:secure-platform:auth-service";
  public static final String AUDIENCE = "secure-platform-api";
  public static final String USER_SCOPES = "orders:read orders:write";
  public static final String ADMIN_SCOPES = "orders:read orders:write orders:admin users:admin";
  public static final String RESOURCE = "urn:secure-platform:orders-service";

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

  // ------------------------------------------------------------------ services and DPoP

  public static ECKey newEcKey() {
    try {
      return new ECKeyGenerator(Curve.P_256).generate();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Shaped like auth-service's client credentials tokens: no roles, client_id, cnf if bound. */
  public static JWTClaimsSet.Builder serviceClaims(
      String clientId, String scope, String audience, ECKey dpopKey) {
    Instant now = Instant.now();
    JWTClaimsSet.Builder claims =
        new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(audience)
            .subject(clientId)
            .claim("client_id", clientId)
            .claim("scope", scope)
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(now))
            .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
            .jwtID(UUID.randomUUID().toString());
    if (dpopKey != null) {
      claims.claim("cnf", Map.of("jkt", thumbprint(dpopKey)));
    }
    return claims;
  }

  public static String thumbprint(ECKey key) {
    try {
      return key.computeThumbprint().toString();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  /** An RFC 9449 proof for one request, with knobs to break it. */
  public static String dpopProof(
      ECKey key,
      String method,
      String url,
      String accessToken,
      String nonce,
      UnaryOperator<JWTClaimsSet.Builder> customizer) {
    JWTClaimsSet.Builder claims =
        new JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())
            .claim("htm", method)
            .claim("htu", url)
            .issueTime(new Date())
            .claim("ath", ath(accessToken));
    if (nonce != null) {
      claims.claim("nonce", nonce);
    }
    try {
      SignedJWT proof =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.ES256)
                  .type(new JOSEObjectType("dpop+jwt"))
                  .jwk(key.toPublicJWK())
                  .build(),
              customizer.apply(claims).build());
      proof.sign(new ECDSASigner(key));
      return proof.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  /** RFC 9449 {@code ath}: base64url(SHA-256(access token)). */
  public static String ath(String accessToken) {
    try {
      return Base64URL.encode(
              MessageDigest.getInstance("SHA-256")
                  .digest(accessToken.getBytes(StandardCharsets.US_ASCII)))
          .toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Signs with {@code key} but sets the JOSE {@code typ}, e.g. to pass a proof off as a token. */
  public static String signWithType(RSAKey key, String type, JWTClaimsSet claims) {
    try {
      SignedJWT jwt =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256)
                  .keyID(key.getKeyID())
                  .type(new JOSEObjectType(type))
                  .build(),
              claims);
      jwt.sign(new RSASSASigner(key));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }
}
