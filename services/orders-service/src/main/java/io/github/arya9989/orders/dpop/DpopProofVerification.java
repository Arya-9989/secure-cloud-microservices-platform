package io.github.arya9989.orders.dpop;

import io.github.arya9989.orders.config.PlatformSecurityProperties;
import java.time.Clock;
import java.util.List;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.DPoPProofReplayValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtIssuedAtValidator;
import org.springframework.stereotype.Component;

/**
 * How DPoP proofs are verified: Spring Security's checks ({@code typ}, asymmetric {@code alg},
 * signature by the proof's own {@code jwk}, its thumbprint against the token's {@code cnf.jkt},
 * {@code htm}, {@code htu}, {@code ath}), with three of the defaults replaced:
 *
 * <ul>
 *   <li>{@code iat} must be within {@code proof-max-age} of now, either way;
 *   <li>the {@code jti} replay cache is PostgreSQL ({@link JdbcDpopReplayCache}), shared by all
 *       replicas, instead of one in-memory map per instance;
 *   <li>a current server nonce ({@link DpopNonces}) is required, so proofs cannot be prepared in
 *       advance. A missing or stale one fails with {@link #USE_DPOP_NONCE}.
 * </ul>
 */
@Component
public class DpopProofVerification {

  /** RFC 9449 section 9: the client must retry with the nonce in the {@code DPoP-Nonce} header. */
  public static final String USE_DPOP_NONCE = "use_dpop_nonce";

  private final DPoPProofJwtDecoderFactory factory = new DPoPProofJwtDecoderFactory();

  public DpopProofVerification(
      PlatformSecurityProperties properties,
      JdbcDpopReplayCache replayCache,
      DpopNonces nonces,
      Clock clock) {
    PlatformSecurityProperties.Dpop dpop = properties.dpop();
    JwtIssuedAtValidator issuedAt = new JwtIssuedAtValidator(true);
    issuedAt.setClockSkew(dpop.proofMaxAge());
    issuedAt.setClock(clock);
    DPoPProofReplayValidator replay = new DPoPProofReplayValidator(replayCache);
    replay.setClockSkew(dpop.proofMaxAge());
    replay.setClock(clock);
    OAuth2TokenValidator<Jwt> nonce = new NonceValidator(nonces, dpop.requireNonce());
    factory.setJwtValidatorFactory(
        DPoPProofJwtDecoderFactory.createDefaultJwtValidatorFactory(
            List.of(issuedAt, replay, nonce)));
  }

  public JwtDecoderFactory<DPoPProofContext> decoderFactory() {
    return factory;
  }

  record NonceValidator(DpopNonces nonces, boolean required) implements OAuth2TokenValidator<Jwt> {

    @Override
    public OAuth2TokenValidatorResult validate(Jwt proof) {
      if (!required || nonces.isValid(proof.getClaimAsString("nonce"))) {
        return OAuth2TokenValidatorResult.success();
      }
      return OAuth2TokenValidatorResult.failure(
          new OAuth2Error(USE_DPOP_NONCE, "A current DPoP nonce is required.", null));
    }
  }
}
