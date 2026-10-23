-- DPoP proof replay cache (docs/adr/0006-client-credentials-and-dpop.md). Shared by
-- every replica, so a proof replayed to another instance is still caught. Rows
-- outlive a proof's acceptance window and are then purged.
CREATE TABLE dpop_proof_jti (
    proof_hash  CHAR(64)     PRIMARY KEY, -- SHA-256 of the key Spring derives from jti + jwk
    expires_at  TIMESTAMPTZ  NOT NULL
);

CREATE INDEX dpop_proof_jti_expires_idx ON dpop_proof_jti (expires_at);
