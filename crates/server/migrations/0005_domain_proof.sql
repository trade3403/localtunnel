-- Legacy rows intentionally have no proof and cannot be verified until a
-- new challenge is issued. No old verified_at value is trusted.
ALTER TABLE domains ADD COLUMN verification_token TEXT
    CHECK (verification_token IS NULL OR length(verification_token)=64);
UPDATE domains SET verified_at=NULL;
