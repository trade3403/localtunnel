ALTER TABLE preview_attempts ADD COLUMN transport TEXT NOT NULL DEFAULT 'http'
    CHECK (transport IN ('http','https'));
