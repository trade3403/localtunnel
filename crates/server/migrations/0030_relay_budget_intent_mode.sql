-- Existing intents remain non-executable observations. New tenant opt-in is
-- immutable and cannot be promoted from an already recorded observation.
ALTER TABLE relay_budget_intents ADD COLUMN intent_mode TEXT NOT NULL DEFAULT 'observe'
 CHECK(intent_mode IN ('observe','guarded_tcp'));
CREATE TRIGGER relay_budget_intent_mode_immutable BEFORE UPDATE OF intent_mode ON relay_budget_intents
WHEN NEW.intent_mode<>OLD.intent_mode
BEGIN SELECT RAISE(ABORT,'budget intent mode immutable'); END;
