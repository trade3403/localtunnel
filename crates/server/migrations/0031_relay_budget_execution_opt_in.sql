-- Previously recorded guarded previews remain non-executable.
ALTER TABLE relay_budget_intents ADD COLUMN execution_opt_in INTEGER NOT NULL DEFAULT 0
 CHECK(execution_opt_in IN (0,1) AND (execution_opt_in=0 OR intent_mode='guarded_tcp'));
CREATE TRIGGER relay_budget_execution_opt_in_immutable BEFORE UPDATE OF execution_opt_in ON relay_budget_intents
WHEN NEW.execution_opt_in<>OLD.execution_opt_in
BEGIN SELECT RAISE(ABORT,'budget execution opt-in immutable'); END;
