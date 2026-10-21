CREATE TABLE control_admissions(permit_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, task_id TEXT NOT NULL REFERENCES tasks(task_id), target_invocation_id TEXT NOT NULL REFERENCES invocations(invocation_id), generation INTEGER NOT NULL CHECK(generation>=0), tool_id TEXT NOT NULL CHECK(tool_id IN ('process.inspect','process.cancel')), resource_id TEXT NOT NULL, consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms>=0), payload BLOB NOT NULL);
CREATE TRIGGER control_admissions_no_update BEFORE UPDATE ON control_admissions BEGIN SELECT RAISE(ABORT,'control admissions are immutable'); END;
CREATE TRIGGER control_admissions_no_delete BEFORE DELETE ON control_admissions BEGIN SELECT RAISE(ABORT,'control admissions are immutable'); END;
PRAGMA user_version=3;
