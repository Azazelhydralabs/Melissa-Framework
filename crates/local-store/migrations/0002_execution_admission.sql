CREATE TABLE permit_admissions(permit_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, invocation_id TEXT NOT NULL UNIQUE REFERENCES invocations(invocation_id), attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), arguments_digest TEXT NOT NULL, permit_digest TEXT NOT NULL, consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms>=0), payload BLOB NOT NULL);
CREATE TRIGGER permit_admissions_no_update BEFORE UPDATE ON permit_admissions BEGIN SELECT RAISE(ABORT,'permit admissions are immutable'); END;
CREATE TRIGGER permit_admissions_no_delete BEFORE DELETE ON permit_admissions BEGIN SELECT RAISE(ABORT,'permit admissions are immutable'); END;
CREATE TABLE permit_revocations(permit_id TEXT PRIMARY KEY, revoked_at_ms INTEGER NOT NULL CHECK(revoked_at_ms>=0), payload BLOB NOT NULL);
CREATE TRIGGER permit_revocations_no_update BEFORE UPDATE ON permit_revocations BEGIN SELECT RAISE(ABORT,'permit revocations are immutable'); END;
CREATE TRIGGER permit_revocations_no_delete BEFORE DELETE ON permit_revocations BEGIN SELECT RAISE(ABORT,'permit revocations are immutable'); END;
CREATE TABLE execution_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms>=0), payload BLOB NOT NULL);
PRAGMA user_version=2;
