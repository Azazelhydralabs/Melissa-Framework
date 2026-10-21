CREATE TABLE model_requests(request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), profile_id TEXT NOT NULL, provider_id TEXT NOT NULL, model_id TEXT NOT NULL, request_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','succeeded','failed','cancelled','outcome_unknown','never_dispatched')), version INTEGER NOT NULL CHECK(version>=0), created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0), payload BLOB NOT NULL);
CREATE INDEX model_requests_task ON model_requests(task_id,state);
CREATE TRIGGER model_requests_no_delete BEFORE DELETE ON model_requests BEGIN SELECT RAISE(ABORT,'model requests cannot be deleted'); END;
CREATE TABLE model_request_events(request_id TEXT NOT NULL REFERENCES model_requests(request_id), sequence INTEGER NOT NULL CHECK(sequence>=0), kind TEXT NOT NULL CHECK(kind IN ('reserved','dispatched','settled','unknown','reconciled','recovered_unknown')), created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0), payload BLOB NOT NULL, PRIMARY KEY(request_id,sequence));
CREATE TRIGGER model_request_events_no_update BEFORE UPDATE ON model_request_events BEGIN SELECT RAISE(ABORT,'model request events are append only'); END;
CREATE TRIGGER model_request_events_no_delete BEFORE DELETE ON model_request_events BEGIN SELECT RAISE(ABORT,'model request events are append only'); END;
PRAGMA user_version=4;
