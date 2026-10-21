CREATE TABLE notes(id INTEGER PRIMARY KEY,tenant TEXT NOT NULL,text TEXT NOT NULL CHECK(length(text)>0));
CREATE INDEX notes_tenant ON notes(tenant);
CREATE TABLE requests(tenant TEXT NOT NULL,key TEXT NOT NULL,note_id INTEGER NOT NULL REFERENCES notes(id),PRIMARY KEY(tenant,key));
