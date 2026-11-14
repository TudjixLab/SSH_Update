CREATE TABLE instances (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 instance_id TEXT NOT NULL UNIQUE,
 app_id TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 active_release_id TEXT REFERENCES releases(release_id),
 max_seen_sequence INTEGER NOT NULL DEFAULT 0,
 committed_sequence INTEGER NOT NULL DEFAULT 0,
 needs_operator INTEGER NOT NULL DEFAULT 0 CHECK(needs_operator IN (0,1))
);
CREATE TABLE releases (
 release_id TEXT PRIMARY KEY,
 display_version TEXT NOT NULL,
 sequence INTEGER NOT NULL UNIQUE CHECK(sequence>0),
 package_sha256 TEXT NOT NULL,
 signer_id TEXT NOT NULL,
 result_digest TEXT NOT NULL,
 manifest_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('VERIFIED','FAILED','ACTIVE','RETIRED')),
 created_ms INTEGER NOT NULL
);
CREATE TABLE jobs (
 job_id TEXT PRIMARY KEY,
 release_id TEXT NOT NULL REFERENCES releases(release_id),
 previous_release_id TEXT REFERENCES releases(release_id),
 phase TEXT NOT NULL,
 terminal INTEGER NOT NULL CHECK(terminal IN (0,1)),
 error_code TEXT,
 created_ms INTEGER NOT NULL,
 updated_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX one_running_job ON jobs((1)) WHERE terminal=0;
CREATE TABLE requests (
 request_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL,
 job_id TEXT NOT NULL REFERENCES jobs(job_id)
);
CREATE TABLE events (
 event_id INTEGER PRIMARY KEY AUTOINCREMENT,
 job_id TEXT REFERENCES jobs(job_id),
 code TEXT NOT NULL,
 error_code TEXT,
 created_ms INTEGER NOT NULL
);
PRAGMA user_version=1;
