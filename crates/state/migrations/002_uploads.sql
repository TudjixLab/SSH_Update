CREATE TABLE uploads (
 upload_id TEXT PRIMARY KEY,
 size INTEGER NOT NULL CHECK(size>0),
 package_sha256 TEXT NOT NULL,
 committed_offset INTEGER NOT NULL DEFAULT 0 CHECK(committed_offset>=0 AND committed_offset<=size),
 state TEXT NOT NULL CHECK(state IN ('RECEIVING','SEALING','SEALED','REJECTED')),
 error_code TEXT,
 created_ms INTEGER NOT NULL,
 updated_ms INTEGER NOT NULL
);
ALTER TABLE requests RENAME TO requests_v1;
CREATE TABLE requests (
 request_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL,
 job_id TEXT REFERENCES jobs(job_id),
 upload_id TEXT REFERENCES uploads(upload_id),
 CHECK((job_id IS NULL) != (upload_id IS NULL))
);
INSERT INTO requests(request_id,request_digest,job_id) SELECT request_id,request_digest,job_id FROM requests_v1;
DROP TABLE requests_v1;
PRAGMA user_version=2;
