-- Cleanup ledger for durable abandoned-upload reconciliation.
--
-- Every reclaim attempt records one row before the first removal and updates it
-- after the filesystem change completes. A restart reads this ledger instead of
-- guessing, so an agent stop mid-cleanup neither repeats a removal nor loses
-- the fact that one happened. The rows are lightweight bookkeeping only; they
-- never gate verification or release registration.
--
-- completed_ms is NULL while removal is in flight, so a re-run can tell which
-- uploads still need their copies cleared.
CREATE TABLE cleanup (
 cleanup_id TEXT PRIMARY KEY,
 upload_id TEXT NOT NULL,
 reclaimed_ingress INTEGER NOT NULL CHECK(reclaimed_ingress IN (0,1)),
 reclaimed_artifact INTEGER NOT NULL CHECK(reclaimed_artifact IN (0,1)),
 attempt_ms INTEGER NOT NULL,
 completed_ms INTEGER
);

CREATE TABLE cleanup_orphans (
 orphan_id TEXT PRIMARY KEY,
 location TEXT NOT NULL,
 name TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('REMOVED','RETAINED','UNKNOWN')),
 checked_ms INTEGER NOT NULL
);
PRAGMA user_version=3;
