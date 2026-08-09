-- 0093_laravel_workers.sql, one row per Laravel queue worker definition.
--
-- The toolkit carried a single worker per domain inside cp_laravel_apps: one
-- connection, one set of timings, one process. A real Laravel application runs
-- its high priority queue on its own worker and scales throughput with the
-- process count, and neither is expressible in one row.
--
-- queues holds a comma separated list and an EMPTY string means "whatever the
-- connection considers default", so the --queue flag is omitted entirely. It is
-- NOT NULL because the code path should have one notion of empty, not two.
--
-- Both columns of uk_laravel_worker_name are NOT NULL. A UNIQUE index treats
-- every NULL as distinct, so a nullable member would let the same name exist
-- any number of times on one domain.
CREATE TABLE cp_laravel_workers (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  domain_id    BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(32)  NOT NULL,
  connection   VARCHAR(32)  NOT NULL DEFAULT 'database',
  queues       VARCHAR(255) NOT NULL DEFAULT '',
  processes    INT          NOT NULL DEFAULT 1,
  tries        INT          NOT NULL DEFAULT 3,
  timeout_sec  INT          NOT NULL DEFAULT 60,
  sleep_sec    INT          NOT NULL DEFAULT 3,
  max_jobs     INT          NOT NULL DEFAULT 1000,
  memory_mb    INT          NOT NULL DEFAULT 128,
  enabled      TINYINT(1)   NOT NULL DEFAULT 0,
  created_at   TIMESTAMP    NULL DEFAULT current_timestamp(),
  updated_at   TIMESTAMP    NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (id),
  UNIQUE KEY uk_laravel_worker_name (domain_id, name),
  CONSTRAINT fk_laravel_worker_domain FOREIGN KEY (domain_id)
    REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Carry the one definition each domain already had across, so a worker running
-- today keeps its settings and its name on the new screen.
INSERT INTO cp_laravel_workers (domain_id, name, connection, timeout_sec, max_jobs, enabled)
SELECT domain_id, 'default', queue_connection, queue_timeout, queue_max_jobs, queue_enabled
FROM cp_laravel_apps
WHERE queue_enabled = 1;

-- The old columns go in the same migration. Leaving two sources of a worker
-- definition behind means the screen can show one while the other is what
-- actually runs.
ALTER TABLE cp_laravel_apps
  DROP COLUMN queue_enabled,
  DROP COLUMN queue_timeout,
  DROP COLUMN queue_max_jobs,
  DROP COLUMN queue_connection;
