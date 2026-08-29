-- mail_count records how many mailboxes a live migration moved for one domain,
-- so the migration result table can report mail beside db_count and dns_count.
-- It defaults to 0, so a job that ran before the mail step existed reads as
-- "no mail migrated" rather than as a missing value.
ALTER TABLE migration_items
  ADD COLUMN mail_count INT NOT NULL DEFAULT 0 AFTER dns_count;
