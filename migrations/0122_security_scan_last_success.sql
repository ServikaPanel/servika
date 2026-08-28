-- last_success records when a full sweep last FINISHED without error, distinct
-- from finished_at which begin() clears at the start of every run. It is the one
-- signal that separates "a domain has no supported app" (a completed sweep found
-- none) from "a domain has never been scanned" (no sweep has ever finished), so
-- the domain-driven monitor can draw those opposite states differently.
ALTER TABLE security_scan_status
  ADD COLUMN last_success DATETIME NULL DEFAULT NULL AFTER finished_at;
