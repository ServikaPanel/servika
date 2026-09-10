-- Move the plan's request-body ceiling out of the customer-writable directive
-- block and into a column of its own.
--
-- WHY: the plan's value was seeded as literal nginx TEXT into
-- nginx_settings.extra_directives, which is the same column PUT
-- /domains/{id}/nginx-settings replaces wholesale with whatever the customer
-- sends. A customer could delete the plan's line and write their own with any
-- value, so the tier's upload limit held for exactly as long as nobody sent one
-- request. Beyond the entitlement, nginx spools an oversized request body to
-- client_body_temp_path, which is root-owned, outside the tenant's XFS quota and
-- outside every tenant sweep.
--
-- The value is carried as the RAW nginx size string, not as megabytes. A row an
-- operator edited by hand may name any unit ('500k', '2g'); converting to MB
-- would silently drop those to zero and put nginx's own 1m default in force.

ALTER TABLE nginx_settings
  ADD COLUMN client_max_body VARCHAR(16) NOT NULL DEFAULT '';

-- Copy the first stated value into the column. The pattern matches the string
-- the seeder writes ('client_max_body_size 8192m;') and every hand-written form
-- of it, including one with no unit suffix.
UPDATE nginx_settings
   SET client_max_body = REGEXP_SUBSTR(extra_directives,
         '(?<=client_max_body_size )[0-9]+[kKmMgG]?(?=[[:space:]]*;)')
 WHERE extra_directives REGEXP 'client_max_body_size[[:space:]]+[0-9]+[kKmMgG]?[[:space:]]*;';

-- Remove every statement of the directive from the text.
--
-- This second pass is not cosmetic. The directive joins the forbidden list in
-- the same change, so a row still carrying it would be refused the moment the
-- customer pressed save, and the nginx settings screen would break on every
-- domain that already exists.
UPDATE nginx_settings
   SET extra_directives = TRIM(BOTH '\n' FROM TRIM(REGEXP_REPLACE(extra_directives,
         'client_max_body_size[[:space:]]+[^;]*;[[:space:]]*', '')))
 WHERE extra_directives REGEXP 'client_max_body_size';
