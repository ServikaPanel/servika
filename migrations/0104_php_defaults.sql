-- Raise the per-domain PHP limits a new domain receives, and raise the nginx
-- ceilings that sit above them.
--
-- WHY A NEW FILE: editing the DEFAULT clauses in 0011 and 0016 would reach no
-- existing server, because those migrations already ran and MariaDB only
-- changes a column default through ALTER. It would also change their stored
-- checksum, and the runner calls log.Fatalf on a mismatch, so the panel would
-- stop starting altogether.
--
-- SCOPE: php_settings keeps every value a domain already has. An operator may
-- have set those deliberately, and only the DEFAULT for a domain with no row
-- of its own moves.
--
--   memory_limit         256M -> 2048M
--   max_execution_time     30 -> 3000
--   max_input_time         60 -> 6000
--   post_max_size         64M -> 8000M
--   upload_max_filesize   32M -> 2000M
--
-- These five values are mirrored in Go by internal/phpdefaults, and
-- TestTheMigrationsAgreeWithTheseConstants reads this file to hold the two
-- together.

ALTER TABLE php_settings
  MODIFY COLUMN memory_limit        VARCHAR(16) NOT NULL DEFAULT '2048M',
  MODIFY COLUMN max_execution_time  INT         NOT NULL DEFAULT 3000,
  MODIFY COLUMN max_input_time      INT         NOT NULL DEFAULT 6000,
  MODIFY COLUMN post_max_size       VARCHAR(16) NOT NULL DEFAULT '8000M',
  MODIFY COLUMN upload_max_filesize VARCHAR(16) NOT NULL DEFAULT '2000M';

-- The nginx ceiling above post_max_size. Measured with nginx 1.26.3: with
-- post_max_size at 8000M and upload_max_filesize at 2000M in the pool, a 65 MB
-- POST answered 413 while client_max_body_size was 64m, so raising the PHP
-- limits alone changes nothing a visitor can see.
--
-- 8192 MB lets nginx buffer a request body that large to disk before PHP ever
-- runs. Lower it per plan on the plans screen when that matters.
ALTER TABLE service_plans
  MODIFY COLUMN client_max_body_mb INT NOT NULL DEFAULT 8192;

-- Only rows still sitting on the old default move. A plan an operator
-- deliberately capped lower is a product decision and is left alone; a value of
-- exactly 64 cannot be told apart from the default, so it moves with the rest.
UPDATE service_plans
   SET client_max_body_mb = 8192
 WHERE client_max_body_mb = 64;

-- A plan's value is COPIED into the domain's nginx_settings.extra_directives
-- when the domain is attached to the plan (domains.applyPlanNginxDefaults) and
-- frozen there, so the ALTER above reaches only domains created afterwards.
-- Only the exact string that seeder writes is replaced, so a directive block an
-- operator edited by hand keeps whatever they put in it.
UPDATE nginx_settings
   SET extra_directives = REPLACE(extra_directives,
         'client_max_body_size 64m;', 'client_max_body_size 8192m;')
 WHERE extra_directives LIKE '%client_max_body_size 64m;%';
