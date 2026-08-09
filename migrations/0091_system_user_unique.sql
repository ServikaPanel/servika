-- 0091 - one top-level domain per system user, enforced by the database.
--
-- provisioner.allocateSystemUser picks a free name, but a check followed by an
-- INSERT is not atomic: two creates running together can both read the same name
-- as free. The index is what actually forbids the second row, and everything on
-- the host is keyed on this name (home directory, Linux and FTP account, vhost
-- dom_<system user>.conf, PHP-FPM pool, systemd slice, Valkey ACL account, WAF
-- configs, cron spool, backup directory, c_<system user>_ database namespace).
--
-- A plain UNIQUE on system_user cannot be used: an addon domain and a subdomain
-- are rows in this table carrying their PARENT's system_user, so it would refuse
-- every addon domain on every install. The generated column is NULL for those
-- rows, and a UNIQUE index treats every NULL as distinct, so any number of them
-- coexist while a second TOP-LEVEL row with the same name is refused (measured
-- on 10.11: ERROR 1062 on the insert, addon rows accepted).
--
-- NOT NULL is deliberately absent: MariaDB refuses it on a generated column in
-- every position, and the NULLs are the whole mechanism here.
--
-- If this migration fails, the database already holds two top-level domains
-- sharing a system user. The error does NOT say so: measured on 10.11 the ALTER
-- copies the table, tries to drop the duplicate row on the way, and reports
-- "ERROR 1834 Cannot delete rows from table which is parent in a foreign key
-- constraint 'fk_alias_domain' of table 'mail_aliases'", which names neither the
-- column nor the duplicate. Such a pair shares one home directory, so no
-- statement can separate them; find them with
--   SELECT system_user, GROUP_CONCAT(domain_name) FROM domains
--    WHERE parent_domain_id IS NULL AND system_user<>''
--    GROUP BY system_user HAVING COUNT(*)>1;
-- and delete or recreate one of each pair before applying this file.
ALTER TABLE domains
  ADD COLUMN system_user_top VARCHAR(64) GENERATED ALWAYS AS
    (IF(parent_domain_id IS NULL, system_user, NULL)) PERSISTENT,
  ADD UNIQUE KEY uq_domains_system_user_top (system_user_top);
