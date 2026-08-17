-- 0097 - one-click application installation.
--
-- Until now only WordPress could be installed, through wp-cli. Everything else
-- meant a customer downloading an archive somewhere and uploading it.
--
-- The catalog is a TABLE rather than a list in Go, and the reason is the pin.
-- A sha256 is what stops a moving upstream archive putting arbitrary PHP into a
-- customer's document root with the panel's blessing, so it cannot be dropped;
-- but a pin compiled into the binary freezes the offered version until the next
-- panel release, and a control panel that installs a CMS eight months out of
-- date is worse than one that installs nothing. A table keeps the pin and lets
-- an administrator enter a new version the day it ships.
--
-- The pin is NOT optional. An entry with an empty sha256 is refused at install
-- time rather than installed unverified: the whole point is that the panel does
-- not hand a customer bytes it cannot vouch for.
--
-- strip_components is per entry because the vendors disagree and there is no
-- rule to derive it from. Measured against the real archives: Joomla's full
-- package and PrestaShop's outer zip extract FLAT, while Drupal, MediaWiki,
-- Grav, Matomo and Nextcloud each wrap everything in one directory named after
-- the release.
CREATE TABLE app_catalog (
  code VARCHAR(32) NOT NULL PRIMARY KEY,
  name VARCHAR(64) NOT NULL,
  version VARCHAR(32) NOT NULL,
  download_url VARCHAR(512) NOT NULL,
  sha256 CHAR(64) NOT NULL DEFAULT '',
  archive_name VARCHAR(128) NOT NULL,
  strip_components TINYINT UNSIGNED NOT NULL DEFAULT 0,
  needs_database TINYINT(1) NOT NULL DEFAULT 1,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seeded from the releases current when this migration was written. Every
-- sha256 below was computed from the archive the URL actually served, not
-- copied from a vendor page. archive_name carries the extension, because
-- archivex decides the format from it and a name without one is refused.
INSERT INTO app_catalog
  (code, name, version, download_url, sha256, archive_name, strip_components, needs_database)
VALUES
  ('joomla', 'Joomla', '6.1.2',
   'https://github.com/joomla/joomla-cms/releases/download/6.1.2/Joomla_6.1.2-Stable-Full_Package.tar.gz',
   'ba184026652260816dd826ac08fc95fd710888877824e2396a85e64d6e983325',
   'joomla.tar.gz', 0, 1),
  ('drupal', 'Drupal', '11.4.5',
   'https://ftp.drupal.org/files/projects/drupal-11.4.5.tar.gz',
   'c9444b40993332f4dd0e57968a20c6013ffcac384f3a3ea9f62e6a0bfddf24e6',
   'drupal.tar.gz', 1, 1),
  ('mediawiki', 'MediaWiki', '1.45.4',
   'https://releases.wikimedia.org/mediawiki/1.45/mediawiki-1.45.4.tar.gz',
   'de1a56b4545ba03390df22ae30d962df22db702f8b9dd9813b0d0e503d3d2c9e',
   'mediawiki.tar.gz', 1, 1),
  ('grav', 'Grav', '2.0.19',
   'https://github.com/getgrav/grav/releases/download/2.0.19/grav-admin-v2.0.19.zip',
   '6cd2dd181ef2d652768e426bef3c745de1a538283a4631f3154b6109eeb340f9',
   'grav.zip', 1, 0),
  ('matomo', 'Matomo', '5.13.0',
   'https://builds.matomo.org/matomo-5.13.0.zip',
   '52dc5f3c131ff9a1e194488acaefd08129f99b700e8d83dab20e5728ebae4c90',
   'matomo.zip', 1, 1),
  ('nextcloud', 'Nextcloud', '34.0.3',
   'https://download.nextcloud.com/server/releases/nextcloud-34.0.3.zip',
   '0fb96682ceb62f0c572cd4a3b30e5d45c39de39b402be5597921cf527c91b4c1',
   'nextcloud.zip', 1, 1),
  ('prestashop', 'PrestaShop', '8.2.7',
   'https://github.com/PrestaShop/PrestaShop/releases/download/8.2.7/prestashop_8.2.7.zip',
   '0ef5e69fb3d0e37c0993d7ad4f67140c26156f550b1ca91c5b8131b76e17f3ab',
   'prestashop.zip', 0, 1);

-- What was installed where, so the screen can say so and a removal knows what
-- it is removing.
--
-- There is no ON DELETE for app_catalog: an entry can be retired or its version
-- moved on, and a record of what was actually installed must survive that.
-- code and version are therefore COPIES taken at install time, not references.
--
-- The row is written BEFORE the work starts, as 'installing'. Downloading a
-- 200 MB archive and unpacking thirty thousand files takes longer than the
-- panel's 300-second request timeout, so the installation runs detached and
-- this row is how the screen learns what happened. It also makes the unique key
-- do a second job: two installations into one target cannot both start, because
-- the second INSERT is refused by the key rather than by a check that races.
--
-- A failure keeps its row, as 'failed' with the reason. Deleting it would leave
-- a half-unpacked document root with nothing in the panel saying why.
CREATE TABLE app_installs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id BIGINT UNSIGNED NOT NULL,
  code VARCHAR(32) NOT NULL,
  name VARCHAR(64) NOT NULL,
  version VARCHAR(32) NOT NULL,
  subdirectory VARCHAR(128) NOT NULL DEFAULT '',
  site_url VARCHAR(512) NOT NULL DEFAULT '',
  db_name VARCHAR(64) NOT NULL DEFAULT '',
  db_user VARCHAR(64) NOT NULL DEFAULT '',
  state ENUM('installing','installed','failed') NOT NULL DEFAULT 'installing',
  last_error VARCHAR(512) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL DEFAULT NULL,
  UNIQUE KEY uq_app_installs_target (domain_id, subdirectory),
  KEY ix_app_installs_domain (domain_id),
  CONSTRAINT fk_app_installs_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
