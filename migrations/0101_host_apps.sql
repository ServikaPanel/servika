-- 0101 - server-level applications.
--
-- internal/apps runs a TENANT's application: it belongs to a customer, lives in
-- their home, runs in their slice and is published through their vhost. These
-- belong to the SERVER. Gitea, Grafana, a MinIO bucket store: an operator runs
-- them for themselves, not on behalf of a domain, and there is no tenant to
-- charge the memory to or to name the account after.
--
-- Three things follow from that, and each is why this is a separate set of
-- tables rather than a flag on the existing ones.
--
--   * Its own port range and its own firewall decision. Tenant application
--     ports (30000-30999) are DROPPED unconditionally, because nothing forces a
--     Node process to bind loopback and a customer's application must never be
--     reachable past nginx. A host application usually WANTS to be reachable,
--     so each port carries firewall_open explicitly and it defaults to CLOSED:
--     the operator opens what they meant to open, rather than discovering later
--     what they published.
--   * Its own system user, one per application, so a compromise of one is not a
--     compromise of the others. The names are prefixed svk_ rather than the
--     tenant c_, which keeps them out of every place that enumerates tenants.
--   * Admin only. There is no ownership chain to scope these by, because they
--     are not owned by a customer at all.
--
-- The catalog is a TABLE for the same reason internal/appinstall's is: a
-- checksum compiled into the binary freezes the offered version until the next
-- panel release, and these projects publish every few weeks.
CREATE TABLE host_app_catalog (
  code VARCHAR(32) NOT NULL PRIMARY KEY,
  name VARCHAR(64) NOT NULL,
  version VARCHAR(64) NOT NULL,
  -- One URL and one digest PER ARCHITECTURE. Servika ships linux_amd64 and
  -- linux_arm64, and several of these projects publish a build for only one of
  -- them: TeamSpeak has no arm64 Linux server at all (measured: HTTP 404). An
  -- empty URL means "not available for that architecture" and the screen says
  -- so rather than offering a button that fails at download time.
  url_amd64 VARCHAR(512) NOT NULL DEFAULT '',
  sha256_amd64 CHAR(64) NOT NULL DEFAULT '',
  url_arm64 VARCHAR(512) NOT NULL DEFAULT '',
  sha256_arm64 CHAR(64) NOT NULL DEFAULT '',
  -- How the download is unpacked. 'binary' means the download IS the program.
  archive_kind ENUM('binary','tar.gz','tar.xz','tar.bz2','zip') NOT NULL DEFAULT 'tar.gz',
  -- Several archives name their top directory after the ARCHITECTURE
  -- (syncthing-linux-amd64-v2.1.3, prometheus-3.13.2.linux-amd64), so the
  -- wrapper is stripped by LEVEL and never matched by name.
  strip_components TINYINT UNSIGNED NOT NULL DEFAULT 1,
  -- Where the program is inside the unpacked tree, after the strip.
  binary_path VARCHAR(255) NOT NULL DEFAULT '',
  -- Arguments appended to the binary, with {data} and {port} substituted.
  --
  -- Where an argument names a listen address it is written UNBOUND (":{port}"),
  -- not 127.0.0.1. That is the opposite of internal/apps and it is deliberate:
  -- there the tenant application is published through nginx and must never be
  -- reachable directly, so loopback is a second layer under the range drop. Here
  -- firewall_open below is the whole feature, and an application pinned to
  -- loopback would leave an operator looking at a screen that says the port is
  -- open while nothing outside the server can reach it. The firewall is the
  -- boundary, exactly as it is for the tenant range.
  start_args VARCHAR(512) NOT NULL DEFAULT '',
  -- How the application is told which port to listen on. The panel assigns the
  -- port from its OWN range, so the product's own default is never what it ends
  -- up on, and an application that did not get the message listens somewhere
  -- else and reads as down with nothing in its log to explain it.
  --
  -- Three shapes exist among the products seeded below and all three are
  -- needed: a command-line flag (written as {port} in start_args), an
  -- environment variable under a product-specific name, or neither, where the
  -- product reads its own configuration file and the operator is told the
  -- assigned port so they can put it there.
  port_env_name VARCHAR(64) NOT NULL DEFAULT 'PORT',
  -- takes_port says whether the panel can make the application listen on the
  -- assigned port at all. When it is 0 the port is still reserved and still
  -- firewalled, but the operator has to set it in the product's own config.
  takes_port TINYINT(1) NOT NULL DEFAULT 1,
  default_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  needs_data_dir TINYINT(1) NOT NULL DEFAULT 1,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Every entry below was measured against what the URL actually served: the
-- digest was read from the project's own published checksum file where one
-- exists and computed from the download where it does not, and the archive
-- layout was read out of the archive rather than assumed.
--
-- Caddy is the reason each digest was checked rather than copied: its release
-- carries a file called checksums.txt whose entries are 128 hex characters,
-- which is SHA-512. Storing one as a sha256 would refuse every Caddy install
-- for good, and nothing would say why. The value below is the real SHA-256.
--
-- MinIO is pinned to a concrete GitHub release rather than to
-- dl.min.io/server/minio/release/..., which is a MUTABLE path: a fixed digest
-- against a moving file is a pin that breaks the moment the project publishes.
INSERT INTO host_app_catalog
  (code, name, version, url_amd64, sha256_amd64, url_arm64, sha256_arm64,
   archive_kind, strip_components, binary_path, start_args, default_port, needs_data_dir)
VALUES
  ('gitea','Gitea','1.27.2',
   'https://github.com/go-gitea/gitea/releases/download/v1.27.2/gitea-1.27.2-linux-amd64',
   'aa4e624ca6aa58a824a75562caecc2d206fcab8c70bc8fab765b456f182844fd',
   'https://github.com/go-gitea/gitea/releases/download/v1.27.2/gitea-1.27.2-linux-arm64',
   'a585d7ce94bacb81241ec39b0e3dc99b173c9d7dd41cd3e5c28445a30271c3ab',
   'binary',0,'gitea','web',3000,1),

  ('caddy','Caddy','2.11.4',
   'https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz',
   '527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9',
   'https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_arm64.tar.gz',
   '52d42ae12b3462097e9868da6dfed3c9648ae12edd3b3638102312af84cb6904',
   'tar.gz',0,'caddy','run',2019,1),

  ('syncthing','Syncthing','2.1.3',
   'https://github.com/syncthing/syncthing/releases/download/v2.1.3/syncthing-linux-amd64-v2.1.3.tar.gz',
   'f929eb8e5b72a85543eeeefb2c38f34a68e0c530e70758a2905b78840c76602c',
   'https://github.com/syncthing/syncthing/releases/download/v2.1.3/syncthing-linux-arm64-v2.1.3.tar.gz',
   'a5c046965b590a8de2f8c8c16a0dbf9201d99600b0cafd604040232b603e4586',
   'tar.gz',1,'syncthing','serve --no-browser --home={data} --gui-address=0.0.0.0:{port}',8384,1),

  ('grafana','Grafana','13.1.3',
   'https://dl.grafana.com/oss/release/grafana-13.1.3.linux-amd64.tar.gz',
   'e0fd22aa63901ebc961ee64195da60eef8624a831683ca10b26c7b068082e92b',
   'https://dl.grafana.com/oss/release/grafana-13.1.3.linux-arm64.tar.gz',
   '83eef49ccc6529da5ef3ffd2bc76dadfa66cca9a9684278bf858346cf2271b5d',
   'tar.gz',1,'bin/grafana','server',3001,1),

  ('prometheus','Prometheus','3.13.2',
   'https://github.com/prometheus/prometheus/releases/download/v3.13.2/prometheus-3.13.2.linux-amd64.tar.gz',
   '0e8c4d46101bd025ea8265e377d2caabc57f488fc1be1c367f37db69ea41be6f',
   'https://github.com/prometheus/prometheus/releases/download/v3.13.2/prometheus-3.13.2.linux-arm64.tar.gz',
   '7cecb17a6f41d59814e1a0581a1f81f79051ad5973d1ecf39e23a9f747d6572a',
   'tar.gz',1,'prometheus','--storage.tsdb.path={data} --web.listen-address=:{port}',9090,1),

  ('minio','MinIO','RELEASE.2025-09-07T16-13-09Z',
   'https://github.com/minio/minio/releases/download/RELEASE.2025-09-07T16-13-09Z/minio.linux-amd64.RELEASE.2025-09-07T16-13-09Z',
   '7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f',
   'https://github.com/minio/minio/releases/download/RELEASE.2025-09-07T16-13-09Z/minio.linux-arm64.RELEASE.2025-09-07T16-13-09Z',
   '5c83cd2cf151717ba0243f73e1c7802ff36e272b67144bdd7f1f7d684fd6f03d',
   'binary',0,'minio','server {data} --address :{port}',9000,1),

  ('sftpgo','SFTPGo','2.7.5',
   'https://github.com/drakkan/sftpgo/releases/download/v2.7.5/sftpgo_v2.7.5_linux_x86_64.tar.xz',
   '6bfecb99d17e0dc53c3b019100e3577d0e591876b3c593847ee4ab3b25952ffa',
   'https://github.com/drakkan/sftpgo/releases/download/v2.7.5/sftpgo_v2.7.5_linux_arm64.tar.xz',
   '3d5d4bf3297bff001c052ed0ca7d2d7a6e5a7409e9e134d7ffe7ba8ac83d9a9e',
   'tar.xz',0,'sftpgo','serve',8080,1),

  ('headscale','Headscale','0.29.3',
   'https://github.com/juanfont/headscale/releases/download/v0.29.3/headscale_0.29.3_linux_amd64',
   '8dc183758024ed7095cf610fedea0790233613c71353bc8be2715d82ba29b92c',
   'https://github.com/juanfont/headscale/releases/download/v0.29.3/headscale_0.29.3_linux_arm64',
   'ecf0099f9aa1efb56e7c74718342a493f7d44a840626a2877ca526e675040f4e',
   'binary',0,'headscale','serve',8085,1),

  ('statping','Statping-ng','0.93.0',
   'https://github.com/statping-ng/statping-ng/releases/download/v0.93.0/statping-linux-amd64.tar.gz',
   '263ca172c19a61e7272618c5b4acdaab855580a5289963205c5160024628b82d',
   'https://github.com/statping-ng/statping-ng/releases/download/v0.93.0/statping-linux-arm64.tar.gz',
   'ac116f81d78affb7b21f5b18789e70e79a4247f555314119a31fa90766431bc4',
   'tar.gz',0,'statping','',8080,1),

  -- TeamSpeak ships no arm64 Linux server (measured: the arm64 URL answers 404),
  -- so its arm64 columns are empty and the screen refuses it on such a host
  -- rather than failing at download time. Its licence also has to be accepted by
  -- the operator, which is why it is seeded DISABLED: the panel does not agree
  -- to somebody else's terms on their behalf.
  ('teamspeak','TeamSpeak 3 Server','3.13.7',
   'https://files.teamspeak-services.com/releases/server/3.13.7/teamspeak3-server_linux_amd64-3.13.7.tar.bz2',
   '775a5731a9809801e4c8f9066cd9bc562a1b368553139c1249f2a0740d50041e',
   '','',
   'tar.bz2',1,'ts3server','',9987,1);

-- Grafana reads its port from its own environment variable rather than PORT.
UPDATE host_app_catalog SET port_env_name = 'GF_SERVER_HTTP_PORT' WHERE code = 'grafana';

-- These four take the assigned port from neither a flag nor an environment
-- variable: each reads its own configuration file, which the panel does not
-- write because writing somebody else's config format is how a panel breaks an
-- application it does not understand. The port is still reserved and still
-- firewalled; the screen tells the operator which one it is.
UPDATE host_app_catalog SET takes_port = 0
 WHERE code IN ('gitea','caddy','sftpgo','headscale','teamspeak');

UPDATE host_app_catalog SET enabled = 0 WHERE code = 'teamspeak';

-- One installed application.
--
-- system_user is UNIQUE because it names the Linux account, the systemd unit,
-- the install directory and the data directory: two rows sharing it would make
-- removing one take the other's files with it. That is the same rule the tenant
-- side learned the hard way and enforces in migrations/0091.
CREATE TABLE host_apps (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(32) NOT NULL,
  name VARCHAR(64) NOT NULL,
  version VARCHAR(64) NOT NULL,
  system_user VARCHAR(32) NOT NULL,
  install_dir VARCHAR(255) NOT NULL,
  data_dir VARCHAR(255) NOT NULL DEFAULT '',
  state ENUM('installing','installed','failed','removing') NOT NULL DEFAULT 'installing',
  last_error VARCHAR(512) NOT NULL DEFAULT '',
  created_by BIGINT UNSIGNED NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL DEFAULT NULL,
  UNIQUE KEY uq_host_apps_user (system_user),
  KEY ix_host_apps_code (code),
  CONSTRAINT fk_host_apps_user FOREIGN KEY (created_by)
    REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A port an application listens on.
--
-- firewall_open is the whole difference from the tenant side, and its default
-- of 0 is the point: an operator opens what they meant to open, rather than
-- discovering later what they published.
--
-- The enforcement is a RANGE drop plus per-port accepts above it, not a per-port
-- drop. A port nobody has assigned yet is then closed for the same reason an
-- assigned one with firewall_open unset is, and the two cannot drift apart. The
-- accepts sit BELOW the country drop and the ban drops, so an address already
-- refused cannot be let back in by opening an application's port.
CREATE TABLE host_app_ports (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  app_id BIGINT UNSIGNED NOT NULL,
  port SMALLINT UNSIGNED NOT NULL,
  firewall_open TINYINT(1) NOT NULL DEFAULT 0,
  note VARCHAR(128) NOT NULL DEFAULT '',
  UNIQUE KEY uq_host_app_ports_port (port),
  KEY ix_host_app_ports_app (app_id),
  CONSTRAINT fk_host_app_ports_app FOREIGN KEY (app_id)
    REFERENCES host_apps(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- What the panel did to an application, so a failed install says why rather
-- than leaving a row in a state nobody can explain.
CREATE TABLE host_app_jobs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  app_id BIGINT UNSIGNED NULL DEFAULT NULL,
  code VARCHAR(32) NOT NULL DEFAULT '',
  action ENUM('install','remove','start','stop','restart') NOT NULL,
  state ENUM('running','finished','failed') NOT NULL DEFAULT 'running',
  last_error VARCHAR(512) NOT NULL DEFAULT '',
  actor_uid BIGINT UNSIGNED NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL DEFAULT NULL,
  KEY ix_host_app_jobs_app (app_id),
  KEY ix_host_app_jobs_created (created_at),
  CONSTRAINT fk_host_app_jobs_app FOREIGN KEY (app_id)
    REFERENCES host_apps(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A copy of an application's data directory.
--
-- The row is kept when the application is removed (ON DELETE SET NULL rather
-- than CASCADE), because the reason to take a backup is that the application
-- might not survive, and deleting the record of it along with the application
-- would remove the only thing naming the archive on disk.
CREATE TABLE host_app_backups (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  app_id BIGINT UNSIGNED NULL DEFAULT NULL,
  code VARCHAR(32) NOT NULL DEFAULT '',
  archive_path VARCHAR(512) NOT NULL,
  size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_host_app_backups_app (app_id),
  CONSTRAINT fk_host_app_backups_app FOREIGN KEY (app_id)
    REFERENCES host_apps(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
