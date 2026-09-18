-- 0142 — keep the generated WordPress administrator password out of the install
-- response.
--
-- WHY: the install endpoint returned the generated password as `admin_password`
-- in its JSON body. A response body reaches more places than the screen that
-- displays it: the panel's own request log captures bodies, a reverse proxy in
-- front of the panel writes them to its access log, and the browser keeps the
-- response in memory for the session. The password is also the one credential
-- the installer never writes anywhere else, so the customer who closes the tab
-- loses it and has to reset it through WordPress.
--
-- The row holds the password sealed by internal/secret (`enc:v1:` prefix), with
-- the domain id and the absolute install directory bound as AAD, so a row copied
-- into another domain's id does not decrypt.
--
-- `target` is the ABSOLUTE install directory, not the subdirectory name. A
-- domain can carry several installs at once (public_html, public_html/shop, and
-- a subdomain's own document root), and each one has its own administrator
-- account, so the unique key is the pair.
--
-- The row is deleted the moment the owner reveals the password. The panel is not
-- a password manager, and a password that stays readable for ever is a second
-- copy of a credential the customer can already rotate in WordPress.

CREATE TABLE wp_install_passwords (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain_id      BIGINT UNSIGNED NOT NULL,
  target         VARCHAR(500) NOT NULL,
  admin_user     VARCHAR(191) NOT NULL,
  admin_password VARCHAR(255) NOT NULL,
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_wp_install_password_target (domain_id, target),
  CONSTRAINT fk_wp_install_password_domain FOREIGN KEY (domain_id)
    REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
