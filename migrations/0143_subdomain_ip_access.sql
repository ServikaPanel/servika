-- 0143 — per-subdomain IP access restriction.
--
-- The panel restricts access by IP address per domain (0047: domains.ip_access_mode
-- plus domain_ip_rules), and a subdomain has carried none of it. A customer who
-- wants api.example.com open to two office addresses had to add the subdomain as
-- a separate domain, which takes it out of the parent's plan and its resources.
--
-- The schema mirrors the domain side exactly, so the renderer and the API keep
-- one vocabulary: mode `off` restricts nothing, `block` denies the listed
-- addresses, `allow` admits only them. ENUM rather than VARCHAR, so the column
-- itself refuses a value the renderer would not recognise.
--
-- The foreign key is ON DELETE CASCADE, and it is load-bearing rather than
-- decorative: subdomains.id is a plain AUTO_INCREMENT and MariaDB does not carry
-- the counter across a restart, so a reused id would hand the deleted
-- subdomain's rules to a new one. The cascade makes that impossible.

CREATE TABLE subdomain_ip_access (
  subdomain_id   INT NOT NULL PRIMARY KEY,
  ip_access_mode ENUM('off','block','allow') NOT NULL DEFAULT 'off',
  updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_subdomain_ip_access_sub FOREIGN KEY (subdomain_id)
    REFERENCES subdomains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE subdomain_ip_rules (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subdomain_id INT NOT NULL,
  ip_cidr      VARCHAR(43) NOT NULL,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_subdomain_ip_rules (subdomain_id, ip_cidr),
  CONSTRAINT fk_subdomain_ip_rules_sub FOREIGN KEY (subdomain_id)
    REFERENCES subdomains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
