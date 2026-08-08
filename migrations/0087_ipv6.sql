-- The address a domain answers on over IPv6.
--
-- This mirrors `domains.ipv4`: it is a DNS and verification value, not a listen
-- address. The vhost binds the wildcard port and nginx separates sites by the
-- Host header, so an address here decides what goes into the AAAA record and
-- what the verification screen expects to find, nothing else.
--
-- Empty means the domain has no IPv6, and that is the safe state rather than a
-- missing feature: seeding a AAAA that points at an address the server does not
-- answer on makes the site unreachable for every IPv6-preferring client, and
-- stops certificate renewal outright, because Let's Encrypt tries the AAAA
-- FIRST when one exists. So the column stays empty until an address is known,
-- and the seeder writes no AAAA at all while it is.
ALTER TABLE domains
  ADD COLUMN ipv6 VARCHAR(45) NOT NULL DEFAULT '';
