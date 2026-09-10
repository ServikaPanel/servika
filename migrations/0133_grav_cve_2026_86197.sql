-- Move the pinned Grav release past CVE-2026-86197.
--
-- The seeded pin 2.0.19 is inside the affected range of GHSA-8hgv-xc77-jmcr
-- (CVE-2026-86197), {introduced: 0, fixed: 2.0.20}: Grav 2.0 renders
-- editor-authored Twig in page content by default and the shipped sandbox policy
-- allowlists addcss/addjs on Grav\Common\Assets, so an account holding only
-- page-edit rights can register arbitrary script into rendered pages and
-- escalate to super-admin of the site.
--
-- The panel places the files and pins the digest, so an installation from the
-- catalog looks vouched for. The digest proves the bytes are the release named;
-- it says nothing about whether that release is vulnerable, which is what this
-- corrects.
--
-- 2.0.26 rather than the 2.0.20 that closes the advisory: it is the current
-- release and re-running the OSV query at it returns only
-- GHSA-xrf8-cmrg-7436 (CVE-2023-31506), whose range is unbounded with no fixed
-- version, so it applies to every release including the newest and cannot be
-- answered by a bump.
--
-- The sha256 is the digest GitHub publishes for the release asset, confirmed by
-- downloading the file and hashing it.
UPDATE app_catalog
   SET version      = '2.0.26',
       download_url = 'https://github.com/getgrav/grav/releases/download/2.0.26/grav-admin-v2.0.26.zip',
       sha256       = '6315b1035962678c16a76a114205d8e1ce61cd65131ca0a1876c24393b130e68'
 WHERE code = 'grav'
   AND version = '2.0.19';
