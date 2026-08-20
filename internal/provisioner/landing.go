package provisioner

import (
	"fmt"
	"os"
	"path/filepath"
)

// ── Brand pages: new-domain welcome + server-wide 404 + catch-all park ──────
// Both are FULL-PAGE two-column layouts: Lottie animation on the left, content
// on the right. On mobile they collapse to a single column (animation on top).
//
// The animation + player come from the SHARED directory (see brand.go /
// EnsureBrandAssets): `/_srv/lottie.min.js` + `/_srv/ready.json`. When they
// cannot load (an old vhost without `location ^~ /_srv/`, or JS disabled) the
// page falls back to an inline SVG drawing — never a broken image. NO external
// dependency (CDN/webfont).

const (
	errorPageDir  = "/usr/share/servika/errors"
	errorPageFile = "_srv_404.html"
	// ErrorPageURL is the file name used by the nginx `location = /_srv_404.html`
	// block (joined with root to locate the file on disk).
	ErrorPageURL = "/" + errorPageFile
)

// brandStyle is the shared CSS for both pages (single source → visual
// consistency). The left panel is a light surface in BOTH themes: the
// animations carry dark and light elements, and a light-neutral ground is the
// only choice that renders both correctly.
const brandStyle = `
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#ffffff; --bg2:#f8fafc; --line:#e7e5e4;
    --title:#1c1917; --text:#57534e; --faint:#a8a29e;
    --accent:#ea580c; --accent2:#f59e0b;
    --panel1:#f2f4fd; --panel2:#e6ebf9; --panelText:rgba(28,25,23,.32);
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0c0a09; --bg2:#1c1917; --line:#292524;
      --title:#fafaf9; --text:#a8a29e; --faint:#78716c;
      --accent:#fb923c; --accent2:#fbbf24;
      --panel1:#dfe4f4; --panel2:#ccd4ec; --panelText:rgba(28,25,23,.38);
    }
  }
  html,body{height:100%}
  body{
    font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
    background:var(--bg);color:var(--title);-webkit-font-smoothing:antialiased;
  }
  .page{min-height:100vh;min-height:100dvh;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr)}
  .visual{
    position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;
    padding:24px;background:linear-gradient(150deg,var(--panel1),var(--panel2));
  }
  .anim{position:relative;z-index:1;width:min(88%,560px);aspect-ratio:1/1;display:none}
  .anim-on .anim{display:block}
  .anim-on .draw{display:none}
  .draw{position:relative;z-index:1;width:min(62%,360px);height:auto}
  .ring{transform-origin:150px 150px;animation:spin 26s linear infinite}
  .ring2{transform-origin:150px 150px;animation:spin 34s linear infinite reverse}
  .sat{transform-origin:150px 150px;animation:spin 12s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .mark{
    position:absolute;z-index:1;bottom:26px;left:0;right:0;text-align:center;
    font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--panelText);
  }
  .content{
    display:flex;flex-direction:column;justify-content:center;
    padding:clamp(28px,6vw,84px);max-width:660px;
    animation:rise .7s cubic-bezier(.2,.7,.3,1) both;
  }
  @keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
  .eyebrow{
    display:inline-flex;align-items:center;gap:9px;align-self:flex-start;
    font-size:11px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);
    margin-bottom:20px;
  }
  .live{width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.16);animation:pulse 2.4s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
  h1{
    font-size:clamp(30px,4.4vw,48px);line-height:1.1;letter-spacing:-.025em;
    font-weight:800;text-wrap:balance;word-break:break-word;margin-bottom:14px;
  }
  h1 .domain{
    background:linear-gradient(100deg,var(--accent),var(--accent2));
    -webkit-background-clip:text;background-clip:text;color:transparent;
  }
  .code-big{
    font-size:clamp(64px,11vw,120px);font-weight:800;line-height:.92;letter-spacing:-.05em;
    background:linear-gradient(100deg,var(--accent),var(--accent2));
    -webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:8px;
  }
  .lead{font-size:clamp(16px,1.6vw,19px);color:var(--text);line-height:1.65;max-width:46ch}
  .steps{list-style:none;display:flex;flex-direction:column;gap:14px;margin:32px 0 28px}
  .steps li{display:flex;gap:14px;align-items:flex-start;font-size:15px;color:var(--text);line-height:1.5}
  .num{
    flex:none;width:26px;height:26px;border-radius:9px;display:grid;place-items:center;
    background:var(--bg2);border:1px solid var(--line);
    font-size:12px;font-weight:700;color:var(--accent);font-variant-numeric:tabular-nums;
  }
  .steps b{color:var(--title);font-weight:600}
  code{
    background:var(--bg2);border:1px solid var(--line);padding:2px 7px;border-radius:6px;
    font-size:13px;color:var(--title);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  .btn{
    display:inline-flex;align-items:center;gap:8px;align-self:flex-start;
    padding:11px 18px;border-radius:10px;text-decoration:none;font-size:15px;font-weight:600;
    color:#fff;background:linear-gradient(100deg,var(--accent),var(--accent2));
    box-shadow:0 8px 22px rgba(234,88,12,.26);transition:transform .15s ease,box-shadow .15s ease;
  }
  .btn:hover{transform:translateY(-1px);box-shadow:0 12px 26px rgba(234,88,12,.32)}
  .btn:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
  .rule{height:1px;background:var(--line);margin:34px 0 16px}
  .foot{font-size:13px;color:var(--faint)}
  @media (max-width:900px){
    .page{grid-template-columns:1fr;grid-template-rows:minmax(210px,32vh) 1fr}
    .visual{padding:12px}
    .anim{width:min(70%,300px)}
    .draw{width:min(46%,200px)}
    .mark{bottom:10px;font-size:11px}
    .content{padding:32px 24px 44px;max-width:none}
    .steps{margin:24px 0 22px}
  }
  @media (max-width:900px) and (max-height:560px){
    .page{grid-template-rows:0 1fr}
    .visual{display:none}
  }
  @media (prefers-reduced-motion: reduce){
    .ring,.ring2,.sat,.content,.live{animation:none}
  }
`

// brandDrawing is the inline SVG fallback shown when the animation cannot load.
const brandDrawing = `  <svg class="draw" viewBox="0 0 300 300" fill="none" aria-hidden="true">
    <g class="ring" opacity=".5"><circle cx="150" cy="150" r="128" stroke="url(#g1)" stroke-width="1" stroke-dasharray="3 9"/></g>
    <g class="ring2" opacity=".65"><circle cx="150" cy="150" r="98" stroke="url(#g1)" stroke-width="1.2" stroke-dasharray="26 14"/></g>
    <g class="sat"><circle cx="150" cy="52" r="5" fill="url(#g2)"/><circle cx="150" cy="52" r="11" fill="url(#g2)" opacity=".2"/></g>
    <rect x="92" y="112" width="116" height="30" rx="9" fill="#1c1917" fill-opacity=".06" stroke="#1c1917" stroke-opacity=".12"/>
    <rect x="92" y="150" width="116" height="30" rx="9" fill="#1c1917" fill-opacity=".06" stroke="#1c1917" stroke-opacity=".12"/>
    <rect x="92" y="188" width="116" height="30" rx="9" fill="#1c1917" fill-opacity=".06" stroke="#1c1917" stroke-opacity=".12"/>
    <circle cx="108" cy="127" r="3.5" fill="url(#g2)"/>
    <circle cx="108" cy="165" r="3.5" fill="url(#g2)" opacity=".7"/>
    <circle cx="108" cy="203" r="3.5" fill="url(#g2)" opacity=".45"/>
    <defs>
      <linearGradient id="g1" x1="22" y1="22" x2="278" y2="278" gradientUnits="userSpaceOnUse">
        <stop stop-color="#ea580c" stop-opacity=".8"/><stop offset="1" stop-color="#f59e0b" stop-opacity=".15"/>
      </linearGradient>
      <linearGradient id="g2" x1="139" y1="41" x2="161" y2="63" gradientUnits="userSpaceOnUse">
        <stop stop-color="#ea580c"/><stop offset="1" stop-color="#f59e0b"/>
      </linearGradient>
    </defs>
  </svg>`

// brandFooter is the shared footer block for both pages.
const brandFooter = `    <div class="rule"></div>
    <p class="foot">Managed by Servika</p>`

// animScript returns the Lottie loader. On failure (missing file / JS disabled /
// reduced-motion preference) the inline SVG fallback stays on screen.
func animScript(file string) string {
	return fmt.Sprintf(`<script src="/_srv/lottie.min.js" defer></script>
<script>
window.addEventListener('load', function () {
  try {
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce || !window.lottie) return;            // keep the fallback SVG
    var box = document.getElementById('anim');
    if (!box) return;
    var a = window.lottie.loadAnimation({
      container: box, renderer: 'svg', loop: true, autoplay: true, path: '/_srv/%s'
    });
    a.addEventListener('DOMLoaded', function () {
      document.documentElement.className += ' anim-on';   // hide fallback, show animation
    });
  } catch (e) { /* keep the fallback SVG */ }
});
</script>`, file)
}

// welcomeHTML is the index.html landing page for a newly created domain.
func welcomeHTML(domain string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>%s</title>
<style>%s</style>
</head>
<body>
<div class="page">
  <aside class="visual">
    <div class="anim" id="anim" aria-hidden="true"></div>
%s
    <div class="mark">servika</div>
  </aside>
  <main class="content">
    <span class="eyebrow"><span class="live"></span>Live</span>
    <h1>Your website is ready<br><span class="domain">%s</span></h1>
    <p class="lead">Your domain is connected to the server and answering requests. Upload your content and go live.</p>
    <ol class="steps">
      <li><span class="num">1</span><span><b>Upload your files</b> — over FTP or the panel file manager into the <code>public_html/</code> folder.</span></li>
      <li><span class="num">2</span><span><b>Create your database</b> — one click from the panel; connection details appear immediately.</span></li>
      <li><span class="num">3</span><span><b>Get your SSL certificate</b> — free Let's Encrypt, auto-renewed.</span></li>
    </ol>
%s
  </main>
</div>
%s
</body>
</html>`, domain, brandStyle, brandDrawing, domain, brandFooter, animScript("ready.json"))
}

// WelcomeHTML is the exported wrapper — the subdomain package renders the same
// brand landing page for new subdomains.
func WelcomeHTML(domain string) string { return welcomeHTML(domain) }

// error404HTML is the server-wide 404 page (all domains + subdomains).
func error404HTML() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>404 — Page not found</title>
<style>%s</style>
</head>
<body>
<div class="page">
  <aside class="visual">
    <div class="anim" id="anim" aria-hidden="true"></div>
%s
    <div class="mark">servika</div>
  </aside>
  <main class="content">
    <span class="eyebrow">Error 404</span>
    <div class="code-big">404</div>
    <h1>Page not found</h1>
    <p class="lead">The page you are looking for may have moved, been renamed, or never existed. Check the address and try again.</p>
    <a class="btn" href="/">&larr; Back to home</a>
%s
  </main>
</div>
%s
</body>
</html>`, brandStyle, brandDrawing, brandFooter, animScript("notfound.json"))
}

// defaultParkHTML is what a visitor sees when the Host header or the SNI name
// matches no tenant on this server, served by both catch-all vhosts out of
// defaultWebroot.
//
// It deliberately does NOT call animScript. That loader fetches
// /_srv/lottie.min.js and /_srv/<file>, which errorPageBlock serves through
// `location ^~ /_srv/` in TENANT vhosts only; neither catch-all declares such a
// location, so every load would produce two 404s for an animation that could
// never appear. brandDrawing is already the fallback for exactly that case and
// stands on its own: .anim is display:none until the loader adds .anim-on.
func defaultParkHTML() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>No site is configured for this address</title>
<style>%s</style>
</head>
<body>
<div class="page">
  <aside class="visual">
%s
    <div class="mark">servika</div>
  </aside>
  <main class="content">
    <span class="eyebrow">Not configured</span>
    <h1>No site is configured<br>for <span class="domain">this address</span></h1>
    <p class="lead">The request reached this server, but no site here answers to the domain name you used. If the domain was pointed here recently, DNS may still be propagating.</p>
    <ol class="steps">
      <li><span class="num">1</span><span><b>If you own this domain</b> — add it from the <b>Domains</b> page in the panel.</span></li>
      <li><span class="num">2</span><span><b>If you just added it</b> — wait a few minutes for DNS to propagate and try again.</span></li>
      <li><span class="num">3</span><span><b>If you are a visitor</b> — check the address, or let the site owner know.</span></li>
    </ol>
%s
  </main>
</div>
</body>
</html>`, brandStyle, brandDrawing, brandFooter)
}

// Ensure404Page writes the server-wide 404 page into the root-owned directory
// (idempotent). Called from Init. A tenant CANNOT modify it (outside its home).
func Ensure404Page() {
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(errorPageDir, 0o755); err != nil {
		return
	}
	path := filepath.Join(errorPageDir, errorPageFile)
	next := []byte(error404HTML())
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(next) {
		return // unchanged
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	_ = os.WriteFile(path, next, 0o644)
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(errorPageDir, 0o755)
}

// errorPageBlock is the nginx block injected into vhosts (brand 404 + brand
// assets). ACME/panel are unaffected; the 404 fires only on nginx-level 404s
// (missing file). When the app produces its own 404 (WordPress etc.) that wins.
const errorPageBlock = `    error_page 404 /_srv_404.html;
    location = /_srv_404.html {
        root /usr/share/servika/errors;
        internal;
        access_log off;
    }
    location ^~ /_srv/ {
        alias /usr/share/servika/errors/;
        access_log off;
        expires 7d;
        gzip on;
        gzip_types application/json application/javascript;
    }
`
