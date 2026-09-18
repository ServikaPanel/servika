/* Servika Windows — the embedded local panel (it enters the Go binary through
   go:embed). Plain ES2019: no framework, no module, no outside request.
   SECURITY (XSS): EVERY string from the API is written with textContent or
   .title; innerHTML is NEVER used on API data (see the el + clear helpers). */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }

  // A safe element builder: the text is always written with textContent.
  function el(tag, cls, text) {
    var d = document.createElement(tag);
    if (cls) d.className = cls;
    if (text !== undefined && text !== null) d.textContent = text;
    return d;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function chip(text, kind) { return el('span', 'chip chip-' + kind, text); }

  function writeLoading(box) { clear(box); box.appendChild(el('div', 'loading', t('Loading…'))); }

  function writeEmpty(box, message) { clear(box); box.appendChild(el('div', 'loading', message)); }

  function buildTable(headings) {
    var table = el('table', 'table'), head = el('thead'), tr = el('tr'), body = el('tbody');
    headings.forEach(function (h) { tr.appendChild(el('th', null, h)); });
    head.appendChild(tr);
    table.appendChild(head);
    table.appendChild(body);
    return { table: table, body: body };
  }

  // RFC3339 turns into the local format; anything else is printed as it came
  // (there is no risk of parsing it wrongly).
  function formatTime(v) {
    if (!v) return '—';
    if (/^\d{4}-\d{2}-\d{2}T/.test(v)) {
      var d = new Date(v);
      if (!isNaN(d.getTime())) return d.toLocaleString(activeLang === 'tr' ? 'tr-TR' : 'en-GB');
    }
    return v;
  }

  // ---------- Preferences: cookies, never localStorage ----------
  // The session itself is an HttpOnly cookie. A non-secret preference goes into
  // its own cookie so the panel keeps ONE storage mechanism.
  function readCookie(name) {
    var parts = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < parts.length; i++) {
      var eq = parts[i].indexOf('=');
      if (eq > 0 && parts[i].slice(0, eq) === name) return decodeURIComponent(parts[i].slice(eq + 1));
    }
    return '';
  }
  function writeCookie(name, value) {
    // One year, same-site, and Secure because the panel is HTTPS only.
    document.cookie = name + '=' + encodeURIComponent(value)
      + '; Path=/; Max-Age=31536000; SameSite=Strict; Secure';
  }

  // ---------- Toast (top right, 4 s) ----------
  function toast(message, kind) {
    var box = el('div', 'toast ' + (kind === 'error' ? 'toast-error' : 'toast-success'), message);
    $('toast-tray').appendChild(box);
    setTimeout(function () {
      box.classList.add('toast-leaving');
      setTimeout(function () { if (box.parentNode) box.parentNode.removeChild(box); }, 250);
    }, 4000);
  }

  function showError(err) {
    if (err && err.unauthorized) return; // 401: already back at the sign-in view, no second toast
    toast(err && err.message ? err.message : t('Unknown error'), 'error');
  }

  // ---------- API wrapper ----------
  async function api(path, options) {
    options = options || {};
    var request = { method: options.method || (options.body ? 'POST' : 'GET'), credentials: 'same-origin' };
    if (options.body) {
      request.headers = { 'Content-Type': 'application/json' };
      request.body = JSON.stringify(options.body);
    }
    var response;
    try { response = await fetch(path, request); }
    catch (networkError) { throw new Error(t('The server could not be reached')); }
    if (response.status === 401 && path !== '/api/local/login') {
      showLogin(); // a 401 from any endpoint drops back to the sign-in view
      var stale = new Error(t('A session is required'));
      stale.unauthorized = true;
      throw stale;
    }
    var text = await response.text();
    var data = null;
    if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
    if (!response.ok) {
      var failure = new Error(data && data.error ? data.error : t('Server error') + ' (' + response.status + ')');
      failure.status = response.status; // the wizard's 409 retry reads the status code
      failure.code = data && data.code; // the machine-readable code (INSTALL_PENDING and so on)
      throw failure;
    }
    return data;
  }

  // ---------- View switching ----------
  function showLogin() {
    $('view-panel').hidden = true;
    $('view-login').hidden = false;
    $('login-password').value = '';
    $('login-user').focus();
  }

  function showPanel() {
    $('view-login').hidden = true;
    $('view-panel').hidden = false;
  }

  // ---------- Translation ----------
  // Adding a language means adding one dictionary to LANGS (for example de:{…}).
  // The keys are the interface's own English strings AND the Windows state terms.
  // 'en' carries nothing: a missing key returns the key itself, which IS English.
  var LANGS = {
    en: {},
    tr: {
      Running: 'Çalışıyor', Stopped: 'Durduruldu', Started: 'Başlatıldı', Paused: 'Duraklatıldı',
      StartPending: 'Başlatılıyor', StopPending: 'Durduruluyor',
      Auto: 'Otomatik', Automatic: 'Otomatik', Manual: 'El ile', Disabled: 'Devre dışı',
      Boot: 'Önyükleme', System: 'Sistem',
      Overview: 'Genel Bakış', Sites: 'Siteler', 'Event Log': 'Olay Günlüğü', Tasks: 'Görevler',
      Databases: 'Veritabanları', Services: 'Servisler', Setup: 'Kurulum', 'Sign out': 'Çıkış',
      General: 'Genel', Hosting: 'Barındırma', Server: 'Sunucu', Profile: 'Profil',
      Plans: 'Planlar', Settings: 'Ayarlar',
      'Search: site, database, page…': 'Ara: site, veritabanı, sayfa…',
      Refresh: 'Yenile', Capabilities: 'Yetenekler', 'Scheduled Tasks': 'Zamanlanmış Görevler',
      'Setup Wizard': 'Kurulum Sihirbazı', 'User name': 'Kullanıcı adı', Password: 'Parola',
      'Sign in': 'Giriş yap', 'Add Site': 'Site Ekle', Create: 'Oluştur', Continue: 'Devam', Back: 'Geri',
      'Start Setup': 'Kurulumu Başlat', 'Back to Overview': "Genel Bakış'a Dön", Stop: 'Durdur',
      'Continue (install the rest)': 'Devam Et (kalanları kur)', 'Microsoft tasks': 'Microsoft görevleri',
      Hostname: 'Sunucu adı', Version: 'Sürüm', Channel: 'Kanal',
      Select: 'Seç', Confirm: 'Onay', Install: 'Kurulum', Summary: 'Özet',
      'Search components…': 'Bileşen ara…',
      All: 'Tümü', Error: 'Hata', Warning: 'Uyarı', Info: 'Bilgi',
      'Install a database engine from the Setup tab first': 'Önce Kurulum sekmesinden bir veritabanı motoru kurun',
      'Experimental components may take long and may need manual configuration': 'Deneysel bileşenler uzun sürebilir ve elle yapılandırma gerektirebilir',
      'No matching component': 'Eşleşen bileşen yok',
      downloading: 'indiriliyor', installing: 'kuruluyor', downloaded: 'indi',
      'ETA —': 'kalan —', 'ETA ~': 'kalan ~', elapsed: 'geçen', 'est.': 'tahmini',
      'Loading…': 'Yükleniyor…', 'Could not be loaded': 'Yüklenemedi', 'Unknown error': 'Bilinmeyen hata',
      'The server could not be reached': 'Sunucuya ulaşılamadı', 'A session is required': 'Oturum gerekli',
      'Server error': 'Sunucu hatası',
      Name: 'Ad', State: 'Durum', Bindings: 'Bağlamalar', Detail: 'Detay', Close: 'Kapat',
      Delete: 'Sil', 'Are you sure?': 'Emin misin?', 'No site is registered': 'Kayıtlı site yok',
      'IIS site': 'IIS sitesi', 'All are running': 'Tümü çalışıyor', down: 'kapalı',
      CPU: 'CPU', RAM: 'RAM', Disk: 'Disk', Memory: 'Bellek', free: 'boş', total: 'toplam',
      'Current use': 'Anlık kullanım', 'System Health': 'Sistem Sağlığı',
      'System Resources': 'Sistem Kaynakları', 'Last 24 samples': 'Son 24 örnek',
      'Server & Services': 'Sunucu & Servisler', 'See all': 'Tümünü Gör',
      Active: 'Aktif', Down: 'Kapalı', 'Disk State': 'Disk Durumu', Healthy: 'Sağlıklı', Normal: 'Normal',
      Excellent: 'Mükemmel', Good: 'İyi', Caution: 'Dikkat', Critical: 'Kritik',
      'Storage Usage': 'Depolama Kullanımı', Used: 'Kullanılan', Free: 'Boş',
      'No disk data': 'Disk verisi yok', 'Quick Actions': 'Hızlı İşlemler', Database: 'Veritabanı',
      'No capability is active': 'Etkin yetenek yok', 'All systems are running': 'Tüm sistemler çalışıyor',
      'services are down': 'servis kapalı',
      'Not selftested — run `servika-agent selftest` on the server': 'Sınanmadı — sunucuda `servika-agent selftest` çalıştırın',
      'The dashboard could not be drawn': 'Panel çizilemedi',
      unlimited: 'sınırsız', 'Plan assigned': 'Plan atandı', 'the limits were applied': 'limitler uygulandı',
      'the limits could not be applied': 'limit uygulanamadı',
      'Quota engine': 'Kota motoru', None: 'Yok',
      'The disk quota can be enforced (FSRM is installed).': 'Disk kotası uygulanabilir (FSRM kurulu).',
      'FSRM is not installed — the disk quota is not enforced; only the IIS limits work.': 'FSRM kurulu değil — disk kotası uygulanmaz; yalnız IIS limitleri çalışır.',
      'Install the quota engine': 'Kota motorunu kur', 'Installing… (a few minutes)': 'Kuruluyor… (birkaç dakika)',
      'FSRM was installed — the server must be restarted': 'FSRM kuruldu — sunucu yeniden başlatılmalı',
      'FSRM was installed': 'FSRM kuruldu', 'There is no plan yet': 'Henüz plan yok',
      Connections: 'Bağlantı', Bandwidth: 'Bant', Edit: 'Düzenle', 'Plan deleted': 'Plan silindi',
      'Plan name': 'Plan adı', 'Disk MB (0=∞)': 'Disk MB (0=∞)', 'Connections (0=∞)': 'Bağlantı (0=∞)',
      'Bandwidth KB/s (0=∞)': 'Bant KB/s (0=∞)', 'CPU % (0=∞)': 'CPU % (0=∞)', 'Memory MB (0=∞)': 'Bellek MB (0=∞)',
      'Save the plan': 'Planı kaydet', 'Plan saved': 'Plan kaydedildi',
      'Site assignments': 'Site atamaları', Site: 'Site', Plan: 'Plan', '— no plan —': '— plan yok —',
      'The plan assignment was removed': 'Plan ataması kaldırıldı',
      'Agent details': 'Ajan bilgisi', Selftested: 'Sınanmış', Yes: 'Evet', No: 'Hayır',
      'Panel port': 'Panel portu', 'Central API port': 'Merkezi API portu',
      Language: 'Dil', 'Panel language': 'Panel dili',
      'Change the panel password': 'Panel parolasını değiştir', 'Current password': 'Mevcut parola',
      'New password (at least 8)': 'Yeni parola (en az 8)', 'New password (again)': 'Yeni parola (tekrar)',
      'Change the password': 'Parolayı değiştir',
      'The new password must be at least 8 characters': 'Yeni parola en az 8 karakter olmalı',
      'The new passwords do not match': 'Yeni parolalar eşleşmiyor', 'The password was changed': 'Parola değiştirildi',
      'The detail could not be loaded': 'Detay yüklenemedi', 'Physical path': 'Fiziksel yol',
      'Danger zone': 'Tehlikeli bölge',
      'The site is removed from the IIS configuration; the files (webroot) are NOT deleted.': 'Site IIS yapılandırmasından kaldırılır; dosyalar (webroot) SİLİNMEZ.',
      'Application pool': 'Uygulama havuzu', Pool: 'Havuz', Start: 'Başlat', Recycle: 'Geri dönüştür',
      'No managed code': 'Yönetilen kod yok',
      "The pool's .NET version was updated": 'Havuz .NET sürümü güncellendi',
      Protocol: 'Protokol', Port: 'Port', Host: 'Host', 'Binding deleted': 'Bağlama silindi',
      'Add binding': 'Bağlama ekle', 'Binding added': 'Bağlama eklendi',
      'Current state': 'Mevcut durum', 'There is at least one HTTPS binding': 'En az bir HTTPS bağlaması var',
      'There is no HTTPS binding': 'HTTPS bağlaması yok', "Get a Let's Encrypt certificate": "Let's Encrypt SSL al",
      'Getting it…': 'Alınıyor…', Done: 'Tamamlandı',
      Time: 'Zaman', Level: 'Seviye', Source: 'Kaynak', 'Event ID': 'Olay ID', Message: 'Mesaj',
      'There is no event to show': 'Gösterilecek olay yok',
      'Last Run': 'Son Koşum', Next: 'Sonraki', 'Last Result': 'Son Sonuç',
      'There is no task to show': 'Gösterilecek görev yok',
      'Size (MB)': 'Boyut (MB)', 'This engine has no database': 'Bu motorda veritabanı yok',
      'There is no service': 'Servis yok', 'Start type': 'Başlangıç', Restart: 'Yeniden',
      'was applied': 'uygulandı', drive: 'sürücü',
      'The catalog has no item': 'Katalogda kalem yok', Selected: 'Seçili', components: 'bileşen',
      INSTALLED: 'KURULU', EXPERIMENTAL: 'DENEYSEL', SOON: 'YAKINDA',
      'Total estimated time': 'Toplam tahmini süre', Installing: 'Kuruluyor',
      'setup is starting': 'kurulumu başlıyor', 'was installed': 'kuruldu',
      'was partly installed — more configuration is needed': 'kısmi kuruldu — ek yapılandırma gerekli',
      'could not be installed': 'kurulamadı', 'setup FAILED': 'kurulumu başarısız',
      'Another setup is running, it will be retried in 5 s…': 'Başka bir kurulum sürüyor, 5 sn sonra yeniden denenecek…',
      'the previous setup was left half done (a stale lock)': 'önceki kurulum yarım kalmış (asılı kilit)',
      'The previous setup was left half done. If you are sure no installer is running, clear the lock and try again.': 'Önceki kurulum yarım kalmış. Çalışan bir yükleyici olmadığından eminseniz kilidi temizleyip yeniden deneyin.',
      'Clear the stale lock': 'Asılı kilidi temizle', 'The stale lock was cleared': 'Asılı kilit temizlendi',
      'It could not be cleared': 'Temizlenemedi',
      'The job state could not be read': 'İş durumu okunamadı',
      Component: 'Bileşen', Result: 'Sonuç', Installed: 'Kuruldu',
      'Partial (configuration needed)': 'Kısmi (yapılandırma gerekli)', Failed: 'Başarısız', Skipped: 'Atlandı',
      'Signed in': 'Giriş başarılı', 'The session was closed': 'Oturum kapatıldı',
      'Site added': 'Site eklendi', 'Site deleted': 'Site silindi',
      'Database created': 'Veritabanı oluşturuldu', 'Database deleted': 'Veritabanı silindi'
    }
  };
  var LANG_COOKIE = 'servika_agent_lang';

  function findLang() {
    var saved = readCookie(LANG_COOKIE);
    if (saved && LANGS[saved]) return saved;
    var browser = ((navigator.language || 'en').slice(0, 2)).toLowerCase();
    return LANGS[browser] ? browser : 'en';
  }
  var activeLang = findLang();

  // Translate into the active language; a missing key returns the key itself,
  // which is the English string, so no call site ever breaks.
  function t(s) {
    if (s == null) return '';
    var d = LANGS[activeLang] || LANGS.en;
    return (d && d[s]) || s;
  }

  // A Turkish-aware lower case, for the search comparison.
  function lower(s) { return (s || '').toLocaleLowerCase(activeLang === 'tr' ? 'tr' : 'en'); }

  // Rewrite every static string carrying data-i18n / data-i18n-ph.
  function applyText() {
    var nodes = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = t(nodes[i].getAttribute('data-i18n'));
    var holders = document.querySelectorAll('[data-i18n-ph]');
    for (var j = 0; j < holders.length; j++) holders[j].placeholder = t(holders[j].getAttribute('data-i18n-ph'));
    var selects = document.querySelectorAll('.lang-select');
    for (var m = 0; m < selects.length; m++) selects[m].value = activeLang;
    document.documentElement.lang = activeLang;
  }

  function changeLang(code) {
    if (!LANGS[code]) return;
    activeLang = code;
    writeCookie(LANG_COOKIE, code);
    applyText();
    if ($('view-panel').hidden) return;                       // sign-in screen: static text only
    if (activeTab === 'setup') { if (wizard.step === 1) drawCatalog(); return; } // do not break the wizard
    if (loaded[activeTab] && loaders[activeTab]) loaders[activeTab](); // refresh the dynamic content
  }

  // ---------- Tabs ----------
  var loaders = {
    overview: loadOverview, sites: loadSites, events: loadEvents, tasks: loadTasks,
    databases: loadDatabases, services: loadServices, setup: loadSetup, plans: loadPlans, settings: loadSettings
  };
  var loaded = {};
  var activeTab = 'overview'; // the resource auto-refresh only runs while Services is active

  // ── The two-layer sidebar: rail section ↔ tab mapping ──
  // Every data-tab belongs to a section; the rail icon opens that section's panel.
  var TAB_SECTION = {
    overview: 'general',
    sites: 'hosting', databases: 'hosting', plans: 'hosting',
    services: 'server', setup: 'server', tasks: 'server', events: 'server',
    settings: 'profile'
  };
  var SECTION_TITLE = { general: 'General', hosting: 'Hosting', server: 'Server', profile: 'Profile' };
  var TAB_KEYS = ['overview', 'sites', 'events', 'tasks', 'databases', 'services', 'setup', 'plans', 'settings'];

  // Activate a rail section: the rail icon lights up, that section's tab group
  // becomes visible and the panel caption is updated. It does NOT change the
  // content tab (openTab does that).
  function openSection(key) {
    if (!SECTION_TITLE[key]) key = 'general';
    var rails = document.querySelectorAll('.rail-button');
    for (var i = 0; i < rails.length; i++) {
      var on = rails[i].getAttribute('data-section') === key;
      rails[i].classList.toggle('active', on);
      rails[i].setAttribute('aria-current', on ? 'true' : 'false');
    }
    var groups = document.querySelectorAll('.tab-group');
    for (var j = 0; j < groups.length; j++) {
      groups[j].hidden = groups[j].getAttribute('data-group') !== key;
    }
    var caption = $('panel-caption');
    if (caption) { caption.setAttribute('data-i18n', SECTION_TITLE[key]); caption.textContent = t(SECTION_TITLE[key]); }
  }

  var TAB_COOKIE = 'servika_agent_tab';

  function openTab(name) {
    activeTab = name;
    writeCookie(TAB_COOKIE, name);
    var buttons = document.querySelectorAll('.tab');
    for (var i = 0; i < buttons.length; i++) {
      var on = buttons[i].getAttribute('data-tab') === name;
      buttons[i].classList.toggle('active', on);
      buttons[i].setAttribute('aria-current', on ? 'true' : 'false');
    }
    openSection(TAB_SECTION[name] || 'general'); // keep the content tab and rail section in step
    TAB_KEYS.forEach(function (key) { $('tab-' + key).hidden = (key !== name); });
    if (!loaded[name]) { loaded[name] = true; loaders[name](); } // each tab fetches once on first open
  }

  // ---------- Overview ----------
  var CAPABILITIES = [
    [1, 'Site'], [128, 'Event Log'], [256, 'Tasks'], [512, 'MSSQL'],
    [1024, 'FTP'], [2048, 'DNS'], [4096, '.NET'], [8192, 'MySQL'], [16384, 'PgSQL']
  ];

  function writeSummary(s) {
    lastSummary = s || {};
    $('top-hostname').textContent = s.hostname || '';
    $('top-badge').textContent = (s.version || '?') + ' · ' + (s.channel || '?');
  }

  async function loadOverview() {
    try { writeSummary(await api('/api/local/summary')); }
    catch (err) { showError(err); }
    drawDashboard();
  }

  // ═══════════════════════════════════════════════════════════════════════
  // DASHBOARD — the visual match of the main panel's dashboard. There is no
  // charting library (no outside request), so every chart, donut and ring is
  // inline SVG. Data: /resources, /sites, /services, /summary.
  // ═══════════════════════════════════════════════════════════════════════
  var lastSummary = null;  // the last /summary answer (host, version, channel, capabilities)
  var samples = [];        // the last <=24 samples {cpu,ram,disk} — sparkline + chart
  var chartTab = 'cpu';    // the System Resources chart tab

  // The icons are FIXED SVG strings (they are NOT server data, so innerHTML is safe here).
  var ICON = {
    site: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/></svg>',
    service: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><line x1="10" y1="12" x2="14" y2="12"/></svg>',
    cpu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg>',
    ram: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 7V5M12 7V5M17 7V5M6 17v2M18 17v2"/></svg>',
    disk: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>',
    health: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    chart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    database: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/></svg>',
    setup: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a13.5 13.5 0 0 1 0 18 13.5 13.5 0 0 1 0-18z"/></svg>'
  };

  function svgNode(markup) { var d = el('div'); d.innerHTML = markup; return d.firstChild; }
  function clamp(v) { return Math.max(0, Math.min(100, v || 0)); }

  // the in-card sparkline (an array of 0..100)
  function sparkSVG(points, colour, id) {
    var W = 300, H = 46;
    if (!points || points.length < 2) return svgNode('<svg class="stat-spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none"></svg>');
    var n = points.length, step = W / (n - 1), yy = function (v) { return (H - 4) * (1 - clamp(v) / 100) + 2; };
    var line = 'M0 ' + yy(points[0]).toFixed(1);
    for (var i = 1; i < n; i++) line += ' L' + (i * step).toFixed(1) + ' ' + yy(points[i]).toFixed(1);
    var area = line + ' L' + W + ' ' + H + ' L0 ' + H + ' Z';
    return svgNode('<svg class="stat-spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
      '<defs><linearGradient id="sp-' + id + '" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="' + colour + '" stop-opacity="0.34"/><stop offset="100%" stop-color="' + colour + '" stop-opacity="0"/></linearGradient></defs>' +
      '<path d="' + area + '" fill="url(#sp-' + id + ')"/><path d="' + line + '" fill="none" stroke="' + colour + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>');
  }

  // the big area chart (System Resources)
  function areaChartSVG(values, colour) {
    var W = 600, H = 180, grid = '';
    [25, 50, 75].forEach(function (g) { var y = H * (1 - g / 100); grid += '<line x1="0" y1="' + y.toFixed(1) + '" x2="' + W + '" y2="' + y.toFixed(1) + '" stroke="rgba(255,255,255,.06)" stroke-dasharray="3 3"/>'; });
    if (!values || values.length < 2) return svgNode('<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" style="width:100%;height:100%">' + grid + '</svg>');
    var n = values.length, step = W / (n - 1), yy = function (v) { return H * (1 - clamp(v) / 100); };
    var line = 'M0 ' + yy(values[0]).toFixed(1);
    for (var i = 1; i < n; i++) line += ' L' + (i * step).toFixed(1) + ' ' + yy(values[i]).toFixed(1);
    var area = line + ' L' + W + ' ' + H + ' L0 ' + H + ' Z';
    return svgNode('<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" style="width:100%;height:100%">' +
      '<defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="' + colour + '" stop-opacity="0.3"/><stop offset="100%" stop-color="' + colour + '" stop-opacity="0"/></linearGradient></defs>' +
      grid + '<path d="' + area + '" fill="url(#area)"/><path d="' + line + '" fill="none" stroke="' + colour + '" stroke-width="2" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>');
  }

  // the donut (segments: [{label,value,colour}])
  function donutSVG(segments) {
    var R = 54, C = 2 * Math.PI * R, acc = 0;
    var total = segments.reduce(function (a, x) { return a + x.value; }, 0) || 1;
    var parts = '<circle cx="70" cy="70" r="' + R + '" fill="none" stroke="#18232e" stroke-width="16"/>';
    segments.forEach(function (x) {
      var dash = C * (x.value / total);
      parts += '<circle cx="70" cy="70" r="' + R + '" fill="none" stroke="' + x.colour + '" stroke-width="16" stroke-dasharray="' + dash.toFixed(2) + ' ' + (C - dash).toFixed(2) + '" stroke-dashoffset="' + (-acc).toFixed(2) + '"/>';
      acc += dash;
    });
    return svgNode('<svg viewBox="0 0 140 140"><g transform="rotate(-90 70 70)">' + parts + '</g></svg>');
  }

  function progressBar(value, variant) {
    var p = el('div', 'progress'), f = el('div', 'progress-fill' + (variant ? ' ' + variant : ''));
    f.style.width = Math.max(2, clamp(value)) + '%'; p.appendChild(f); return p;
  }

  // a stat card
  function statCard(title, value, sub, icon, sparkPoints, sparkColour, sparkId) {
    var c = el('div', 'stat-card');
    c.appendChild(el('div', 'glow'));
    var copy = el('div', 'stat-copy');
    copy.appendChild(el('div', 'muted', t(title)));
    var row = el('div', 'stat-value-row');
    row.appendChild(el('strong', null, value == null ? '—' : String(value)));
    copy.appendChild(row);
    copy.appendChild(el('div', 'tiny muted', sub || ''));
    c.appendChild(copy);
    var box = el('div', 'stat-icon'); box.appendChild(svgNode(icon)); c.appendChild(box);
    if (sparkPoints) c.appendChild(sparkSVG(sparkPoints, sparkColour || '#3b82f6', sparkId || 'x'));
    return c;
  }

  // a card shell (the body is appended by the caller)
  function dashCard(title, icon, action, fn) {
    var s = el('section', 'card');
    var head = el('div', 'card-head'), label = el('div', 'card-title');
    if (icon) label.appendChild(svgNode(icon));
    label.appendChild(el('span', null, t(title)));
    head.appendChild(label);
    if (action) {
      var b = el('button', 'ghost-button', t(action)); b.type = 'button';
      if (fn) b.addEventListener('click', fn);
      head.appendChild(b);
    }
    s.appendChild(head);
    return s;
  }

  // readDashboardData — PARALLEL and TIME LIMITED. If one endpoint hangs, the
  // dashboard must not stay blank, so every call falls back to null after 6 s.
  async function readDashboardData() {
    var limited = function (p) {
      return Promise.race([
        Promise.resolve(p),
        new Promise(function (resolve) { setTimeout(function () { resolve(null); }, 6000); })
      ]).catch(function () { return null; });
    };
    var answers = await Promise.all([
      limited(api('/api/local/resources')),
      limited(api('/api/local/sites')),
      limited(api('/api/local/services'))
    ]);
    return {
      resources: answers[0] || null,
      siteCount: answers[1] ? (((answers[1].sites) || []).length) : null,
      services: answers[2] ? ((answers[2].services) || []) : []
    };
  }

  // dashboardNumbers — turns the raw answers into the percentages the cards use
  // and pushes one sample into the ring buffer behind the sparklines.
  function dashboardNumbers(data) {
    var r = data.resources;
    var cpu = r ? Math.round(r.cpu_percent || 0) : null;
    var ram = (r && r.memory) ? Math.round(r.memory.percent || 0) : null;
    var disk = (r && r.disks && r.disks[0]) || null;
    var diskPercent = disk ? Math.round(disk.Percent || 0) : null;
    if (r) {
      var sample = { cpu: cpu || 0, ram: ram || 0, disk: diskPercent || 0 };
      // On the first load the chart must not be empty, so it starts flat.
      if (samples.length === 0) { for (var i = 0; i < 7; i++) samples.push(sample); }
      samples.push(sample);
      while (samples.length > 24) samples.shift();
    }
    var up = data.services.filter(isRunning).length;
    var total = data.services.length;
    var down = total - up;
    var score = r ? Math.max(0, Math.min(100,
      100 - down * 12 - (diskPercent > 90 ? 15 : diskPercent > 80 ? 6 : 0) - (cpu > 92 ? 8 : 0))) : 0;
    return {
      cpu: cpu, ram: ram, disk: disk, diskPercent: diskPercent,
      up: up, total: total, down: down, score: score,
      scoreColour: score >= 85 ? '#10b981' : score >= 60 ? '#f59e0b' : '#f43f5e',
      scoreName: score >= 85 ? t('Excellent') : score >= 60 ? t('Good') : score >= 40 ? t('Caution') : t('Critical')
    };
  }

  function isRunning(s) { return s.State === 'Running' || s.State === 'Started'; }

  // ── THE MAIN DRAW (loadOverview and the auto-refresh both call this) ──
  async function drawDashboard() {
    var root = $('dash-root');
    if (!root) return;
    var data = await readDashboardData();
    var n = dashboardNumbers(data);
    var summary = lastSummary || {};
    try {
      clear(root);
      var page = el('div', 'dash');
      page.appendChild(dashHeading(summary));
      page.appendChild(dashStats(n, data.siteCount));
      page.appendChild(dashFirstRow(n, data, summary));
      page.appendChild(dashSecondRow(n, summary));
      page.appendChild(dashFooter(n, summary));
      root.appendChild(page);
      appendSelftestWarning(page, summary);
    } catch (drawError) {
      clear(root);
      var band = el('div', 'band band-warning'); band.style.margin = '16px';
      band.appendChild(el('span', null, t('The dashboard could not be drawn') + ': ' + (drawError && drawError.message ? drawError.message : drawError)));
      root.appendChild(band);
    }
  }

  function dashHeading(summary) {
    var head = el('div', 'page-title'), left = el('div');
    left.appendChild(el('h1', null, t('Overview')));
    left.appendChild(el('p', null, (summary.hostname || '—') + ' · ' + (summary.version || '?') + ' · ' + (summary.channel || '?')));
    head.appendChild(left);
    var actions = el('div', 'title-actions');
    var refresh = el('button', 'secondary'); refresh.type = 'button';
    refresh.appendChild(svgNode(ICON.chart));
    refresh.appendChild(document.createTextNode(' ' + t('Refresh')));
    refresh.addEventListener('click', function () { loadOverview(); });
    var add = el('button', 'primary'); add.type = 'button';
    add.appendChild(svgNode(ICON.globe));
    add.appendChild(document.createTextNode(' ' + t('Add Site')));
    add.addEventListener('click', function () { openTab('sites'); });
    actions.appendChild(refresh); actions.appendChild(add);
    head.appendChild(actions);
    return head;
  }

  function dashStats(n, siteCount) {
    var grid = el('div', 'stats-grid');
    var r = n.disk;
    grid.appendChild(statCard('Sites', siteCount == null ? '—' : siteCount, t('IIS site'), ICON.site));
    grid.appendChild(statCard('Services', n.total ? (n.up + '/' + n.total) : '—',
      n.down === 0 ? t('All are running') : (n.down + ' ' + t('down')), ICON.service));
    grid.appendChild(statCard('CPU', n.cpu == null ? '—' : (n.cpu + '%'), t('Current use'), ICON.cpu,
      samples.map(function (d) { return d.cpu; }), '#10b981', 'cpu'));
    grid.appendChild(statCard('RAM', n.ram == null ? '—' : (n.ram + '%'), ramSub(), ICON.ram,
      samples.map(function (d) { return d.ram; }), '#8b5cf6', 'ram'));
    grid.appendChild(statCard('Disk', n.diskPercent == null ? '—' : (n.diskPercent + '%'),
      r ? (round1(r.FreeGB) + ' / ' + round1(r.TotalGB) + ' GB ' + t('free')) : '…', ICON.disk,
      samples.map(function (d) { return d.disk; }), '#f59e0b', 'disk'));
    grid.appendChild(statCard('System Health', n.total || n.cpu != null ? n.score : '—', n.scoreName, ICON.health));
    return grid;
  }

  function ramSub() {
    var last = samples.length ? samples[samples.length - 1] : null;
    if (!last || !lastResources || !lastResources.memory) return '…';
    return mb(lastResources.memory.used_mb) + ' / ' + mb(lastResources.memory.total_mb);
  }

  function round1(v) { return (Math.round((v || 0) * 10) / 10).toFixed(1); }

  function dashFirstRow(n, data, summary) {
    var row = el('div', 'grid grid-main');
    row.appendChild(dashChartCard());
    row.appendChild(dashServerCard(n, data, summary));
    row.appendChild(dashHealthCard(n));
    return row;
  }

  function dashChartCard() {
    var card = dashCard('System Resources', ICON.chart, 'Last 24 samples');
    var colours = { cpu: '#10b981', ram: '#8b5cf6', disk: '#f59e0b' };
    var tabs = el('div', 'tabs');
    [['cpu', 'CPU'], ['ram', t('Memory')], ['disk', t('Disk')]].forEach(function (pair) {
      var b = el('button', chartTab === pair[0] ? 'selected' : '', pair[1]); b.type = 'button';
      if (chartTab === pair[0]) { b.style.color = colours[pair[0]]; b.style.borderBottomColor = colours[pair[0]]; }
      b.addEventListener('click', function () { chartTab = pair[0]; drawDashboard(); });
      tabs.appendChild(b);
    });
    card.appendChild(tabs);
    var wrap = el('div', 'chart');
    wrap.appendChild(areaChartSVG(samples.map(function (d) { return d[chartTab]; }), colours[chartTab]));
    card.appendChild(wrap);
    return card;
  }

  function dashServerCard(n, data, summary) {
    var card = dashCard('Server & Services', ICON.site, 'See all', function () { openTab('services'); });
    var list = el('div', 'server-list');
    if (!data.resources) {
      var box = el('div', 'alerts');
      box.appendChild(el('div', 'empty', t('Loading…')));
      list.appendChild(box);
      card.appendChild(list);
      return card;
    }
    var hostRow = el('div', 'server-row'), hostMain = el('div', 'server-main');
    var hostIcon = el('div', 'server-icon'); hostIcon.appendChild(svgNode(ICON.site)); hostMain.appendChild(hostIcon);
    var hostText = el('div');
    hostText.appendChild(el('strong', null, summary.hostname || '—'));
    hostText.appendChild(el('small', null, summary.version || ''));
    hostMain.appendChild(hostText);
    hostRow.appendChild(hostMain);
    hostRow.appendChild(el('span', 'status', t('Active')));
    var metrics = el('div', 'metrics');
    metrics.appendChild(metricBlock('CPU', n.cpu, n.cpu > 70 ? 'orange' : ''));
    metrics.appendChild(metricBlock('RAM', n.ram, n.ram > 75 ? 'orange' : 'purple'));
    hostRow.appendChild(metrics);
    list.appendChild(hostRow);
    data.services.forEach(function (s) {
      var row = el('div', 'server-row'), main = el('div', 'server-main');
      var icon = el('div', 'server-icon'); icon.appendChild(svgNode(ICON.service)); main.appendChild(icon);
      var text = el('div');
      text.appendChild(el('strong', null, s.DisplayName || s.Name || '—'));
      text.appendChild(el('small', null, s.Name || ''));
      main.appendChild(text);
      row.appendChild(main);
      row.appendChild(el('span', 'status' + (isRunning(s) ? '' : ' down'), isRunning(s) ? t('Active') : t('Down')));
      list.appendChild(row);
    });
    card.appendChild(list);
    return card;
  }

  function metricBlock(name, value, variant) {
    var block = el('div'), label = el('label');
    label.appendChild(document.createTextNode(name + ' '));
    label.appendChild(el('b', null, (value || 0) + '%'));
    block.appendChild(label);
    block.appendChild(progressBar(value, variant));
    return block;
  }

  function dashHealthCard(n) {
    var card = dashCard('System Health', ICON.health);
    var health = el('div', 'health');
    var ring = el('div', 'health-ring');
    ring.style.background = 'conic-gradient(' + n.scoreColour + ' 0 ' + n.score + '%, #18232e ' + n.score + '%)';
    var inner = el('div');
    inner.appendChild(el('strong', null, n.total || n.cpu != null ? String(n.score) : '—'));
    var name = el('small', null, n.scoreName); name.style.color = n.scoreColour;
    inner.appendChild(name);
    ring.appendChild(inner);
    health.appendChild(ring);
    var list = el('div', 'health-list');
    [[t('Services'), n.total ? (n.up + ' / ' + n.total) : '—', n.down === 0],
     [t('Disk State'), n.diskPercent == null ? '—' : (n.diskPercent < 90 ? t('Healthy') : n.diskPercent + '%'), n.diskPercent != null && n.diskPercent < 90],
     [t('CPU'), n.cpu == null ? '—' : (n.cpu < 85 ? t('Normal') : n.cpu + '%'), n.cpu != null && n.cpu < 85],
     [t('Memory'), n.ram == null ? '—' : (n.ram < 85 ? t('Normal') : n.ram + '%'), n.ram != null && n.ram < 85]
    ].forEach(function (row) {
      var line = el('div');
      line.appendChild(el('span', null, row[0]));
      var value = el('b', row[2] ? '' : 'warn', String(row[1]));
      if (!row[2]) value.style.color = '#fb923c';
      line.appendChild(value);
      list.appendChild(line);
    });
    health.appendChild(list);
    card.appendChild(health);
    return card;
  }

  function dashSecondRow(n, summary) {
    var row = el('div', 'grid grid-second');
    row.appendChild(dashStorageCard(n.disk));
    row.appendChild(dashQuickCard());
    row.appendChild(dashCapabilityCard(summary));
    return row;
  }

  function dashStorageCard(disk) {
    var card = dashCard('Storage Usage', ICON.disk);
    if (!disk) {
      var empty = el('div', 'alerts');
      empty.appendChild(el('div', 'empty', t('No disk data')));
      card.appendChild(empty);
      return card;
    }
    var used = Math.max(0, (disk.TotalGB - disk.FreeGB));
    var segments = [
      { label: t('Used'), value: used, colour: '#3b82f6' },
      { label: t('Free'), value: disk.FreeGB, colour: '#10b981' }
    ];
    var wrap = el('div', 'storage'), ring = el('div', 'storage-ring');
    ring.appendChild(donutSVG(segments));
    var centre = el('div', 'storage-inner'), centreText = el('div');
    centreText.appendChild(el('strong', null, used.toFixed(1) + ' GB'));
    centreText.appendChild(el('small', null, t('Used')));
    centre.appendChild(centreText);
    ring.appendChild(centre);
    wrap.appendChild(ring);
    var list = el('div', 'storage-list');
    segments.forEach(function (x) {
      var row = el('div'), dot = el('i');
      dot.style.background = x.colour;
      row.appendChild(dot);
      row.appendChild(el('span', null, x.label));
      row.appendChild(el('b', null, x.value.toFixed(1) + ' GB'));
      list.appendChild(row);
    });
    wrap.appendChild(list);
    card.appendChild(wrap);
    var foot = el('div', 'storage-foot'), free = el('span', 'storage-free');
    free.appendChild(el('b', null, round1(disk.FreeGB) + ' GB'));
    free.appendChild(document.createTextNode(' ' + t('free') + ' · ' + round1(disk.TotalGB) + ' GB ' + t('total')));
    foot.appendChild(free);
    card.appendChild(foot);
    return card;
  }

  function dashQuickCard() {
    var card = dashCard('Quick Actions', ICON.bolt);
    var grid = el('div', 'quick-grid');
    [[ICON.globe, t('Add Site'), 'sites'], [ICON.database, t('Database'), 'databases'], [ICON.disk, t('Plans'), 'plans'],
     [ICON.service, t('Services'), 'services'], [ICON.setup, t('Setup'), 'setup'], [ICON.settings, t('Settings'), 'settings']
    ].forEach(function (item) {
      var b = el('button'); b.type = 'button';
      b.appendChild(svgNode(item[0]));
      b.appendChild(el('span', null, item[1]));
      b.addEventListener('click', function () { openTab(item[2]); });
      grid.appendChild(b);
    });
    card.appendChild(grid);
    return card;
  }

  function dashCapabilityCard(summary) {
    var card = dashCard('Capabilities', ICON.health);
    var row = el('div', 'chip-row');
    var bits = summary.capabilities || 0, count = 0;
    CAPABILITIES.forEach(function (c) { if (bits & c[0]) { row.appendChild(chip(t(c[1]), 'blue')); count++; } });
    if (!count) row.appendChild(el('span', 'dim', t('No capability is active')));
    card.appendChild(row);
    return card;
  }

  function dashFooter(n, summary) {
    var footer = el('footer', 'dash-footer');
    var left = el('div');
    left.appendChild(el('i', 'online-dot' + (n.down === 0 ? '' : ' warn')));
    left.appendChild(document.createTextNode(' ' + (n.down === 0 ? t('All systems are running') : (n.down + ' ' + t('services are down')))));
    footer.appendChild(left);
    footer.appendChild(el('span', null, summary.hostname || ''));
    footer.appendChild(el('span', null, (summary.version || '') + (summary.channel ? ' · ' + summary.channel : '')));
    return footer;
  }

  // A host whose selftest never passed cannot create a site, so say so where the
  // operator will look first rather than only failing at the create call.
  function appendSelftestWarning(page, summary) {
    var unproven = summary && (summary.selftested === false
      || (summary.capabilities != null && (summary.capabilities & 1) === 0));
    if (!unproven) return;
    var band = el('div', 'band band-warning');
    band.style.marginTop = '12px';
    band.appendChild(el('span', null, t('Not selftested — run `servika-agent selftest` on the server')));
    page.appendChild(band);
  }

  // ---------- Sites ----------
  async function loadSites() {
    var root = $('sites-root');
    writeLoading(root);
    try {
      var answer = await api('/api/local/sites');
      var list = (answer && answer.sites) || [];
      clear(root);
      if (!list.length) { writeEmpty(root, t('No site is registered')); return; }
      var table = buildTable([t('Name'), t('State'), t('Bindings'), '']);
      list.forEach(function (s) { appendSiteRow(table.body, s); });
      root.appendChild(table.table);
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  function appendSiteRow(body, site) {
    var tr = el('tr');
    tr.appendChild(el('td', 'mono', site.name));
    var state = el('td');
    state.appendChild(chip(t(site.state) || '—', site.state === 'Started' ? 'green' : 'neutral'));
    tr.appendChild(state);
    var bindings = el('td', 'mono truncate', site.bindings);
    bindings.title = site.bindings || ''; // the full value lives in the tooltip
    tr.appendChild(bindings);
    var actions = el('td', 'actions');
    var detailButton = el('button', 'btn btn-outline btn-small', t('Detail'));
    detailButton.type = 'button';
    actions.appendChild(detailButton);
    actions.appendChild(siteDeleteButton(site.name));
    tr.appendChild(actions);
    // the accordion detail row (fetched once on first open; a second click closes it)
    var detailRow = el('tr', 'site-detail');
    detailRow.hidden = true;
    var cell = el('td');
    cell.colSpan = 4;
    detailRow.appendChild(cell);
    var detailLoaded = false;
    detailButton.addEventListener('click', async function () {
      detailRow.hidden = !detailRow.hidden;
      detailButton.textContent = detailRow.hidden ? t('Detail') : t('Close');
      if (!detailRow.hidden && !detailLoaded) { detailLoaded = await fillSiteDetail(site.name, cell); }
    });
    body.appendChild(tr);
    body.appendChild(detailRow);
  }

  // Instead of confirm(): a two-step delete. The first click turns the button
  // into "Are you sure?" and a second click within 3 s confirms it.
  function deleteButton(confirmed) {
    var b = el('button', 'btn btn-danger btn-small', t('Delete'));
    b.type = 'button';
    var armed = false, timer = 0;
    function reset() { armed = false; b.textContent = t('Delete'); b.classList.remove('confirming'); }
    b.addEventListener('click', async function () {
      if (!armed) {
        armed = true;
        b.textContent = t('Are you sure?');
        b.classList.add('confirming');
        timer = setTimeout(reset, 3000);
        return;
      }
      clearTimeout(timer);
      b.disabled = true;
      try { await confirmed(); }
      catch (err) { showError(err); b.disabled = false; reset(); }
    });
    return b;
  }

  function siteDeleteButton(name) {
    return deleteButton(async function () {
      await api('/api/local/sites?domain=' + encodeURIComponent(name), { method: 'DELETE' });
      toast(t('Site deleted') + ': ' + name, 'success');
      loadSites();
    });
  }

  // fillSiteDetail draws the site detail panel; true on success, so the
  // accordion does not fetch it a second time.
  async function fillSiteDetail(name, cell) {
    writeLoading(cell);
    try {
      var detail = await api('/api/local/site-detail?domain=' + encodeURIComponent(name));
      clear(cell);
      var wrap = el('div', 'detail-wrap');
      var panels = buildSubTabs(wrap, [['general', 'General'], ['bindings', 'Bindings'], ['ssl', 'SSL'], ['pool', 'Pool']]);
      fillDetailGeneral(panels.general, detail, name);
      fillDetailPool(panels.pool, detail, name, cell);
      fillDetailBindings(panels.bindings, detail, name, cell);
      fillDetailSSL(panels.ssl, detail, name);
      cell.appendChild(wrap);
      return true;
    } catch (err) { writeEmpty(cell, t('The detail could not be loaded')); showError(err); return false; }
  }

  // buildSubTabs appends the sub-tab bar and returns the panel per key.
  function buildSubTabs(wrap, definitions) {
    var bar = el('div', 'sub-tabs'), content = el('div', 'sub-tab-content'), panels = {};
    definitions.forEach(function (def, index) {
      var button = el('button', 'sub-tab' + (index === 0 ? ' active' : ''), t(def[1]));
      button.type = 'button';
      var panel = el('div', 'sub-panel'); panel.hidden = (index !== 0);
      panels[def[0]] = panel;
      button.addEventListener('click', function () {
        var all = bar.querySelectorAll('.sub-tab');
        for (var i = 0; i < all.length; i++) all[i].classList.remove('active');
        button.classList.add('active');
        definitions.forEach(function (other) { panels[other[0]].hidden = (other[0] !== def[0]); });
      });
      bar.appendChild(button);
      content.appendChild(panel);
    });
    wrap.appendChild(bar);
    wrap.appendChild(content);
    return panels;
  }

  function labelled(label, valueNode) {
    var block = el('div', 'detail-block');
    block.appendChild(el('div', 'detail-label', t(label)));
    block.appendChild(valueNode);
    return block;
  }

  function fillDetailGeneral(panel, detail, name) {
    var running = detail.State === 'Started' || detail.State === 'Running';
    panel.appendChild(labelled('State', chip(t(detail.State) || '—', running ? 'green' : 'neutral')));
    var path = el('div', 'mono truncate', detail.PhysicalPath || '—');
    path.title = detail.PhysicalPath || '';
    panel.appendChild(labelled('Physical path', path));
    var danger = el('div', 'detail-block');
    danger.appendChild(el('div', 'detail-label', t('Danger zone')));
    danger.appendChild(el('div', 'dim', t('The site is removed from the IIS configuration; the files (webroot) are NOT deleted.')));
    danger.appendChild(siteDeleteButton(name));
    panel.appendChild(danger);
  }

  function fillDetailPool(panel, detail, name, cell) {
    var pool = detail.Pool || {};
    var row = el('div', 'detail-pool');
    row.appendChild(el('span', 'mono', pool.Name || '—'));
    var running = pool.State === 'Started' || pool.State === 'Running';
    row.appendChild(chip(t(pool.State) || '—', running ? 'green' : 'neutral'));
    if (pool.Name) {
      row.appendChild(poolButton(pool.Name, 'start', 'Start', name, cell));
      row.appendChild(poolButton(pool.Name, 'stop', 'Stop', name, cell));
      row.appendChild(poolButton(pool.Name, 'recycle', 'Recycle', name, cell));
      var select = el('select');
      [['v4.0', '.NET 4.x'], ['v2.0', '.NET 2.x'], ['', t('No managed code')]].forEach(function (option) {
        var node = el('option', null, option[1]);
        node.value = option[0];
        if ((pool.RuntimeVersion || '') === option[0]) node.selected = true;
        select.appendChild(node);
      });
      select.addEventListener('change', async function () {
        try {
          await api('/api/local/pool-runtime', { body: { name: pool.Name, version: select.value } });
          toast(t("The pool's .NET version was updated"), 'success');
        } catch (err) { showError(err); }
      });
      row.appendChild(select);
    }
    panel.appendChild(labelled('Application pool', row));
  }

  function fillDetailBindings(panel, detail, name, cell) {
    var wrap = el('div', 'table-wrap');
    var table = buildTable([t('Protocol'), t('Port'), t('Host'), 'SSL', '']);
    (detail.Bindings || []).forEach(function (binding) {
      var row = el('tr');
      row.appendChild(el('td', 'mono', binding.Protocol));
      row.appendChild(el('td', 'mono', binding.Port));
      var host = el('td', 'mono truncate', binding.Host || '*');
      host.title = binding.Host || '*';
      row.appendChild(host);
      var ssl = el('td');
      ssl.appendChild(binding.SSL ? chip('SSL', 'green') : el('span', 'dim', '—'));
      row.appendChild(ssl);
      var actions = el('td', 'actions');
      actions.appendChild(deleteButton(async function () {
        await api('/api/local/binding?site=' + encodeURIComponent(name)
          + '&protocol=' + encodeURIComponent(binding.Protocol)
          + '&port=' + encodeURIComponent(binding.Port)
          + '&host=' + encodeURIComponent(binding.Host || ''), { method: 'DELETE' });
        toast(t('Binding deleted'), 'success');
        fillSiteDetail(name, cell);
      }));
      row.appendChild(actions);
      table.body.appendChild(row);
    });
    wrap.appendChild(table.table);
    panel.appendChild(wrap);
    panel.appendChild(bindingForm(name, cell));
  }

  function bindingForm(name, cell) {
    var form = el('form', 'mini-form');
    var protocol = el('select');
    ['http', 'https'].forEach(function (p) { var o = el('option', null, p); o.value = p; protocol.appendChild(o); });
    var port = el('input', 'port'); port.type = 'text'; port.placeholder = 'port'; port.setAttribute('aria-label', 'Port');
    var host = el('input'); host.type = 'text'; host.placeholder = 'host (for example example.com)'; host.setAttribute('aria-label', 'Host');
    var add = el('button', 'btn btn-filled btn-small', t('Add binding')); add.type = 'submit';
    form.appendChild(protocol); form.appendChild(port); form.appendChild(host); form.appendChild(add);
    form.addEventListener('submit', async function (e) {
      e.preventDefault(); add.disabled = true;
      try {
        await api('/api/local/binding-add', { body: { site: name, protocol: protocol.value, port: port.value.trim(), host: host.value.trim() } });
        toast(t('Binding added'), 'success');
        fillSiteDetail(name, cell);
      } catch (err) { showError(err); add.disabled = false; }
    });
    return form;
  }

  function fillDetailSSL(panel, detail, name) {
    var hasSSL = (detail.Bindings || []).some(function (b) { return b.SSL; });
    panel.appendChild(labelled('Current state', hasSSL
      ? chip(t('There is at least one HTTPS binding'), 'green')
      : el('span', 'dim', t('There is no HTTPS binding'))));
    var block = el('div', 'detail-block');
    var button = el('button', 'btn btn-outline', t("Get a Let's Encrypt certificate"));
    button.type = 'button';
    button.addEventListener('click', async function () {
      button.disabled = true;
      var label = button.textContent;
      button.textContent = t('Getting it…');
      try {
        var answer = await api('/api/local/site-ssl', { body: { site: name } });
        var message = (answer && answer.message) || t('Done');
        toast(message, 'success');
        writeSSLMessage(block, message);
      } catch (err) { showError(err); writeSSLMessage(block, err.message); }
      button.textContent = label;
      button.disabled = false;
    });
    block.appendChild(button);
    panel.appendChild(block);
  }

  function writeSSLMessage(block, text) {
    var line = block.querySelector('.ssl-message'); // update the one line rather than stacking them
    if (!line) { line = el('div', 'ssl-message'); block.appendChild(line); }
    line.textContent = text;
  }

  function poolButton(pool, action, label, siteName, cell) {
    var b = el('button', 'btn btn-outline btn-small', t(label));
    b.type = 'button';
    b.addEventListener('click', async function () {
      b.disabled = true;
      try {
        await api('/api/local/pool-action', { body: { name: pool, action: action } });
        toast(t('Pool') + ': ' + t(label) + ' ' + t('was applied'), 'success');
        fillSiteDetail(siteName, cell); // refresh the state chip
      } catch (err) { showError(err); b.disabled = false; }
    });
    return b;
  }

  // ---------- Hosting plans ----------
  // 0 means UNLIMITED. The limits are always applied with appcmd; the disk quota
  // is only applied when FSRM is installed, and the "Quota engine" card says so
  // plainly rather than letting an unenforced quota look enforced.
  function planValue(v, unit) { return (!v || v <= 0) ? t('unlimited') : (v + (unit ? ' ' + unit : '')); }

  function planAssignToast(result) {
    if (!result) { toast(t('Plan assigned'), 'success'); return; }
    var message = t('Plan assigned') + ' — ' + (result.limitsSet ? t('the limits were applied') : t('the limits could not be applied'));
    if (result.quotaNote) message += '. ' + result.quotaNote;
    if (result.warnings && result.warnings.length) message += ' — ' + result.warnings.join('; ');
    toast(message, 'success');
  }

  async function loadPlans() {
    var root = $('plans-root');
    writeLoading(root);
    try {
      var status = await api('/api/local/plans');
      var siteAnswer = await api('/api/local/sites');
      var sites = (siteAnswer && siteAnswer.sites) || [];
      var plans = (status && status.plans) || [];
      var assignments = (status && status.assignments) || {};
      clear(root);
      root.appendChild(quotaEngineCard(status.quotaEngine));
      root.appendChild(planTableCard(plans));
      root.appendChild(planAssignmentCard(sites, plans, assignments));
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  function quotaEngineCard(installed) {
    var card = el('div', 'card tabular');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, t('Quota engine')));
    card.appendChild(head);
    var body = el('div', 'card-body');
    var row = el('div', 'detail-pool');
    if (installed) {
      row.appendChild(chip('FSRM', 'green'));
      row.appendChild(el('span', 'dim', t('The disk quota can be enforced (FSRM is installed).')));
    } else {
      row.appendChild(chip(t('None'), 'neutral'));
      row.appendChild(el('span', 'dim', t('FSRM is not installed — the disk quota is not enforced; only the IIS limits work.')));
      row.appendChild(quotaInstallButton());
    }
    body.appendChild(row);
    card.appendChild(body);
    return card;
  }

  function quotaInstallButton() {
    var button = el('button', 'btn btn-outline btn-small', t('Install the quota engine'));
    button.type = 'button';
    button.addEventListener('click', async function () {
      button.disabled = true;
      var label = button.textContent;
      button.textContent = t('Installing… (a few minutes)');
      try {
        var answer = await api('/api/local/quota-engine-install', { body: {} });
        toast(answer && answer.restart ? t('FSRM was installed — the server must be restarted') : t('FSRM was installed'), 'success');
        loadPlans();
      } catch (err) { showError(err); button.textContent = label; button.disabled = false; }
    });
    return button;
  }

  function planTableCard(plans) {
    var card = el('div', 'card tabular');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, t('Plans')));
    card.appendChild(head);
    var body = el('div', 'card-body');
    var form = planForm();
    if (!plans.length) {
      body.appendChild(el('div', 'loading', t('There is no plan yet')));
    } else {
      var wrap = el('div', 'table-wrap');
      var table = buildTable([t('Name'), t('Disk'), t('Connections'), t('Bandwidth'), 'CPU', t('Memory'), '']);
      plans.forEach(function (plan) { table.body.appendChild(planRow(plan, form.fill)); });
      wrap.appendChild(table.table);
      body.appendChild(wrap);
    }
    body.appendChild(form.node);
    card.appendChild(body);
    return card;
  }

  function planRow(plan, fill) {
    var tr = el('tr');
    tr.appendChild(el('td', 'mono', plan.name));
    tr.appendChild(el('td', 'mono', planValue(plan.diskQuotaMB, 'MB')));
    tr.appendChild(el('td', 'mono', planValue(plan.maxConnections)));
    tr.appendChild(el('td', 'mono', planValue(plan.maxBandwidthKBs, 'KB/s')));
    tr.appendChild(el('td', 'mono', planValue(plan.cpuPercent, '%')));
    tr.appendChild(el('td', 'mono', planValue(plan.memoryMB, 'MB')));
    var actions = el('td', 'actions');
    var edit = el('button', 'btn btn-outline btn-small', t('Edit'));
    edit.type = 'button';
    edit.addEventListener('click', function () { fill(plan); });
    actions.appendChild(edit);
    actions.appendChild(deleteButton(async function () {
      await api('/api/local/plan-delete', { body: { name: plan.name } });
      toast(t('Plan deleted'), 'success');
      loadPlans();
    }));
    tr.appendChild(actions);
    return tr;
  }

  function planForm() {
    var form = el('form', 'plan-form');
    function field(key, label, placeholder) {
      var wrap = el('label', 'plan-field');
      wrap.appendChild(el('span', 'plan-label', t(label)));
      var input = el('input');
      if (key === 'name') { input.type = 'text'; input.maxLength = 40; }
      else { input.type = 'number'; input.min = '0'; input.step = '1'; }
      input.placeholder = placeholder || '';
      input.setAttribute('data-field', key);
      wrap.appendChild(input);
      form.appendChild(wrap);
      return input;
    }
    var name = field('name', 'Plan name', 'Starter');
    var disk = field('diskQuotaMB', 'Disk MB (0=∞)');
    var conns = field('maxConnections', 'Connections (0=∞)');
    var band = field('maxBandwidthKBs', 'Bandwidth KB/s (0=∞)');
    var cpu = field('cpuPercent', 'CPU % (0=∞)');
    var memory = field('memoryMB', 'Memory MB (0=∞)');
    var save = el('button', 'btn btn-filled btn-small', t('Save the plan'));
    save.type = 'submit';
    form.appendChild(save);
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      save.disabled = true;
      var body = {
        name: name.value.trim(),
        diskQuotaMB: parseInt(disk.value || '0', 10) || 0,
        maxConnections: parseInt(conns.value || '0', 10) || 0,
        maxBandwidthKBs: parseInt(band.value || '0', 10) || 0,
        cpuPercent: parseInt(cpu.value || '0', 10) || 0,
        memoryMB: parseInt(memory.value || '0', 10) || 0
      };
      try { await api('/api/local/plan-save', { body: body }); toast(t('Plan saved'), 'success'); loadPlans(); }
      catch (err) { showError(err); save.disabled = false; }
    });
    return {
      node: form,
      fill: function (plan) {
        name.value = plan.name;
        disk.value = plan.diskQuotaMB || 0;
        conns.value = plan.maxConnections || 0;
        band.value = plan.maxBandwidthKBs || 0;
        cpu.value = plan.cpuPercent || 0;
        memory.value = plan.memoryMB || 0;
        name.focus();
      }
    };
  }

  function planAssignmentCard(sites, plans, assignments) {
    var card = el('div', 'card tabular');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, t('Site assignments')));
    card.appendChild(head);
    var body = el('div', 'card-body');
    if (!sites.length) {
      body.appendChild(el('div', 'loading', t('No site is registered')));
      card.appendChild(body);
      return card;
    }
    var wrap = el('div', 'table-wrap');
    var table = buildTable([t('Site'), t('Plan'), '']);
    sites.forEach(function (site) {
      var tr = el('tr');
      tr.appendChild(el('td', 'mono', site.name));
      var cell = el('td');
      cell.appendChild(planSelect(site.name, plans, assignments));
      tr.appendChild(cell);
      tr.appendChild(el('td', 'actions', ''));
      table.body.appendChild(tr);
    });
    wrap.appendChild(table.table);
    body.appendChild(wrap);
    card.appendChild(body);
    return card;
  }

  function planSelect(siteName, plans, assignments) {
    var select = el('select');
    var none = el('option', null, t('— no plan —'));
    none.value = '';
    select.appendChild(none);
    plans.forEach(function (plan) {
      var option = el('option', null, plan.name);
      option.value = plan.name;
      if (assignments[siteName] === plan.name) option.selected = true;
      select.appendChild(option);
    });
    select.addEventListener('change', async function () {
      select.disabled = true;
      try {
        if (select.value === '') {
          await api('/api/local/plan-remove', { body: { site: siteName } });
          toast(t('The plan assignment was removed'), 'success');
        } else {
          planAssignToast(await api('/api/local/plan-assign', { body: { site: siteName, plan: select.value } }));
        }
        loadPlans();
      } catch (err) { showError(err); select.disabled = false; }
    });
    return select;
  }

  // ---------- Settings: agent details + language + panel password ----------
  var LANG_NAME = { en: 'English', tr: 'Türkçe' };

  async function loadSettings() {
    var root = $('settings-root');
    writeLoading(root);
    try {
      var summary = {};
      try { summary = (await api('/api/local/summary')) || {}; } catch (e) { summary = {}; }
      clear(root);
      root.appendChild(agentCard(summary));
      root.appendChild(languageCard());
      root.appendChild(passwordCard());
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  function infoRow(label, value) {
    var block = el('div', 'detail-block');
    block.appendChild(el('div', 'detail-label', t(label)));
    block.appendChild(el('div', 'mono', (value == null || value === '') ? '—' : String(value)));
    return block;
  }

  function agentCard(summary) {
    var card = el('div', 'card tabular');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, t('Agent details')));
    card.appendChild(head);
    var body = el('div', 'card-body');
    var grid = el('div', 'stat-grid');
    grid.appendChild(infoRow('Hostname', summary.hostname));
    grid.appendChild(infoRow('Version', summary.version));
    grid.appendChild(infoRow('Channel', summary.channel));
    grid.appendChild(infoRow('Selftested', summary.selftested ? t('Yes') : t('No')));
    grid.appendChild(infoRow('Panel port', location.port || '8443'));
    grid.appendChild(infoRow('Central API port', '8460'));
    body.appendChild(grid);
    card.appendChild(body);
    return card;
  }

  function languageCard() {
    var card = el('div', 'card tabular');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, t('Language')));
    card.appendChild(head);
    var body = el('div', 'card-body');
    var row = el('div', 'detail-pool');
    row.appendChild(el('span', 'dim', t('Panel language')));
    var select = el('select', 'lang-select');
    Object.keys(LANGS).forEach(function (code) {
      var option = el('option', null, LANG_NAME[code] || code.toUpperCase());
      option.value = code;
      if (code === activeLang) option.selected = true;
      select.appendChild(option);
    });
    select.addEventListener('change', function () { changeLang(select.value); });
    row.appendChild(select);
    body.appendChild(row);
    card.appendChild(body);
    return card;
  }

  function passwordCard() {
    var card = el('div', 'card tabular');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, t('Change the panel password')));
    card.appendChild(head);
    var body = el('div', 'card-body');
    var form = el('form', 'plan-form');
    function field(label) {
      var wrap = el('label', 'plan-field');
      wrap.appendChild(el('span', 'plan-label', t(label)));
      var input = el('input');
      input.type = 'password';
      input.autocomplete = 'new-password';
      input.setAttribute('autocapitalize', 'off');
      input.spellcheck = false;
      wrap.appendChild(input);
      form.appendChild(wrap);
      return input;
    }
    var current = field('Current password');
    var fresh = field('New password (at least 8)');
    var again = field('New password (again)');
    var save = el('button', 'btn btn-filled btn-small', t('Change the password'));
    save.type = 'submit';
    form.appendChild(save);
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      if (fresh.value.length < 8) { toast(t('The new password must be at least 8 characters'), 'error'); return; }
      if (fresh.value !== again.value) { toast(t('The new passwords do not match'), 'error'); return; }
      save.disabled = true;
      try {
        await api('/api/local/change-password', { body: { old_password: current.value, new_password: fresh.value } });
        toast(t('The password was changed'), 'success');
        current.value = ''; fresh.value = ''; again.value = '';
      } catch (err) { showError(err); }
      save.disabled = false;
    });
    body.appendChild(form);
    card.appendChild(body);
    return card;
  }

  // ---------- Event Log ----------
  var eventData = [];
  var LEVELS = { error: ['red', 'Error'], warning: ['amber', 'Warning'], info: ['neutral', 'Info'] };

  async function loadEvents() {
    var root = $('events-root');
    writeLoading(root);
    try {
      var log = $('event-log').value;
      var answer = await api('/api/local/events?log=' + encodeURIComponent(log) + '&count=50');
      eventData = (answer && answer.events) || [];
      drawEvents();
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  // The level filter is applied on the client; the data is not fetched again.
  function drawEvents() {
    var root = $('events-root');
    clear(root);
    var filter = $('event-level').value;
    var list = eventData.filter(function (e) { return !filter || e.Level === filter; });
    if (!list.length) { writeEmpty(root, t('There is no event to show')); return; }
    var table = buildTable([t('Time'), t('Level'), t('Source'), t('Event ID'), t('Message')]);
    list.forEach(function (event) { appendEventRow(table.body, event); });
    root.appendChild(table.table);
  }

  function appendEventRow(body, event) {
    var tr = el('tr', 'clickable');
    tr.tabIndex = 0; // it must open with the keyboard too
    tr.setAttribute('aria-expanded', 'false');
    tr.appendChild(el('td', 'mono', formatTime(event.Time)));
    var level = LEVELS[event.Level] || ['neutral', event.Level || '?'];
    var cell = el('td');
    cell.appendChild(chip(t(level[1]), level[0]));
    tr.appendChild(cell);
    tr.appendChild(el('td', null, event.Source));
    tr.appendChild(el('td', 'mono', (event.ID === undefined || event.ID === null) ? '—' : event.ID));
    tr.appendChild(el('td', 'truncate', event.Text));
    var detail = el('tr', 'event-detail');
    detail.hidden = true;
    var cellDetail = el('td', null, event.Text || '—'); // the full message, still textContent
    cellDetail.colSpan = 5;
    detail.appendChild(cellDetail);
    function toggle() {
      detail.hidden = !detail.hidden;
      tr.setAttribute('aria-expanded', detail.hidden ? 'false' : 'true');
    }
    tr.addEventListener('click', toggle);
    tr.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
    });
    body.appendChild(tr);
    body.appendChild(detail);
  }

  // ---------- Scheduled tasks ----------
  async function loadTasks() {
    var root = $('tasks-root');
    writeLoading(root);
    try {
      var answer = await api('/api/local/tasks?all=' + ($('task-all').checked ? '1' : '0'));
      var list = (answer && answer.tasks) || [];
      clear(root);
      if (!list.length) { writeEmpty(root, t('There is no task to show')); return; }
      var table = buildTable([t('Name'), t('State'), t('Last Run'), t('Next'), t('Last Result')]);
      list.forEach(function (task) {
        var tr = el('tr');
        var name = el('td', 'mono truncate', task.Name);
        name.title = task.Name || ''; // the full name lives in the tooltip
        tr.appendChild(name);
        var state = el('td');
        var kind = task.State === 'Running' ? 'green' : (task.State === 'Disabled' ? 'amber' : 'neutral');
        state.appendChild(chip(t(task.State) || '—', kind));
        tr.appendChild(state);
        tr.appendChild(el('td', 'mono', formatTime(task.LastRun)));
        tr.appendChild(el('td', 'mono', formatTime(task.NextRun)));
        tr.appendChild(resultCell(task.LastResult));
        table.body.appendChild(tr);
      });
      root.appendChild(table.table);
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  function resultCell(value) {
    var cell = el('td', 'mono');
    if (value === 0) cell.appendChild(el('span', 'text-green', '0'));
    else if (value === undefined || value === null) cell.textContent = '—';
    else cell.appendChild(el('span', 'text-red', '0x' + (Number(value) >>> 0).toString(16).toUpperCase()));
    return cell;
  }

  // ---------- Databases ----------
  async function loadDatabases() {
    var select = $('db-engine');
    try {
      var answer = await api('/api/local/db-engines');
      var engines = ((answer && answer.engines) || []).filter(function (e) { return e.Installed; });
      clear(select);
      if (!engines.length) { // with no engine installed, point the operator at Setup
        $('db-no-engine').hidden = false;
        $('db-body').hidden = true;
        return;
      }
      $('db-no-engine').hidden = true;
      $('db-body').hidden = false;
      engines.forEach(function (engine) {
        var option = el('option', null, engine.Name);
        option.value = engine.Kind;
        select.appendChild(option);
      });
      loadDatabaseList();
    } catch (err) { showError(err); }
  }

  function setDatabaseFormDisabled(disabled) {
    ['db-name', 'db-user', 'db-password', 'btn-db-create'].forEach(function (id) { $(id).disabled = disabled; });
  }

  async function loadDatabaseList() {
    var engine = $('db-engine').value;
    var root = $('db-list-root');
    writeLoading(root);
    $('db-warning').hidden = true;
    setDatabaseFormDisabled(false);
    try {
      var answer = await api('/api/local/db-list?engine=' + encodeURIComponent(engine));
      var list = (answer && answer.databases) || [];
      clear(root);
      if (!list.length) { writeEmpty(root, t('This engine has no database')); return; }
      var table = buildTable([t('Name'), t('Size (MB)'), '']);
      list.forEach(function (db) {
        var tr = el('tr');
        tr.appendChild(el('td', 'mono', db.Name));
        tr.appendChild(el('td', 'mono', (db.SizeMB === undefined || db.SizeMB === null) ? '—' : db.SizeMB));
        var actions = el('td', 'actions');
        actions.appendChild(deleteButton(async function () {
          await api('/api/local/db-drop?engine=' + encodeURIComponent(engine) + '&name=' + encodeURIComponent(db.Name), { method: 'DELETE' });
          toast(t('Database deleted') + ': ' + db.Name, 'success');
          loadDatabaseList();
        }));
        tr.appendChild(actions);
        table.body.appendChild(tr);
      });
      root.appendChild(table.table);
    } catch (err) { handleDatabaseError(err, root); }
  }

  // A 422 here means the engine wants a password the agent does not hold. That
  // is not a failure to retry: say what is missing and disable the form.
  function handleDatabaseError(err, root) {
    if (err && err.unauthorized) return;
    if (err && err.status === 422) {
      $('db-warning-text').textContent = err.message;
      $('db-warning').hidden = false;
      setDatabaseFormDisabled(true);
      clear(root);
      return;
    }
    writeEmpty(root, t('Could not be loaded'));
    showError(err);
  }

  // ---------- Services + resources ----------
  async function loadServices() {
    loadResources(); // the stat cards live on this tab too
    var root = $('services-root');
    writeLoading(root);
    try {
      var answer = await api('/api/local/services');
      var list = (answer && answer.services) || [];
      clear(root);
      if (!list.length) { writeEmpty(root, t('There is no service')); return; }
      var table = buildTable([t('Services'), t('State'), t('Start type'), '']);
      list.forEach(function (service) { table.body.appendChild(serviceRow(service)); });
      root.appendChild(table.table);
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  function serviceRow(service) {
    var tr = el('tr');
    var name = el('td', 'truncate', service.DisplayName || service.Name);
    name.title = service.Name || '';
    tr.appendChild(name);
    var running = isRunning(service);
    var state = el('td');
    state.appendChild(chip(t(service.State) || '—', running ? 'green' : 'neutral'));
    tr.appendChild(state);
    tr.appendChild(el('td', null, t(service.StartType) || '—'));
    var actions = el('td', 'actions');
    if (running) {
      actions.appendChild(serviceButton(service.Name, 'stop', 'Stop', 'btn-outline'));
      actions.appendChild(serviceButton(service.Name, 'restart', 'Restart', 'btn-outline'));
    } else {
      actions.appendChild(serviceButton(service.Name, 'start', 'Start', 'btn-filled'));
    }
    tr.appendChild(actions);
    return tr;
  }

  function serviceButton(name, action, label, style) {
    var b = el('button', 'btn ' + style + ' btn-small', t(label));
    b.type = 'button';
    b.addEventListener('click', async function () {
      b.disabled = true;
      try {
        await api('/api/local/service-action', { body: { name: name, action: action } });
        toast(t(label) + ' ' + t('was applied') + ': ' + name, 'success');
        loadServices();
      } catch (err) { showError(err); b.disabled = false; }
    });
    return b;
  }

  function mb(v) { if (v === undefined || v === null) return '—'; return v >= 1024 ? (v / 1024).toFixed(1) + ' GB' : Math.round(v) + ' MB'; }

  function resourceCard(title, big, sub) {
    var d = el('div', 'stat');
    d.appendChild(el('div', 'stat-head', title));
    d.appendChild(el('div', 'stat-big', big));
    d.appendChild(el('div', 'stat-sub', sub));
    return d;
  }

  var lastResources = null;

  // The resource boxes fail SILENTLY: they are fetched every 5 s, so a toast
  // or a band would turn one broken endpoint into a stream of noise.
  async function loadResources() {
    try {
      var r = await api('/api/local/resources');
      lastResources = r;
      var root = $('resource-row');
      clear(root);
      root.appendChild(resourceCard('CPU', r.cpu_percent == null ? '—' : Math.round(r.cpu_percent) + '%', t('Current use')));
      var memory = r.memory || {};
      root.appendChild(resourceCard('RAM', memory.percent == null ? '—' : Math.round(memory.percent) + '%',
        mb(memory.used_mb) + ' / ' + mb(memory.total_mb)));
      var disk = (r.disks && r.disks[0]) || null;
      var diskSub = disk ? (round1(disk.FreeGB) + ' GB ' + t('free') + ' / ' + round1(disk.TotalGB) + ' GB') : '—';
      if (r.disks && r.disks.length > 1) diskSub += '  ·  +' + (r.disks.length - 1) + ' ' + t('drive');
      root.appendChild(resourceCard('Disk' + (disk ? ' (' + disk.Drive + ')' : ''),
        disk ? Math.round(disk.Percent) + '%' : '—', diskSub));
    } catch (err) { /* silent: a 401 already dropped to the sign-in view inside api() */ }
  }

  // ---------- Setup wizard ----------
  // The backend is single flight: the selected items are installed IN ORDER and
  // the job is watched over SSE, falling back to polling. Switching tabs only
  // hides the section; the watch chain and the DOM state stay in memory, so
  // step 3 carries on from where it was.
  var wizard = {
    step: 1, catalog: [], selected: [], selection: {}, term: '', index: 0, results: {},
    jobID: null, active: false, autoScroll: true, errorStreak: 0, segment: null,
    stream: null, streamGuard: 0, itemStarted: 0
  };

  // ---------- Setup progress formatters (the ETA bar) ----------
  function writeMB(bytes) {
    bytes = bytes || 0;
    if (bytes >= (1 << 30)) return (bytes / (1 << 30)).toFixed(2) + ' GB';
    return (bytes / (1 << 20)).toFixed(1) + ' MB';
  }
  function writeSpeed(bps) {
    if (!bps || bps <= 0) return '—';
    if (bps >= (1 << 20)) return (bps / (1 << 20)).toFixed(1) + ' MB/s';
    return Math.round(bps / 1024) + ' KB/s';
  }
  function writeDuration(seconds) {
    seconds = Math.max(0, Math.round(seconds));
    var m = Math.floor(seconds / 60), s = seconds % 60;
    return m + ':' + (s < 10 ? '0' : '') + s;
  }
  function writeETA(seconds) {
    if (seconds == null || seconds < 0) return t('ETA —');
    if (seconds < 60) return t('ETA ~') + Math.round(seconds) + ' s';
    return t('ETA ~') + writeDuration(seconds);
  }
  function writeElapsed() {
    if (!wizard.itemStarted) return '0:00';
    return writeDuration((Date.now() - wizard.itemStarted) / 1000);
  }

  async function loadSetup() {
    var root = $('setup-list');
    if (wizard.active) return; // the catalog is not refetched while a setup runs
    writeLoading(root);
    showStep(1);
    wizard.term = '';
    $('setup-search').value = '';
    $('btn-setup-next').disabled = true;
    try {
      var answer = await api('/api/local/catalog');
      wizard.catalog = (answer && answer.items) || [];
      drawCatalog();
    } catch (err) { writeEmpty(root, t('Could not be loaded')); showError(err); }
  }

  // The upper bound of the TimeToRun range ("2-5 min" → 5, "3 min" → 3).
  function upperMinutes(text) {
    var found = (text || '').match(/\d+/g);
    if (!found) return 0;
    var max = 0;
    for (var i = 0; i < found.length; i++) { var n = parseInt(found[i], 10); if (n > max) max = n; }
    return max;
  }

  function selectedKeys() {
    return Object.keys(wizard.selection).filter(function (k) { return wizard.selection[k]; });
  }

  // The Continue button's state plus the live "Selected: N components · ~X min".
  function updateSelection() {
    var keys = selectedKeys();
    $('btn-setup-next').disabled = keys.length === 0;
    var minutes = 0;
    wizard.catalog.forEach(function (item) { if (keys.indexOf(item.Key) >= 0) minutes += upperMinutes(item.TimeToRun); });
    $('setup-selection').textContent = t('Selected') + ': ' + keys.length + ' ' + t('components') + ' · ~' + minutes + ' min';
  }

  function drawCatalog() {
    var root = $('setup-list');
    clear(root);
    if (!wizard.catalog.length) { writeEmpty(root, t('The catalog has no item')); updateSelection(); return; }
    var term = wizard.term;
    // A live filter over the array already in memory, by name AND summary.
    var list = wizard.catalog.filter(function (item) {
      return !term || lower(item.Name).indexOf(term) >= 0 || lower(item.Summary).indexOf(term) >= 0;
    });
    if (!list.length) { writeEmpty(root, t('No matching component')); updateSelection(); return; }
    list.forEach(function (item) { root.appendChild(catalogRow(item)); });
    updateSelection();
  }

  function catalogRow(item) {
    var selectable = item.Installable && !item.Installed && item.Tier !== 'undecided';
    var row = el(selectable ? 'label' : 'div', 'setup-item' + (selectable ? '' : ' locked'));
    if (selectable) { // the checkbox only appears on an installable item
      var box = el('input', 'setup-check');
      box.type = 'checkbox';
      box.value = item.Key;
      box.checked = !!wizard.selection[item.Key]; // the selection survives a search or language redraw
      row.appendChild(box);
    }
    var body = el('div', 'setup-body');
    var head = el('div', 'setup-item-head');
    head.appendChild(el('span', null, item.Name));
    if (item.Installed) head.appendChild(chip(t('INSTALLED'), 'green'));
    if (item.Tier === 'experimental') head.appendChild(chip(t('EXPERIMENTAL'), 'amber'));
    if (item.Tier === 'undecided') head.appendChild(chip(t('SOON'), 'neutral'));
    body.appendChild(head);
    body.appendChild(el('p', null, item.Summary));
    row.appendChild(body);
    row.appendChild(el('span', 'setup-time', item.TimeToRun || ''));
    return row;
  }

  function showStep(n) {
    wizard.step = n;
    for (var i = 1; i <= 4; i++) $('setup-step-' + i).hidden = (i !== n);
    var items = document.querySelectorAll('#setup-steps .step');
    for (var j = 0; j < items.length; j++) {
      items[j].classList.toggle('active', j === n - 1);
      items[j].classList.toggle('done', j < n - 1);
    }
  }

  function logLine(text, cls) {
    var box = $('setup-log');
    box.appendChild(el('div', cls || null, text));
    if (wizard.autoScroll) box.scrollTop = box.scrollHeight;
  }

  // ---------- The overall (segmented) progress bar ----------
  // One segment per selected item; the colour carries that item's state
  // (waiting / active / done / partial / failed).
  function buildOverallBar() {
    var root = $('setup-overall-bar');
    clear(root);
    wizard.selected.forEach(function (item) {
      var segment = el('div', 'seg');
      segment.title = item.Name;
      root.appendChild(segment);
    });
    $('setup-overall').hidden = wizard.selected.length < 2; // with one item it says nothing
  }
  function markSegment(index, cls) {
    var segment = $('setup-overall-bar').children[index];
    if (segment) segment.className = 'seg' + (cls ? ' ' + cls : '');
  }

  // ---------- The per-item (live ETA) progress bar ----------
  function resetProgress() {
    var fill = $('prog-fill');
    fill.classList.remove('indeterminate');
    fill.style.width = '0';
    $('prog-label').textContent = '—';
    $('prog-percent').textContent = '';
    $('prog-bottom').textContent = '';
    $('setup-progress').hidden = true;
  }

  // updateProgress reflects the structured progress the backend reports.
  // "downloading" with a known size gives a real percentage, a speed and an ETA.
  // With no size, or while "installing", the bar goes indeterminate: WE DO NOT
  // INVENT A DURATION. The elapsed time and the catalog estimate are shown
  // instead, because a made-up percentage is worse than an honest sweep.
  function updateProgress(progress) {
    var box = $('setup-progress');
    if (!progress || !progress.stage) { box.hidden = true; return; }
    box.hidden = false;
    var current = wizard.selected[wizard.index] || {};
    if (progress.stage === 'downloading' && progress.bytes_total > 0 && progress.percent >= 0) {
      writeKnownProgress(progress, current);
    } else if (progress.stage === 'downloading') {
      writeUnknownDownload(progress, current);
    } else {
      writeInstallingProgress(current);
    }
    if (wizard.autoScroll) $('setup-log').scrollTop = $('setup-log').scrollHeight;
  }

  function writeKnownProgress(progress, current) {
    var fill = $('prog-fill'), stage = $('prog-stage');
    fill.classList.remove('indeterminate');
    fill.style.width = progress.percent + '%';
    stage.textContent = t('downloading'); stage.className = 'chip chip-blue';
    $('prog-label').textContent = progress.label || current.Name || '';
    $('prog-percent').textContent = progress.percent + '%';
    $('prog-bottom').textContent = writeMB(progress.bytes_done) + ' / ' + writeMB(progress.bytes_total)
      + '   ·   ' + writeSpeed(progress.bytes_per_sec) + '   ·   ' + writeETA(progress.seconds_left);
  }

  function writeUnknownDownload(progress, current) {
    var fill = $('prog-fill'), stage = $('prog-stage');
    fill.classList.add('indeterminate');
    stage.textContent = t('downloading'); stage.className = 'chip chip-blue';
    $('prog-label').textContent = progress.label || current.Name || '';
    $('prog-percent').textContent = '';
    $('prog-bottom').textContent = writeMB(progress.bytes_done) + ' ' + t('downloaded')
      + '   ·   ' + writeSpeed(progress.bytes_per_sec);
  }

  function writeInstallingProgress(current) {
    var fill = $('prog-fill'), stage = $('prog-stage');
    fill.classList.add('indeterminate');
    stage.textContent = t('installing'); stage.className = 'chip chip-amber';
    $('prog-label').textContent = current.Name || t('installing');
    $('prog-percent').textContent = '';
    $('prog-bottom').textContent = t('elapsed') + ' ' + writeElapsed()
      + '   ·   ' + t('est.') + ' ' + (current.TimeToRun || '—');
  }

  // applyJobView renders one snapshot (from SSE or from a poll): it refreshes
  // the log pane, updates the ETA bar and, when the job is finished, closes the
  // stream and calls itemFinished. It reports whether the job settled.
  function applyJobView(item, view) {
    clear(wizard.segment); // the job log arrives whole each time, so the pane is replaced
    ((view && view.log) || []).forEach(function (line) { wizard.segment.appendChild(el('div', null, line)); });
    updateProgress(view && view.progress);
    if (wizard.autoScroll) $('setup-log').scrollTop = $('setup-log').scrollHeight;
    if (view && view.finished) { closeStream(); itemFinished(item, view.state, null); return true; }
    return false;
  }

  function closeStream() {
    if (wizard.streamGuard) { clearTimeout(wizard.streamGuard); wizard.streamGuard = 0; }
    if (wizard.stream) { try { wizard.stream.close(); } catch (e) { } wizard.stream = null; }
  }

  // watchJob — REAL TIME: it attaches to the job's event stream. If no message
  // arrives within 3.5 s, or the connection is CLOSED (unrecoverable), it falls
  // back to polling. Once SSE has worked, EventSource reconnects by itself on a
  // temporary drop, and the server sends the current snapshot on connect.
  function watchJob(item) {
    closeStream();
    if (typeof EventSource === 'undefined') { pollJob(item); return; } // the browser cannot stream
    var source;
    try { source = new EventSource('/api/local/catalog/job-stream?id=' + encodeURIComponent(wizard.jobID)); }
    catch (e) { pollJob(item); return; }
    wizard.stream = source;
    var fellBack = false;
    function fallBack() { if (fellBack) return; fellBack = true; closeStream(); pollJob(item); }
    wizard.streamGuard = setTimeout(fallBack, 3500);
    source.onmessage = function (event) {
      if (wizard.stream !== source) return; // an old stream (the item changed): ignore it
      clearTimeout(wizard.streamGuard); wizard.streamGuard = 0;
      wizard.errorStreak = 0;
      var view;
      try { view = JSON.parse(event.data); } catch (e) { return; }
      applyJobView(item, view);
    };
    source.onerror = function () {
      if (wizard.stream !== source) return;
      if (!wizard.active) { closeStream(); return; }
      if (source.readyState === 2) fallBack(); // CLOSED: unrecoverable, poll instead
      // CONNECTING(0): EventSource reconnects on its own, and the guard covers it
    };
  }

  function installNext() {
    if (wizard.index >= wizard.selected.length) { setupFinished(); return; }
    var item = wizard.selected[wizard.index];
    $('setup-current').textContent = t('Installing') + ': ' + item.Name + ' (' + (wizard.index + 1) + '/' + wizard.selected.length + ')';
    markSegment(wizard.index, 'active');
    wizard.itemStarted = Date.now();
    resetProgress();
    logLine('— ' + item.Name + ' ' + t('setup is starting') + ' —', 'log-head');
    wizard.segment = el('div'); // this item's live log pane (replaced on every update)
    $('setup-log').appendChild(wizard.segment);
    tryInstall(item, 3);
  }

  async function tryInstall(item, attemptsLeft) {
    try {
      var answer = await api('/api/local/catalog/install', { body: { key: item.Key } });
      wizard.jobID = answer && answer.job_id;
      wizard.errorStreak = 0;
      watchJob(item); // real time (SSE); it falls back to pollJob when that fails
    } catch (err) { handleInstallError(item, attemptsLeft, err); }
  }

  function handleInstallError(item, attemptsLeft, err) {
    if (err && err.unauthorized) { wizard.active = false; return; } // the session dropped, the wizard stops
    if (err && err.code === 'INSTALL_PENDING') { // a stale lock: do NOT retry, an operator must clear it
      logLine('⚠ ' + (err.message || t('the previous setup was left half done (a stale lock)')), 'log-warn');
      showStaleLockClear(item);
      return;
    }
    if (err && err.status === 409 && attemptsLeft > 0) { // another setup runs: wait 5 s, at most 3 times
      logLine(t('Another setup is running, it will be retried in 5 s…') + ' (' + (4 - attemptsLeft) + '/3)');
      setTimeout(function () { tryInstall(item, attemptsLeft - 1); }, 5000);
      return;
    }
    itemFinished(item, 'failed', err.message);
  }

  // showStaleLockClear — on a stale install lock, offer the operator a
  // "clear and retry" button. It POSTs to the clear-install-lock endpoint and
  // then retries, because only a human can know no installer is still running.
  function showStaleLockClear(item) {
    var box = el('div', 'warning-row');
    box.appendChild(el('span', null, t('The previous setup was left half done. If you are sure no installer is running, clear the lock and try again.')));
    var button = el('button', 'btn btn-outline btn-small', t('Clear the stale lock'));
    button.type = 'button';
    button.addEventListener('click', async function () {
      button.disabled = true;
      try {
        await api('/api/local/clear-install-lock', { body: {} });
        toast(t('The stale lock was cleared'), 'success');
        if (box.parentNode) box.parentNode.removeChild(box);
        tryInstall(item, 3); // cleared, so try again
      } catch (err) { button.disabled = false; toast(t('It could not be cleared') + ': ' + (err.message || ''), 'error'); }
    });
    box.appendChild(button);
    $('setup-log').appendChild(box);
  }

  // pollJob — the POLLING fallback (when SSE cannot be set up): it reads the job
  // state every 2 s, and gives up after 3 consecutive read failures.
  async function pollJob(item) {
    try {
      var view = await api('/api/local/catalog/job?id=' + encodeURIComponent(wizard.jobID));
      wizard.errorStreak = 0;
      if (applyJobView(item, view)) return; // finished: itemFinished ran inside
      setTimeout(function () { pollJob(item); }, 2000);
    } catch (err) {
      if (err && err.unauthorized) { wizard.active = false; return; }
      wizard.errorStreak++;
      if (wizard.errorStreak < 3) { setTimeout(function () { pollJob(item); }, 2000); return; }
      itemFinished(item, 'failed', t('The job state could not be read') + ': ' + err.message);
    }
  }

  function itemFinished(item, state, extraMessage) {
    closeStream();               // this item's stream closes (if there was one)
    wizard.jobID = null;
    $('setup-progress').hidden = true; // the finished item's ETA bar goes away
    var ok = (state === 'done'), partial = (state === 'partial');
    wizard.results[item.Key] = state || 'failed';
    markSegment(wizard.index, ok ? 'done' : partial ? 'partial' : 'failed');
    if (extraMessage) logLine(extraMessage, 'log-error');
    if (ok) {
      logLine('✓ ' + item.Name + ' ' + t('was installed'), 'log-head');
      wizard.index++;
      installNext();
      return;
    }
    if (partial) { // the steps passed but the result is not complete: warn and go on
      logLine('◐ ' + item.Name + ' ' + t('was partly installed — more configuration is needed'), 'log-warn');
      wizard.index++;
      installNext();
      return;
    }
    logLine('✗ ' + item.Name + ' ' + t('could not be installed'), 'log-error');
    toast(item.Name + ' ' + t('setup FAILED'), 'error');
    if (wizard.index + 1 < wizard.selected.length) $('setup-decision').hidden = false; // Continue / Stop
    else setupFinished(); // it was the last item, so there is nothing to decide
  }

  function setupFinished() {
    wizard.active = false;
    closeStream();
    $('setup-progress').hidden = true;
    var root = $('setup-result-root');
    clear(root);
    var table = buildTable([t('Component'), t('Result')]);
    wizard.selected.forEach(function (item) {
      var tr = el('tr');
      tr.appendChild(el('td', null, item.Name));
      var cell = el('td'), state = wizard.results[item.Key];
      if (state === 'done') cell.appendChild(chip('✓ ' + t('Installed'), 'green'));
      else if (state === 'partial') cell.appendChild(chip('◐ ' + t('Partial (configuration needed)'), 'amber'));
      else if (state === 'failed') cell.appendChild(chip('✗ ' + t('Failed'), 'red'));
      else cell.appendChild(chip('— ' + t('Skipped'), 'neutral'));
      tr.appendChild(cell);
      table.body.appendChild(tr);
    });
    root.appendChild(table.table);
    showStep(4);
  }

  // The selection map follows the checkbox, so the search filter never loses it.
  $('setup-list').addEventListener('change', function (e) {
    var target = e.target;
    if (!target || !target.classList || !target.classList.contains('setup-check')) return;
    if (target.checked) wizard.selection[target.value] = true; else delete wizard.selection[target.value];
    updateSelection();
  });

  // Live search: filter by name AND summary, on the client.
  $('setup-search').addEventListener('input', function () {
    wizard.term = lower(this.value.trim());
    drawCatalog();
  });

  $('btn-setup-next').addEventListener('click', function () {
    var keys = selectedKeys();
    wizard.selected = wizard.catalog.filter(function (item) { return keys.indexOf(item.Key) !== -1; });
    if (!wizard.selected.length) return;
    var root = $('setup-summary-list'), total = 0, experimental = false;
    clear(root);
    wizard.selected.forEach(function (item) {
      var row = el('div', 'setup-summary-row');
      row.appendChild(el('span', null, item.Name));
      row.appendChild(el('span', 'dim mono', item.TimeToRun || ''));
      root.appendChild(row);
      total += upperMinutes(item.TimeToRun); // the same rule as step 1: the range's upper value
      if (item.Tier === 'experimental') experimental = true;
    });
    root.appendChild(el('div', 'setup-summary-row setup-total', t('Total estimated time') + ': ~' + total + ' min'));
    $('setup-experimental-warning').hidden = !experimental;
    showStep(2);
  });

  $('btn-setup-back').addEventListener('click', function () { showStep(1); });

  $('btn-setup-start').addEventListener('click', function () {
    closeStream();
    wizard.index = 0;
    wizard.results = {};
    wizard.active = true;
    wizard.autoScroll = true;
    clear($('setup-log'));
    $('setup-decision').hidden = true;
    buildOverallBar();   // one segment per selected item
    resetProgress();     // the ETA bar starts clean
    showStep(3);
    installNext();
  });

  $('btn-setup-continue').addEventListener('click', function () {
    $('setup-decision').hidden = true;
    wizard.index++;
    installNext();
  });

  $('btn-setup-stop').addEventListener('click', function () {
    $('setup-decision').hidden = true;
    setupFinished(); // whatever came after the failure stays "Skipped"
  });

  $('btn-setup-finish').addEventListener('click', function () {
    wizard.selection = {}; // the selection is cleared once the setup completed
    loadSetup();           // the catalog is refreshed (the Installed flags moved)
    loadOverview();        // the capability chips are fetched again
    openTab('overview');
  });

  // Auto-scroll stops when the operator scrolls up, and resumes at the bottom.
  $('setup-log').addEventListener('scroll', function () {
    var box = $('setup-log');
    wizard.autoScroll = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
  });

  // ---------- Start up and bind the events ----------
  async function startPanel() {
    var summary = await api('/api/local/summary'); // on a 401 api() drops to the sign-in view
    loaded = { overview: true };
    writeSummary(summary);
    drawDashboard();   // draw the dashboard at BOOT, rather than waiting for the 5 s timer
    showPanel();
    // The active tab is remembered: a saved value that is still a real tab wins,
    // otherwise Overview. Only WHICH tab is stored, never the wizard's inner step.
    var target = 'overview';
    var saved = readCookie(TAB_COOKIE);
    if (saved && loaders[saved]) target = saved;
    openTab(target);
  }

  $('login-form').addEventListener('submit', async function (e) {
    e.preventDefault(); // it works with Enter too (a real form submit)
    var button = $('btn-login');
    button.disabled = true;
    try {
      await api('/api/local/login', {
        body: { user: $('login-user').value.trim(), password: $('login-password').value }
      });
      await startPanel();
      toast(t('Signed in'), 'success');
    } catch (err) { showError(err); }
    button.disabled = false;
  });

  $('btn-logout').addEventListener('click', async function () {
    try { await api('/api/local/logout', { method: 'POST' }); }
    catch (err) { /* a sign-out failure is swallowed; the view still returns to sign in */ }
    showLogin();
    toast(t('The session was closed'), 'success');
  });

  var tabButtons = document.querySelectorAll('.tab');
  for (var i = 0; i < tabButtons.length; i++) {
    tabButtons[i].addEventListener('click', function (e) { openTab(e.currentTarget.getAttribute('data-tab')); });
  }

  // The rail section icons: a click opens that section's labelled panel. If the
  // content is NOT in that section, it moves to the section's first tab; if it
  // already is, the content stays and only the panel is synchronised.
  var railButtons = document.querySelectorAll('.rail-button');
  for (var r = 0; r < railButtons.length; r++) {
    railButtons[r].addEventListener('click', function (e) {
      var key = e.currentTarget.getAttribute('data-section');
      if (TAB_SECTION[activeTab] === key) { openSection(key); return; }
      var first = document.querySelector('.tab-group[data-group="' + key + '"] .tab');
      if (first) { openTab(first.getAttribute('data-tab')); } else { openSection(key); }
    });
  }

  // The language selects (top bar + sign in).
  var langSelects = document.querySelectorAll('.lang-select');
  for (var l = 0; l < langSelects.length; l++) {
    langSelects[l].addEventListener('change', function (e) { changeLang(e.target.value); });
  }
  applyText(); // apply the saved or browser language at start up

  $('site-add-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var input = $('site-domain'), button = $('btn-site-add');
    var domain = input.value.trim();
    if (!domain) return;
    button.disabled = true;
    try {
      await api('/api/local/sites', { body: { domain: domain } });
      toast(t('Site added') + ': ' + domain, 'success');
      input.value = '';
      loadSites();
    } catch (err) { showError(err); } // a 422 (the selftest seal and so on) is toasted as it came
    button.disabled = false;
  });

  $('btn-sites-refresh').addEventListener('click', loadSites);
  $('btn-events-refresh').addEventListener('click', loadEvents);
  $('btn-tasks-refresh').addEventListener('click', loadTasks);
  $('event-log').addEventListener('change', loadEvents);
  $('event-level').addEventListener('change', drawEvents);
  $('task-all').addEventListener('change', loadTasks);

  $('btn-db-refresh').addEventListener('click', loadDatabases);
  $('db-engine').addEventListener('change', loadDatabaseList);
  $('db-create-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var name = $('db-name').value.trim();
    if (!name) return;
    var button = $('btn-db-create');
    button.disabled = true;
    try {
      await api('/api/local/db-create', {
        body: { engine: $('db-engine').value, name: name, user: $('db-user').value.trim(), password: $('db-password').value }
      });
      toast(t('Database created') + ': ' + name, 'success');
      $('db-name').value = ''; $('db-user').value = ''; $('db-password').value = '';
      loadDatabaseList();
    } catch (err) { showError(err); }
    button.disabled = false;
  });

  $('btn-services-refresh').addEventListener('click', loadServices);
  // The resource boxes every 5 s: only while the tab is active, the document is
  // visible and the panel is open, so a background tab costs the host nothing.
  setInterval(function () {
    if (document.hidden || $('view-panel').hidden) return;
    if (activeTab === 'services' && loaded.services) loadResources();
    if (activeTab === 'overview' && loaded.overview) drawDashboard();
  }, 5000);

  // Start up: try the summary; on a 401 fall to the sign-in view.
  startPanel().catch(function (err) {
    if (err && err.unauthorized) return;
    showLogin();
    showError(err);
  });
})();
