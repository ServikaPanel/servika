# Yol haritası: ikincil DNS, çok sunuculu ajan modu, yüksek erişilebilirlik

Bu belge üç isteğin araştırma sonucunu ve uygulama akışını taşır. Her bölüm
şu düzendedir: bağlam, ölçülen zemin, tasarım kararları, adımlar, güvenlik
gereksinimleri, kapsam dışı, ödünleşmeler, doğrulama.

Belgedeki her "ölçüldü" ifadesi bu depoda ya da gerçek bir kapsayıcıda
çalıştırılmış bir komutun sonucudur. Ölçülmemiş hiçbir şey olgu olarak
yazılmadı.

---

## Ortak zemin: bugün panel ne durumda

| Gerçek | Nasıl ölçüldü |
|---|---|
| AlmaLinux 10 `bind` paketi **BIND 9.18.33 (ESV)** getiriyor | `docker run almalinux:10` içinde `named -v` |
| `tsig-keygen` kurulu geliyor | aynı kapsayıcı, `command -v tsig-keygen` |
| Catalog zone (RFC 9432, sürüm 2) dosyası `named-checkzone`'dan geçiyor | aynı kapsayıcı |
| `allow-transfer { key ... }`, `also-notify`, `notify explicit`, `catalog-zones` grameri kabul ediliyor | `named-checkconf` |
| Panelin ürettiği her zone **AXFR'yi kapatıyor** | `internal/dns/zone_writer.go::236`, `allow-transfer { none; }` sabit |
| Zone dosyası yazan 22 çağrı yerinin hepsi `dns.WriteZone`'dan geçiyor | `grep -rn "WriteZone("`, 22 sonuç |
| Zone silme tek noktadan geçiyor: `dns.DeleteZone` | 2 çağrı yeri |
| Panelde **hiçbir** çok sunucu kavramı yok: `servers`/`nodes` tablosu yok, ajan yok | `grep -rniE "CREATE TABLE (servers\|nodes\|hosts)" migrations/` boş |
| 66 `internal/` paketinin **39'u** yerel komut çalıştırıyor: test dışı 239 `exec.Command`, 134 `os.WriteFile` çağrısı | `grep -rn "exec.Command" --include="*.go" internal/ \| grep -v _test.go` |
| Uzak sunucuya konuşan tek mevcut mekanizma `internal/transfers/remote.go` (sertleştirilmiş SSH, tek yönlü çekme) | dosya okundu |
| Tek JWT kimliği var ve yalnız `servika_session` çerezinden okunuyor | `internal/middleware/auth.go` |
| Token'ı yolda taşıyan public uç deseni mevcut | `POST /api/v1/git-webhook/{secret}`, `POST /api/v1/internal/pma-redeem` |

Bu tablodaki iki satır bütün planı şekillendiriyor:

1. **`dns.WriteZone` tek kanca noktası.** İkincil DNS senkronizasyonu 22 yere
   değil, tek fonksiyona bağlanır.
2. **Panel süreci hostun kendisidir.** 261 doğrudan `exec.Command` çağrısı
   arkasına ajan koyulabilecek bir soyutlama yok. Çok sunuculu mod bir özellik
   değil, bir yürütme katmanı yazımıdır.

---

# 1. İkincil DNS senkronizasyonu

## 1.1 Bağlam

Panel `named` ile yetkili DNS sunuyor ve her zone'u `/var/named/<domain>.zone`
dosyasına yazıp `/etc/named/servika-zones.conf` içinden dahil ediyor. Sunucu
düşerse alan adlarının **tamamı** çözümlenemez hale gelir: web, mail, hepsi.
Yedek alınmış olması bunu değiştirmez, çünkü NS kayıtları tek adrese işaret
eder.

Bugün AXFR mümkün bile değil. `zone_writer.go::236`:

```go
statement := fmt.Sprintf(`zone "%s" { type master; file "%s/%s.zone"; allow-query { any; }; allow-transfer { none; };`, ...)
```

`also-notify` de yok, yani bir slave kurulsa bile değişiklikten haberi olmaz;
yalnız SOA refresh süresi dolunca kontrol eder.

## 1.2 Üç taşıma yolu, üç ayrı şekil

Araştırma sonucunda bunlar **aynı özelliğin varyantı değil**, üç ayrı mekanizma:

### A. Operatörün kendi slave sunucusu (AXFR + TSIG + catalog zone)

Panel primary kalır, ikinci sunucuda BIND/Knot/PowerDNS slave olur.

Kritik nokta **catalog zone**. Onsuz her yeni alan adı slave'de bir yapılandırma
değişikliği gerektirir ve ikincil DNS tam olarak burada işlemez hale gelir:
kimse 400 alan adı için `named.conf` düzenlemez. Catalog zone ile panel tek bir
zone dosyası daha yazar, slave üyeleri kendiliğinden ekler ve siler.

Ölçülen catalog zone biçimi (`named-checkzone` geçti):

```
$TTL 3600
@ IN SOA invalid. hostmaster.invalid. ( <serial> 3600 600 604800 3600 )
@ IN NS  invalid.
version IN TXT "2"
<sha1-of-domain>.zones IN PTR example.com.
```

Slave tarafı (ajan gerektirmez, tek seferlik operatör işi):

```
options {
  catalog-zones { zone "catalog.<panel-domain>" default-primaries { <panel-ip> key servika-xfr; }; };
};
zone "catalog.<panel-domain>" { type secondary; primaries { <panel-ip> key servika-xfr; }; file "catalog.db"; };
key "servika-xfr" { algorithm hmac-sha256; secret "..."; };
```

**Bu, ajan modu olmadan çalışan tek gerçek ikincil DNS yoludur** ve bu yüzden
ilk yapılacak iştir.

### B. Cloudflare secondary (AXFR + TSIG + CF API)

Mekanik olarak A ile aynı AXFR, üstüne Cloudflare API'sinde üç nesne kurulumu:
TSIG, peer server, `type: "secondary"` zone.

Cloudflare belgelerinden çıkan ve planı bağlayan noktalar:

- Zone'un secondary DNS için **hesap ekibi tarafından etkinleştirilmiş** olması
  gerekiyor ("if this option is not available, contact your account team").
  Yani bu, her müşterinin açabileceği bir seçenek değil; panel bunu bir
  ön koşul olarak göstermeli ve etkin değilse özelliği kapalı sunmalı.
- Cloudflare **primary'nin SOA REFRESH değerini kullanmıyor**; kendi "zone
  refresh" ayarını kullanıyor. Bu yüzden NOTIFY isteğe bağlı değil, gerekli.
- Cloudflare, ilk AXFR **tamamlanmadan** zone için yetkili yanıt vermeye
  başlıyor. Delegasyon ilk aktarım doğrulanmadan değiştirilirse çözümleyiciler
  boş/negatif yanıt önbelleğe alır (varsayılan minimum TTL 1800 sn).
  **Panel, doğrulanmamış bir hedefi "hazır" diye göstermemeli.**
- Panelin nftables tarafında Cloudflare'in transfer IP'lerine ve NOTIFY
  IP'lerine izin verilmesi gerekiyor.

### C. deSEC (AXFR yok, yalnız API push)

deSEC belgelerinde AXFR-in desteği **yok**. Tek yol REST push:

- Kimlik doğrulama: `Authorization: Token <secret>`
- Alan adı oluşturma: `POST /api/v1/domains/`
- Kayıt yazma: `PUT /api/v1/domains/{name}/rrsets/` (**atomik**: hepsi ya da
  hiçbiri), silme `records: []` ile
- Apex `subname: ""` (`@` değil), TTL tavanı 86400, taban alan adına bağlı

Ölçülen hız sınırları (bunlar tasarımı belirliyor):

| Kova | Sınır |
|---|---|
| `dns_api_expensive` (alan adı oluşturma) | 10/sn, 50/dk |
| `dns_api_per_domain_expensive` (RRset yazma) | **2/sn, 15/dk, 100/saat, 300/gün, alan adı başına** |

429 yanıtı `Retry-After` başlığı taşıyor.

Bu sınırlar iki şeyi zorunlu kılıyor: push **kuyruğa** girer (istek içinde
değil), ve toplu yeniden senkronizasyon oran sınırlarına saygı duyan bir
işçiyle yürür. 500 alan adının ilk kurulumu tek başına 50/dk kovası yüzünden
en az 10 dakikadır.

## 1.3 Tasarımı bağlayan kurallar

Bunların her biri, koddan görünmeyen bir deliği kapatır.

- **`allow-transfer` asla `any` olamaz ve asla yalnız IP ACL'i olamaz.**
  `{ key "servika-xfr"; }` biçiminde TSIG'e bağlanır. Bir zone transferi
  müşterinin bütün alt alan adlarını, iç servis adlarını ve mail altyapısını
  tek istekte dışarı verir. IP ACL'i kaynak adres sahteciliğine açık; TSIG
  değil.
- **`notify explicit` zorunlu.** Onsuz BIND, zone'un NS kayıtlarındaki
  hostlara NOTIFY gönderir. Bizim NS kayıtlarımız paylaşılan
  `ns1.<sağlayıcı>` çiftini gösteriyor, yani NOTIFY yanlış makinelere gider ve
  gerçek slave hiç haber almaz.
- **DNSSEC ile API push hedefi birlikte kullanılamaz.** Panelin zone'ları
  `dnssec-policy default; inline-signing yes;` ile imzalanıyor. AXFR bu
  **imzalı** zone'u taşır, slave anahtarsız doğru yanıt verir. Ama deSEC ve
  Cloudflare kendi anahtarlarıyla yeniden imzalar; registrar'daki DS kaydı
  bizim anahtarımızı gösterirken yanıt onların anahtarıyla imzalı olur ve
  doğrulayan her çözümleyici **SERVFAIL** döner. Alan adı erişilemez hale
  gelir. Bu yüzden bir zone için API push hedefi seçmek, o zone'da DNSSEC'i
  kapatmayı gerektirir ve panel bunu YAZMA yolunda reddetmelidir.
- **API push hedefine apex NS, SOA, DNSKEY, RRSIG, NSEC/NSEC3 gönderilmez.**
  Hedef bunları kendisi yönetir; göndermek ya reddedilir ya da çelişkili
  delegasyon üretir.
- **Push, isteğin içinde yapılmaz.** 22 çağrı yeri, sağlayıcı kesintisi ve hız
  sınırları var. Müşterinin bir A kaydı düzenlemesi, Cloudflare yavaş diye
  başarısız olamaz. Kayıt önce yerel zone'a yazılır, sonra kuyruğa alınır.
- **Bayat bir ikincil, ikincil olmamasından kötüdür**, çünkü eski veriyi
  yetkili olarak sunar. Her hedef için zone başına son başarılı senkronizasyon
  zamanı ve son hata saklanır; senkronize olmayan zone ekranda ayrı gösterilir.
- **`internal/netguard` bu yolda uygulanmaz ama gerekçesi yazılır.** Hedef
  adresi operatör yazar, müşteri değil. Yine de sağlayıcı API'sine giden HTTP
  istemcisi kendi zaman aşımını taşır ve panel bağlamını kullanmaz.
- **TSIG sırrı ve sağlayıcı token'ı `internal/secret` ile mühürlenir**, AAD
  olarak hedef satırının kimliği kullanılır. `internal/geoip`'in MaxMind
  anahtarını sakladığı desen birebir uygundur.

## 1.4 Adımlar

Her adım kendi commit'ini alır.

### 1.A. Şema: senkronizasyon hedefleri ve durum

`migrations/00XX_dns_secondary.sql` (numara yazım anında dizinden doğrulanır).

```sql
CREATE TABLE dns_secondaries (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name          VARCHAR(64)  NOT NULL,          -- operatörün verdiği ad
  kind          VARCHAR(16)  NOT NULL,          -- axfr | cloudflare | desec
  enabled       TINYINT(1)   NOT NULL DEFAULT 0,
  -- axfr
  peer_ip       VARCHAR(45)  NOT NULL DEFAULT '',
  tsig_name     VARCHAR(255) NOT NULL DEFAULT '',
  tsig_alg      VARCHAR(32)  NOT NULL DEFAULT 'hmac-sha256',
  tsig_secret   TEXT         NULL,              -- internal/secret ile mühürlü
  -- api
  api_token     TEXT         NULL,              -- internal/secret ile mühürlü
  api_account   VARCHAR(64)  NOT NULL DEFAULT '',
  created_at    TIMESTAMP    NULL DEFAULT current_timestamp(),
  updated_at    TIMESTAMP    NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (id),
  UNIQUE KEY uk_dns_secondary_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE dns_sync_state (
  secondary_id  BIGINT UNSIGNED NOT NULL,
  domain_id     BIGINT UNSIGNED NOT NULL,
  status        VARCHAR(16)  NOT NULL DEFAULT 'pending',  -- pending|ok|failed
  serial        INT UNSIGNED NOT NULL DEFAULT 0,
  attempts      INT          NOT NULL DEFAULT 0,
  last_error    VARCHAR(255) NOT NULL DEFAULT '',
  next_attempt  DATETIME     NULL DEFAULT NULL,
  synced_at     DATETIME     NULL DEFAULT NULL,
  PRIMARY KEY (secondary_id, domain_id),
  CONSTRAINT fk_sync_secondary FOREIGN KEY (secondary_id) REFERENCES dns_secondaries(id) ON DELETE CASCADE,
  CONSTRAINT fk_sync_domain    FOREIGN KEY (domain_id)    REFERENCES domains(id)         ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

Birleşik birincil anahtarın iki sütunu da NOT NULL, yani `ON DUPLICATE KEY
UPDATE` gerçekten birleşir.

### 1.B. `internal/dnssecondary`: AXFR yüzeyini aç

- `zoneIncludeStatement` artık etkin AXFR hedeflerinden `allow-transfer`,
  `also-notify` ve `notify explicit` satırlarını üretir. Hedef yoksa çıktı
  bugünküyle **bayt bayt aynı** kalır.
- TSIG anahtar dosyası `/etc/named/servika-tsig.conf` olarak 0640
  `root:named` yazılır ve `named.conf`'a dahil edilir. Sır zone include
  dosyasına girmez, çünkü o dosya 0644.
- `named-checkconf` yazma yolunda çalışır; başarısızsa dosya geri alınır.
  Mevcut `updateZoneIncludes` bu deseni zaten taşıyor.
- nftables tarafında TCP 53 hedef IP'lerine açılır. Kapalı bir 53/TCP, AXFR'yi
  sessizce başarısız kılar; UDP 53 açık olduğu için sıradan sorgular çalışmaya
  devam eder ve arıza görünmez.

### 1.C. Catalog zone

- Panel `catalog.<panel-domain>` için bir zone dosyası üretir ve her
  `WriteZone`/`DeleteZone` sonrası üyeleri yeniden yazar.
- Üye etiketi alan adının SHA-1'i (RFC 9432 örneği bu), böylece etiket kararlı
  ve çakışmasız olur.
- Catalog zone da `allow-transfer { key ...; }` ile korunur: içeriği barındırılan
  bütün alan adlarının listesidir.
- Serial, mevcut `nextSerial` mantığıyla ilerler.

### 1.D. Senkronizasyon kuyruğu ve işçi

- `dns.WriteZone` başarıyla bittikten **sonra** etkin her hedef için
  `dns_sync_state` satırını `pending` yapar. Bu tek kanca noktası; 22 çağrı
  yerinin hiçbiri değişmez.
- `DeleteZone` aynı şekilde bir `delete` niyeti kuyruklar.
- İşçi `internal/apps`/`internal/backups` desenindeki gibi arka planda döner,
  kendi `context.WithTimeout(context.Background(), ...)` bütçesini taşır ve
  üstel geri çekilme uygular. 429 yanıtındaki `Retry-After` başlığına uyar.
- AXFR hedefi için "senkronizasyon" bir NOTIFY göndermektir; işçi ayrıca
  slave'in serial'ini sorup karşılaştırarak `ok` yazar. NOTIFY gönderdim demek
  senkronize oldu demek değildir.
- Başarısız bir zone, ekranda hedef başına ayrı listelenir.

### 1.E. Sağlayıcı istemcileri

`internal/dnssecondary/cloudflare.go` ve `desec.go`. Her ikisi de:

- kendi HTTP istemcisini kurar, panelin bağlamını kullanmaz,
- token'ı `Authorization` başlığında taşır, asla URL'de değil,
- 429'u kalıcı hata saymaz, `Retry-After` kadar bekler,
- apex NS/SOA/DNSSEC kayıtlarını gönderilecek kümeden çıkarır,
- yanıt gövdesini olduğu gibi loglamaz (token yankılanabilir).

### 1.F. Yazma yolu kapıları

- Bir zone'a API push hedefi atanırken DNSSEC etkinse **reddedilir**
  (`dns_secondary_dnssec_conflict`). Tersi de: DNSSEC açılırken API push hedefi
  varsa reddedilir.
- Cloudflare hedefi doğrulanmadan "hazır" gösterilmez; panel ilk aktarımı
  doğrular (hedefin nameserver'ına doğrudan sorgu) ve ancak sonra delegasyon
  talimatını gösterir.
- Hedef silinirken uzak taraftaki zone'lar **kaldırılmaz**, yalnız yerel satır
  gider ve ekran bunu söyler. Uzak zone'u sessizce silmek, hâlâ delege edilmiş
  bir alan adını yok eder.

### 1.G. Arayüz ve 12 dil

Sunucu genelinde `Tools` altında bir "Secondary DNS" ekranı: hedef listesi,
hedef başına senkronize/bekleyen/başarısız sayısı, başarısız zone listesi,
elle yeniden senkronizasyon düğmesi, TSIG anahtarını gösteren kurulum kutusu
(slave'e yapıştırılacak `named.conf` parçası dahil).

## 1.5 Güvenlik gereksinimleri (her biri iki yönde kanıtlanacak)

1. Hiçbir hedef yokken üretilen `servika-zones.conf` bugünküyle bayt bayt aynı.
2. `allow-transfer` hiçbir yolda `any` üretemez.
3. TSIG sırrı 0644 zone include dosyasına düşmez.
4. `notify explicit` her zaman `also-notify` ile birlikte yazılır.
5. DNSSEC açık bir zone'a API push hedefi atanamaz, ve tersi.
6. Push kuyruğu bir sağlayıcı kesintisinde müşterinin kayıt düzenlemesini
   başarısız etmez.
7. 429 yanıtı kalıcı hata sayılmaz.
8. Senkronize olmayan bir zone "senkron" görünmez.

## 1.6 Kapsam dışı

- **Panelin secondary OLMASI** (dışarıdaki bir primary'den AXFR çekmek). Ayrı
  bir eksen ve istenmedi.
- **Dinamik DNS güncellemesi (RFC 2136).** Zone dosyası modeli ile çakışır.
- **Cloudflare proxy (turuncu bulut) yönetimi.** Secondary override ayrı bir
  ürün yüzeyi.
- **Registrar'da NS değişikliği otomasyonu.** Panel talimatı gösterir, değişikliği
  operatör yapar.

## 1.7 Ödünleşmeler

1. Catalog zone slave'in BIND 9.11+ / Knot 3+ / PowerDNS 4.7+ olmasını gerektirir.
   Daha eskisi için zone başına elle yapılandırma gerekir; panel bu durumda
   üretilecek yapılandırmayı gösterir ama uygulayamaz.
2. API push modeli zone dosyasının birebir kopyası değil, kayıt kümesinin
   izdüşümüdür. Sağlayıcının desteklemediği bir kayıt tipi sessizce düşer;
   bu yüzden push sonucu kayıt sayısıyla doğrulanır.
3. Cloudflare secondary hesap ekibi onayına bağlı, yani özellik her müşteride
   çalışmayabilir.

---

# 2. Çok sunuculu ajan modu

## 2.1 Bağlam ve dürüst değerlendirme

İstenen: ikinci sunucuyu hafif bir ajanla panele bağlayıp tek arayüzden
yönetmek; web bir sunucuda, DB veya mail başka sunucuda.

Ölçülen gerçek: **panel süreci hostun kendisidir.** 66 paketin 39'u yerel
komut çalıştırıyor, test dışı 239 `exec.Command` ve 134 `os.WriteFile` çağrısı
var ve bunların arkasında "bunu şu makinede çalıştır" diyebilecek hiçbir soyutlama
yok. `internal/provisioner` doğrudan `/etc/nginx`, `/etc/php-fpm.d`, `/home`
altına yazıyor; `internal/credentials` yerel MariaDB soketine bağlanıyor;
`internal/mail` yerel Postfix/Dovecot dosyalarını üretiyor.

Bu yüzden "web sunucusu ayrı makinede" hedefi bir özellik değil, yürütme
katmanının yeniden yazımıdır. Bunu tek adımda yapmak, panelin bugün çalışan
her yolunu aynı anda riske atar.

Ama **erken değer üreten kademeli bir yol var** ve ilk kademesi kullanıcının
kendi söylediği gibi ikincil DNS ile birleşiyor.

## 2.2 Kademeler

### Kademe 0. Düğüm kaydı ve kontrol kanalı (temel)

Hiçbir rol taşınmaz. Yalnız panel "başka bir makine var" diyebilir hale gelir.

- `servers` tablosu: id, ad, rol kümesi, adres, ajan sürümü, son görülme,
  mühürlü kayıt token'ı.
- Ajan **dışarı doğru bağlanır** (panel API'sine), panel ajana bağlanmaz.
  Gerekçe: düğüm NAT arkasında olabilir; ve her düğümde açık bir port,
  panelde açık tek bir porttan daha geniş bir saldırı yüzeyidir.
- Kimlik: düğüm başına token, `internal/secret` ile mühürlü, karşılaştırma
  sabit zamanlı (`httpx.ProxySecret` deseni).
- Uç: `POST /api/v1/agent/heartbeat`, `RequireAuth` **değil** kendi ajan
  kimlik doğrulaması, kendi hız sınırı (`middleware.RateLimit` deseni).
- Panel düğüm durumunu **veri olarak** raporlar (hangi düğüm düştü), istek
  üzerinde hata olarak değil.

### Kademe 1. DNS düğümü (ajan gerektirmez)

Bölüm 1.2/A. Catalog zone + AXFR ile ikinci sunucu **hiçbir ajan olmadan**
ikincil nameserver olur. En ucuz gerçek düğüm budur ve tek başına single point
of failure'ı kaldırır.

Kademe 0 ile birleşince panel bu düğümü listede gösterir ve senkronizasyon
durumunu oradan okur.

### Kademe 2. Salt okunur uzak düğüm

Ajan yalnız **rapor eder**: yük, disk, servis durumu, log kuyruğu. Hiçbir şey
yazmaz.

Bu kademe ajan protokolünü, sürümlemeyi ve arayüzü gerçek trafikle sınar; bir
hata en kötü ihtimalle yanlış bir grafik çizer.

### Kademe 3. İlk taşınan rol: MAIL ya da DATABASE

Web **değil**. Gerekçe ölçülebilir: web rolü `internal/provisioner` üzerinden
vhost, PHP-FPM havuzu, kota, safeio, yedekleme ve SSL'e bağlı; mail ve DB
yüzeyleri daha dar ve daha net sınırlıdır.

- **Database düğümü** en kolayı: `internal/dbremote` zaten uzak MariaDB
  hesabının nasıl açılacağını, host bileşeninin nasıl doğrulanacağını ve
  firewall'un nasıl türetileceğini çözdü. Eksik olan, panelin *kendi* DSN'ini
  ve müşteri veritabanı işlemlerini uzak sunucuya yöneltmesi.
- **Mail düğümü** daha çok dosya üretir ama `internal/mail` tek pakette
  toplu.

### Kademe 4. Web düğümü

Yürütme katmanının yazımı. Bu belgede plan olarak **verilmiyor**; Kademe 3
bitmeden tasarımı yapılamaz, çünkü asıl bilgi oradan gelecek.

## 2.3 Ajan protokolünü bağlayan kurallar

- **Her komut ADLANDIRILMIŞ bir işlemdir, tipli argümanlarla.** Ajan asla
  kabuk dizesi almaz. Güvenlik modelinin tamamı budur: panel ele geçirilse
  bile ajan yalnız bildiği işlemleri yapar.
- **Ajan bilmediği işlemi reddeder**, kabuğa geçirmez.
- **İşlem kümesi sürümlüdür.** Panel yeni, ajan eski olduğunda panel bunu
  bilir ve o rolü kullanılamaz gösterir; sessizce başarısız olmaz.
- **Ajan kendini güncellemez.** Güncelleme operatörün işidir; kendini
  güncelleyen bir ajan, paneli ele geçiren birinin bütün filoyu ele
  geçirmesidir.
- **Düğüm token'ı döndürülebilir olmalıdır** ve döndürme paneldeki tek işlemle
  yapılabilmelidir.
- **Ajan logu kiracı ev dizinine yazmaz** (mevcut `append:` kuralı aynen
  geçerli).

## 2.4 Kapsam dışı (bu belgede)

- Web rolünün taşınması.
- Düğümler arası paylaşımlı depolama.
- Otomatik rol devri.

## 2.5 Ödünleşmeler

1. Kademe 0 ve 2 tek başına kullanıcıya az şey verir; değerleri Kademe 3'ün
   riskini düşürmesindedir.
2. Ajan dışarı bağlandığı için panelin ajana **anında** komut göndermesi uzun
   yoklama ya da WebSocket gerektirir; ilk sürümde 5 saniyelik yoklama yeterli
   ve çok daha basittir.
3. Çok sunuculu kurulumda yedekleme ve geri yükleme anlamını değiştirir:
   `internal/backups` bugün tek hostu varsayıyor.

---

# 3. Yüksek erişilebilirlik

## 3.1 "HA" üç ayrı şeydir

Bunları ayırmadan plan yapılamaz.

| Ne | Kapsam | Ulaşılabilirlik |
|---|---|---|
| **a. DNS yedekliliği** | sunucu düşse de alan adları çözümlenir | Bölüm 1 ile **çözülür**, ucuz ve gerçek |
| **b. Kontrol düzlemi yedekliliği** | panel düşse de yönetim geri gelir | aktif/pasif olarak ulaşılabilir |
| **c. Barındırma yedekliliği** | sunucu düşse de siteler ayakta kalır | ayrı bir ürün; paylaşımlı depolama + yük dengeleyici ister |

Kullanıcının "yüksek erişilebilirlik sistemi" isteği çoğunlukla (c)'yi çağrıştırır
ama (a) ve (b) yapılmadan (c) anlamsızdır: siteler ayakta olsa bile DNS düşmüşse
kimse ulaşamaz.

## 3.2 Ölçülen durum envanteri

Panel durumu **hem MariaDB'de hem dosya sisteminde** tutuyor. Ölçülen yollar:

| Yol | İçerik |
|---|---|
| `/etc/servika` | çalışma ortamı dosyası, proxy sırrı |
| `/etc/servika/apps` | uygulama EnvironmentFile'ları (0600, sır taşır) |
| `/etc/named`, `/var/named` | zone dosyaları, DNSSEC anahtarları |
| `/etc/nginx/conf.d`, `/etc/nginx/modsec` | vhost'lar, WAF |
| `/etc/php-fpm.d`, `/etc/opt/remi/php*` | havuzlar, PHP yapılandırması |
| `/etc/pki/servika`, `/etc/letsencrypt` | sertifikalar ve anahtarlar |
| `/etc/systemd/system` | uygulama ve worker unit'leri, kiracı slice'ları |
| `/var/lib/servika/{geoip,quarantine,tmp}` | GeoIP verisi, karantina deposu |
| `/var/backups/servika` | yedekler |
| `/var/log/servika-{apps,laravel}` | uzun süren süreç logları |
| `/home/c_*` | kiracı verisi |
| `/opt/servika` | ikili, frontend, migration'lar, eklentiler |

Bu envanterin kendisi bir teslimattır: **ölçülmemiş bir durum envanteriyle
otomatik devir yapmak, bölünmüş beyin üretir.**

## 3.3 Sıralı yol

### 3.A. DNS yedekliliği

Bölüm 1. Tek başına en büyük kazanç.

### 3.B. Geri yüklemenin gerçekten çalıştığını kanıtlamak

`internal/backups` granüler geri yüklemeyi zaten yapıyor. Eksik olan,
**denenmemiş yedeğin yedek olmadığı**: zamanlanmış bir "restore drill" işi tek
bir alan adını geçici bir hedefe geri yükler ve sonucu raporlar.

Bu HA değildir ama dürüst tabandır ve haftalar sürmez.

### 3.C. Aktif/pasif panel yedeği (elle devir)

- MariaDB replikasyonu (panel şeması) ikinci sunucuya.
- 3.2'deki dosya envanterinin zamanlanmış senkronizasyonu.
- Belgelenmiş bir **elle** yükseltme yordamı: ikincil panelde migration'ları
  çalıştır, `provisioner.Init` heal zincirini çalıştır, kayan IP'yi taşı.
- **Otomatik devir bilerek yapılmaz.** İki panel aynı host kümesine nginx
  yapılandırması yazarsa sonuç kesintiden kötüdür. Otomatik devir, ancak
  düğüm çitleme (fencing) varken düşünülebilir ve bu, Kademe 3 sonrası bir
  konudur.

### 3.D. Rol bazlı yedeklilik

Bölüm 2, Kademe 3'ten sonra: ikinci mail düğümü, veritabanı okuma kopyası.

### 3.E. Barındırma yedekliliği

Kapsam dışı. Gerekleri burada yalnız kaydediliyor: paylaşımlı ya da
replikasyonlu depolama, oturum durumunun paylaşılması, önde yük dengeleyici,
sertifikaların her düğümde bulunması. Panelin bugünkü kiracı modeli (ev
dizini + yerel FPM havuzu + yerel kota) bunların hiçbirini varsaymıyor.

## 3.4 Kuralı belirleyen tek cümle

**Durum envanteri ölçülüp test edilmeden otomatik devir yazılmaz.** Host
yapılandırması yazan bir kontrol düzleminde bölünmüş beyin, kesintiden daha
pahalıdır ve geri alınması zordur.

---

# 4. Önerilen sıra

| Sıra | İş | Neden burada |
|---|---|---|
| 1 | 1.A-1.C: AXFR + TSIG + catalog zone | Tek başına single point of failure'ı kaldırır, ajan gerektirmez, mevcut kanca noktası tek |
| 2 | 1.D-1.G: kuyruk, sağlayıcı istemcileri, ekran | Cloudflare/deSEC seçeneğini açar |
| 3 | 3.B: geri yükleme tatbikatı | Ucuz, dürüst taban |
| 4 | 2 Kademe 0: düğüm kaydı ve kontrol kanalı | Ajan protokolünü riski düşük bir yerde sınar |
| 5 | 2 Kademe 2: salt okunur düğüm | Protokolü gerçek trafikle sınar |
| 6 | 3.C: aktif/pasif panel yedeği | Envanter artık ölçülü |
| 7 | 2 Kademe 3: ilk taşınan rol (DB ya da mail) | En büyük iş, en çok hazırlık ister |

1 ve 2 birlikte tek bir gerçek özellik; 4-5-7 birlikte ikinci bir gerçek
özellik. 3 ve 6 arada duran, ucuz ve bağımsız işlerdir.

---

# 5. Ortak doğrulama kapıları

Her adım için mevcut kapılar geçerlidir:

| Kapı | Komut |
|---|---|
| gofmt | `gofmt -l .` |
| Go vet amd64 / arm64 | `GOOS=linux GOARCH=<arch> go vet ./...` |
| Go lint | `GOOS=linux golangci-lint run ./...` |
| Go güvenlik | `gosec ./...` |
| Go testleri | `go clean -testcache && go test ./...` |
| Migration zinciri | temiz MariaDB 10.11 kabında `migrations/*.sql` sırayla |
| TypeScript / ESLint / build | `cd frontend && npx tsc --noEmit && npm run lint && npm run build` |
| Çeviri eşliği | `node scripts/i18n-verify.mjs` |

Bu işe özgü ek kapılar:

| Kapı | Komut |
|---|---|
| named yapılandırması | AlmaLinux 10 kabında `named-checkconf` ve `named-checkzone` |
| Catalog zone biçimi | aynı kapta `named-checkzone catalog.<domain> <dosya>` |
| Gerçek AXFR | iki kaplı kurulum: primary panel + slave BIND, `dig AXFR` ile TSIG'siz **reddedildiği**, TSIG'li **kabul edildiği** |
| Sağlayıcı istemcileri | kaydedilmiş yanıtlarla, 429 + `Retry-After` yolu dahil |

Gerçek uçtan uca doğrulama bir AlmaLinux 10 hostu ve ikinci bir makine
gerektirir; bu belge o adımları tanımlar, burada çalıştıramaz.
