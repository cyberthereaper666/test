# SSTI (Server-Side Template Injection) — Kapsamlı Araştırma Dokümanı

> Kapsam: Yalnızca SSTI. EL Injection, XSS, SQLi, Command Injection ve diğer
> injection sınıfları bilinçli olarak dışarıda bırakılmıştır. Bu doküman bir
> bug bounty AI agent'ının SSTI tespiti için kullanacağı parçalanmış skill
> dosyalarına (core / detection / fingerprinting / context / engines /
> workflow / reference) kaynaklık edecek şekilde yazılmıştır.

---

## BÖLÜM A — Soru Listesinin Eleştirisi ve Eksik Konular

İstenen 18 maddelik eleştiri buradan başlıyor. Her madde altında hem
"neden eksik" hem de "ne eklenmeli" var. Yeni eklenen sorular Bölüm A'nın
sonunda **28–34. bölümler** olarak numaralandırılmıştır ve Bölüm B'de
cevaplanmıştır.

> **Operasyonel probe notu:** Bu bölümde (Bölüm A) yer yer örnek/
> tarihsel referans olarak `{{7*7}}` gibi ifadeler geçer. Bunlar
> yalnızca **açıklayıcı örneklerdir** — "böyle bir payload çifti
> düşünülebilir" anlamında kullanılmıştır. **Operasyonel SSTI probe
> listesi yalnızca Bölüm B'dedir (Bölüm 6-7, 8, 15, 19, 20)** ve
> oradaki birincil arithmetic identity probe `{{6666*6666}} →
> 44435556`'dır. Agent/skill implementasyonu Bölüm A'daki örnekleri
> değil, yalnızca Bölüm B'deki operasyonel probe tanımlarını referans
> almalıdır; `7*7` hiçbir agent tool-call'ında birincil identity probe
> olarak kullanılmamalıdır.

### 1. Eksik SSTI konusu var mı?
Evet, üç önemli konu eksik:
- **Polyglot / cross-engine payloadlar** (`${{<%[%'"}}%\`.) tek bir probe ile
  birden fazla engine ailesini aynı anda taramak için kritik; agent'ın
  request bütçesini düşürür.
- **"Type confusion" / object context SSTI** — bazı engine'lerde (Jinja2,
  Freemarker, Velocity) input doğrudan string değil, zaten bir obje/attribute
  olarak işlenir (örn. sort/filter parametresi bir attribute adı olarak
  kullanılıyor). Bu, klasik "kullanıcı girdisi template string'in içine
  gömülüyor" modelinden farklı bir SSTI yoludur ve ayrı ele alınmalı.
- **Template injection via configuration / YAML / DSL dosyaları** (örn. CI/CD
  pipeline şablonları, Helm chart'ları, Ansible Jinja2 şablonları) — klasik
  HTTP tabanlı SSTI'nin dışında, bug bounty kapsamında nadiren de olsa
  karşılaşılan bir varyant.

### 2. Eksik attack surface var mı?
Evet:
- **SSR (Server-Side Rendering) frameworkleri** (Next.js get-server-side-props,
  Nuxt, SvelteKit) içinde kullanıcı verisinin template/markup üretimine
  karıştığı noktalar.
- **Chatbot / AI prompt-to-template pipeline'ları** — kullanıcı mesajının bir
  template motoruna (örn. Jinja2 tabanlı prompt template sistemleri) enjekte
  edildiği yeni nesil uygulamalar.
- **Webhook payload render'ları** (Slack/Discord/Teams entegrasyonlarında
  gelen mesaj içeriğinin bir template ile biçimlendirilip başka bir yere
  render edildiği senaryolar).
- **Feature flag / A-B testing içerik motorları** (kullanıcıya özel içerik
  render eden sistemler, örn. Optimizely benzeri araçlar).

### 3. Eksik template engine var mı?
Evet, listeye şunlar eklenmeli:
- **Pug/Jade** (Node.js) — SSTI'ye ek olarak arbitrary JS execution riski.
- **Nunjucks** (Node.js, Mozilla) — Jinja2 sözdizimine çok benzer, ayrı ele
  alınmalı.
- **Handlebars / Mustache** — "logic-less" oldukları için SSTI etkisi sınırlı
  ama helper injection riski var; ayrı bir davranış modeli gerektirir.
- **Smarty** (PHP) — Twig kadar yaygın olmasa da hâlâ canlı projelerde var.
- **Thymeleaf** (Java/Spring) — Freemarker/Velocity dışında üçüncü büyük Java
  engine'i, SpEL (Spring Expression Language) ile etkileşimi nedeniyle
  özellikle önemli.
- **JinjaJS / EJS / doT / Squirrelly** (Node.js ekosistemindeki daha az
  bilinen ama karşılaşılabilecek engine'ler).
- **Liquid** (Shopify, Jekyll) — sandbox modeli farklı, ayrı incelenmeli.
- **Razor** (.NET) listede vardı ama **DotLiquid** ve **Scriban** (.NET
  ekosisteminde Liquid türevleri) eksik.
- **Pebble** (Java) — Twig benzeri ama farklı sandbox.
- **text/template vs html/template (Go)** ayrımı ayrıca vurgulanmalı; Go'nun
  html/template'i context-aware auto-escaping yaptığı için SSTI davranışı
  text/template'ten temelden farklıdır.

### 4. Eksik CMS/framework var mı?
- **Shopify (Liquid)**, **Jekyll/Hugo (statik site üreticiler, build-time
  SSTI)**, **Grav CMS (Twig)**, **October CMS (Twig)**, **Magento (Smarty +
  legacy)**, **Confluence/Jira (Velocity — geçmişte gerçek CVE'ler var)**,
  **Adobe Experience Manager (Sling/JSP)**, **Wagtail (Django/Jinja2)**,
  **Strapi/headless CMS'lerin custom template alanları** eksik.
- Bu framework/CMS eşlemesi tablo olarak Bölüm B'de derlenmiştir.

### 5. Eksik detection yöntemi var mı?
- **Differential/comparative probing**: aynı anlama gelen ama farklı
  engine'lerde farklı sonuç üreten payload çiftlerinin (örn. `{{7*7}}` vs
  `${7*7}` vs `#{7*7}`) sistematik matris halinde denenmesi eksik detaylı
  anlatılmamış.
- **Canary/marker tabanlı detection**: Her probe'a biricik bir marker
  (`SSTI_<random>`) eklenerek response'ta hem hesaplanan değerin hem de
  marker'ın birlikte aranması — reflection ile evaluation'ı ayırmanın en
  güvenilir yollarından biri; ayrı bir madde olarak eklenmeli.
- **Response fragment isolation**: büyük HTML sayfalarında payload'ın nereye
  düştüğünü bulmak için DOM/regex tabanlı izolasyon stratejisi eksik.

### 6. Eksik fingerprinting yöntemi var mı?
- **Timing-based fingerprinting** (bazı engine'lerin çok maliyetli
  expression'ları farklı sürede işlemesi) sadece blind bölümünde geçiyor,
  fingerprinting bölümünde de tekrar bahsedilmeli.
- **HTTP response header fingerprinting**'e ek olarak **cookie/session
  isimlendirmesi** (örn. `JSESSIONID` → Java, `laravel_session` → Blade)
  teknoloji/engine tahmininde kullanılabilecek bir sinyal olarak eksik.

### 7. Eksik context türü var mı?
- **JavaScript context içinde template** (bir `<script>` bloğunun template
  engine tarafından işlendiği ve ardından tarayıcıda çalıştığı karma durum).
- **CSS context** (bazı theme/CSS-in-template sistemlerinde nadir ama
  mevcut).
- **URL/href attribute context** — attribute context'in özel bir alt kümesi
  olarak ayrı ele alınmalı çünkü encoding kuralları farklıdır.

### 8. Eksik encoding/transformation yöntemi var mı?
- **Template-engine-specific escaping filtreleri** (Jinja2'nin `|safe`,
  `|escape`; Twig'in `|raw`; Freemarker'ın `?html`) — bunlar hem bir engşn
  fingerprint sinyali hem de filter/WAF bypass açısından ayrı ele alınmalı.
- **Multipart/charset dönüşümleri** (uygulamanın `charset` header'ına göre
  payload'ı farklı byte dizisine çevirmesi) eksik.

### 9. Eksik WAF/filter konusu var mı?
- **Cloud WAF imza davranışları** (Cloudflare, AWS WAF, Akamai gibi
  ürünlerin SSTI imzalarının genelde `{{`, `${`, `<%` gibi delimiter'lara
  odaklandığı, bunun bypass için parçalama/concat teknikleriyle nasıl
  aşılabileceği) genel olarak var ama somut teknik eksik: **string
  concatenation bypass**, **attribute/filter chaining ile delimiter
  gizleme**, **whitespace/comment injection ile imza kırma**.

### 10. Eksik false-positive/false-negative konusu var mı?
- **Client-side template engine'lerin (AngularJS, Vue) yanlışlıkla SSTI
  sanılması** — CSTI (Client-Side Template Injection) ile SSTI'nin
  ayrıştırılması ayrı bir alt başlık olarak eksik, çünkü çoğu ajan
  yanlışlıkla `{{7*7}}` browser'da render olduğunda bunu SSTI sanabilir.
- **Uygulamanın kendi "template preview" özelliğinin meşru olarak
  matematiksel işlem yapması** (örn. bir hesap makinesi/formül alanı) —
  gerçek SSTI ile karıştırılmaması gereken bir FP kaynağı.

### 11. Eksik blind/stored/indirect SSTI konusu var mı?
- **Multi-step/chained indirect SSTI**: payload'ın 2-3 farklı sistem
  arasından geçerek (örn. destek talebi → e-posta şablonu → PDF export)
  render edildiği senaryolar için "chain mapping" metodolojisi eksik.
- **Second-order OOB confirmation**: DNS/HTTP callback (Burp Collaborator
  benzeri) kullanarak blind + stored SSTI'nin birlikte doğrulanması ayrı
  ele alınmalı.

### 12. Eksik confirmation yöntemi var mı?
- **Differential confirmation**: aynı expression'ın "doğru" ve "kasıtlı
  yanlış" (örn. `{{7*7}}` vs `{{7*'7'}}`) varyantlarının karşılaştırılması,
  yalnızca reflection değil gerçek evaluation'ı kanıtlamak için eklenmeli.
- **Side-effect-free confirmation önceliği**: RCE denemeden önce sadece
  bilgi sızdıran (`{{config}}`, `{{self}}`, environment değişkenleri)
  payload'larla confirmation yapılması ayrı vurgulanmalı (bug bounty
  güvenliği açısından kritik).

### 13. Eksik AI agent workflow/decision-making konusu var mı?
- **Confidence scoring modeli**: her aşamadan çıkan sonucun 0-100 arası bir
  güven skoruna dönüştürülmesi ve eşik değerlere göre bir sonraki aşamaya
  geçiş/durdurma kararı verilmesi eksik — bu, "ne zaman dur/devam et"
  sorularını somutlaştırır.
- **State/memory yönetimi**: agent'ın hangi endpoint/parametre
  kombinasyonlarını zaten test ettiğini takip etmesi (duplicate request
  önleme) ayrı bir teknik madde olarak eklenmeli.

### 14. Gereksiz veya tekrar eden sorular var mı?
Evet, aşağıdaki gruplar birbirini fazlasıyla tekrar ediyor ve Bölüm B'de
tek başlık altında birleştirilmiştir:
- 15–34 arası "her dil için template engine nedir" soruları → tek bir
  "Dil → Engine Haritası" tablosunda birleştirildi.
- 118–136 (fingerprinting) ile 287 (engine-specific research) arasında
  ciddi çakışma var → fingerprinting metodolojisi genel bölümde, engine'e
  özgü sinyaller ise engine profili tablosunda tutuldu.
- 151–169 (CMS/framework mapping) ile 3. bölümdeki dil bazlı mapping
  büyük ölçüde aynı bilgiyi farklı açıdan soruyor → tek bir kapsamlı
  "Teknoloji → Engine" tablosunda birleştirildi.

### 15–16. Hangi sorular birleştirilmeli / ayrı tutulmalı?
- Birleştirilmesi gerekenler: yukarıda 14. maddede listelendi.
- Ayrı tutulması gerekenler: **Generic detection (Bölüm 6)** ile
  **Engine-specific detection (Bölüm 8/20)** kesinlikle ayrı kalmalı —
  bunlar agent'ın karar ağacında farklı dallar, birleştirilirse agent
  "engine bilinmiyorken hangi payload'ı dener" sorusuna net cevap
  bulamaz. Aynı şekilde **Detection (kanıt toplama)** ile **Confirmation
  (kesinleştirme)** ayrı kalmalı; bunlar farklı risk seviyelerinde farklı
  payload setleri gerektiriyor.

### 17. Modern web application açısından eksik SSTI senaryoları
- **BFF (Backend-for-Frontend) katmanlarında template render** (örn. bir
  GraphQL BFF'nin response'u bir e-posta/PDF template'ine besleme yapması).
- **No-code/low-code platformlar** (kullanıcının kendi "formül"/"template"
  yazabildiği SaaS ürünleri — Airtable, Notion-benzeri araçlar, form
  builder'lar) SSTI açısından önemli ve giderek yaygınlaşan bir attack
  surface; kaynak gösterilmeden "en sık rastlanan senaryo" gibi kesin
  bir sıklık iddiası yapılmamalı, ayrı vurgulanmasının nedeni yaygınlık
  değil, tasarım gereği template motoruna doğrudan erişim sunmasıdır.
- **AI/LLM tabanlı içerik üretim pipeline'ları**: kullanıcı promptunun bir
  Jinja2/Handlebars tabanlı "prompt template" sistemine karıştığı ve bunun
  da ayrıca bir backend template motoruna (rapor/e-posta oluşturma) beslendiği
  çift katmanlı senaryolar.

### 18. Coverage'ı artırmak için başka ne araştırılmalı?
- Genel SSTI CVE veritabanı taraması (Twig, Freemarker, Velocity, Thymeleaf,
  Pebble için bilinen public CVE'lerin payload desenleri) — bu Bölüm B'de
  engine profillerine kaynak olarak eklenmiştir.
- Bug bounty platformlarında (HackerOne/Bugcrowd) yayınlanmış SSTI
  raporlarının ortak desenleri (genellikle e-posta/PDF/rapor
  oluşturma özellikleri) — bu, öncelik skorlamasına veri sağlar.

**Sonuç:** Yukarıdaki eksikler ışığında orijinal 27 bölüme ek olarak
**28. Client-Side vs Server-Side Ayrımı (CSTI)**, **29. No-Code/Low-Code ve
Modern SaaS Attack Surface**, **30. Confidence Scoring ve Agent State
Yönetimi**, **31. Polyglot/Cross-Engine Probing**, **32. Type
Confusion / Object-Context SSTI**, **33. Engine-Specific Escaping
Filtreleri (WAF/Filter bypass bağlamında)**, **34. CVE-Tabanlı Payload
Deseni Araştırması** bölümleri eklenmiştir. Bunlar Bölüm B'de cevaplanmıştır.

---

## BÖLÜM B — Kapsamlı Cevaplar

> Not: 366 soru birebir madde madde değil, konu bütünlüğünü bozmamak için
> tekilleştirilerek ve skill dosyalarına doğrudan aktarılabilecek şekilde
> cevaplanmıştır. Her ana başlığın sonunda **[→ hedef dosya]** notu, bu
> içeriğin hangi parçalanmış skill dosyasına gideceğini gösterir.

### 1. SSTI Temelleri **[→ core]**

SSTI, kullanıcı tarafından kontrol edilebilen verinin bir template
motorunun **template kaynak kodu** (statik içerik değil) olarak
işlenmesiyle oluşur. Fark şu: normal bir template motoru kullanımında
kullanıcı verisi bir **değişkenin değeri** olarak template'e enjekte
edilir (`Merhaba {{name}}`, name="ali"); SSTI'de ise kullanıcı verisi
**template'in kendisinin bir parçası** haline gelir (`Merhaba {{name}}`
yerine template string'in tamamı ya da bir kısmı kullanıcıdan gelir ve
motor tarafından derlenip/yorumlanır).

Oluşma koşulları:
1. Uygulama, kullanıcı girdisini `render_template_string`,
   `Template(user_input)`, `engine.compile(user_input)` gibi bir API'ye
   **doğrudan veya string concatenation ile** veriyor olmalı.
2. Bu girdi, motorun **expression/statement** ayrıştırıcısına ulaşmalı
   (yalnızca "value" konumunda değil).
3. Motorun sandbox'ı bu tür bir expression'ın değerlendirilmesine izin
   vermeli (bazı motorlar bunu tamamen engeller).

Çalışma mekanizması iki aşamalıdır: **parse/compile** (template metni bir
AST'ye/bytecode'a çevrilir) ve **render/evaluate** (bu AST çalıştırılıp
çıktı üretilir). SSTI, saldırganın bu compile aşamasına kendi ifadesini
sokabilmesiyle gerçekleşir; XSS'ten temel farkı budur — XSS'te saldırgan
çıktıyı (HTML/JS) kontrol eder, SSTI'de **motorun kendisini** kontrol
eder.

**Türler:**
- **Direct/Reflected SSTI:** Payload aynı HTTP response içinde,
  aynı request-response döngüsünde değerlendirilip görünür.
- **Blind SSTI:** Payload değerlendirilir ama sonucu response'ta
  görünmez (log, arka plan işi, e-posta gövdesi vb.). Zaman gecikmesi
  veya OOB (out-of-band) sinyalle tespit edilir.
- **Stored SSTI:** Payload bir veri deposuna (DB, dosya, cache) yazılır,
  **daha sonra** (aynı veya farklı bir istek/oturumda) render edilir.
- **Indirect SSTI:** Payload'ı gönderdiğiniz endpoint ile render edildiği
  endpoint **farklıdır** ve aralarında bir veri akış zinciri (workflow)
  vardır (örn. profil alanı → haftalık e-posta bülteni).
- **Out-of-band SSTI:** Sonuç hiçbir response kanalında görünmez;
  yalnızca DNS/HTTP callback ile kanıtlanabilir. Blind'in bir alt
  kümesi olarak da düşünülebilir ama confirmation tekniği farklı olduğu
  için ayrı ele alınmalıdır.

**Etki**, üç faktöre bağlıdır: (a) motorun sandbox/güvenlik modeli
(bazı motorlar tasarım gereği yalnızca ifade değerlendirir, kod
çalıştırmaz — örn. Mustache), (b) uygulamanın motoru hangi bağlamda
çalıştırdığı (native obje/fonksiyonlara erişim var mı), (c) işletim
sistemi/dosya sistemi erişimine giden bir "gadget zinciri"nin mevcut
olup olmadığı (örn. Jinja2'de `__class__.__mro__` üzerinden `os` modülüne
ulaşma). Bu üçü olmadan SSTI yalnızca bilgi sızıntısı/DoS seviyesinde
kalabilir.

### 2. Template Engine Ekosistemi **[→ engines + reference]**

**Dil → Engine haritası (birleştirilmiş):**

| Dil/Platform | Yaygın Engine'ler | Delimiter (tipik) |
|---|---|---|
| PHP | Twig, Smarty, Blade (Laravel), Plates | `{{ }}`, `{% %}` (Twig/Blade benzer); Smarty: `{ }` |
| Python | Jinja2, Django Templates, Mako, Tornado, Genshi | `{{ }}`, `{% %}` |
| Java | Freemarker, Velocity, Thymeleaf, Pebble | `${ }`, `#{ }`, `<# #>`, `[[ ]]` |
| Ruby | ERB, Slim, Haml, Liquid | `<%= %>`, `#{ }` |
| Node.js/JS | EJS, Pug/Jade, Handlebars, Mustache, Nunjucks, doT, Squirrelly | `<%= %>`, `{{ }}`, `#{ }` |
| .NET | Razor, DotLiquid, Scriban | `@( )`, `{{ }}` |
| Go | text/template, html/template | `{{ }}` |
| Shopify/Jekyll | Liquid | `{{ }}`, `{% %}` |

Her engine'in delimiter, expression, interpolation, property-access,
function-call, conditional/loop ve comment sözdizimi Bölüm 20'deki
**Engine Profili tablosunda** tek tek işlenmiştir (tekrarı önlemek için
burada özetlenmemiştir).

### 3–5. Attack Surface, Yüksek Öncelikli Endpointler, Parametre Discovery **[→ workflow + reference]**

**Terminoloji notu (önemli):** Bu bölümdeki sıralamalar **evrensel bir
olasılık dağılımı değil, bir triage/priority heuristic'idir** — yani
agent'ın sınırlı request bütçesini nereden başlatacağına dair bir
önceliklendirme sinyalidir, "SSTI burada olma ihtimali daha yüksektir"
şeklinde kesin bir istatistiksel iddia değildir. Gerçek uygulamaya göre
sıralama tersine dönebilir (örn. bir hedefte e-posta template'i hiç
kullanıcı girdisi almazken, "custom report template" özelliği tam
kontrol veriyor olabilir). Skill dosyasına yazılırken "X, Y'den daha
olasıdır" değil, **"X, Y'den daha yüksek öncelikli bir triage
adayıdır"** ifadesi kullanılmalıdır.

**SSTI aranabilecek request bölümleri (triage önceliği, olasılık değil):**
1. Body parametreleri (JSON/form/multipart) — en yüksek öncelikli
   triage kategorisi.
2. Query string parametreleri.
3. URL path segmentleri (özellikle "slug", "id" gibi ama aslında bir
   template adı/anahtarı olan segmentler).
4. Header'lar (User-Agent, Referer, X-Forwarded-* — bazı uygulamalar bu
   değerleri log/rapor template'lerinde kullanır).
5. Cookie değerleri (özellikle "tema", "dil", "layout" tercihlerini
   tutan cookie'ler).
6. Dosya adı/metadata alanları (upload sırasında dosya adının bir
   bildirim şablonuna geçtiği durumlar).
7. GraphQL değişkenleri / WebSocket mesaj alanları — aynı mantıkla,
   ancak framing'e göre payload encode edilmelidir (JSON string escape,
   binary frame vb.).

Parameter pollution (aynı parametrenin birden fazla kez gönderilmesi)
bazı framework'lerde son/ilk değerin farklı katmanlarda kullanılmasına
yol açtığından SSTI'yi gizleyebilir veya ortaya çıkarabilir; bu nedenle
generic taramada bir varyant olarak denenmelidir.

**Yüksek öncelikli endpoint kategorileri (triage/heuristic sırası,
kesin risk sıralaması değil):**
E-posta/bildirim şablon oluşturma > PDF/rapor/döküman üretimi > CMS
tema/şablon editörü > admin panelindeki "özel HTML/imza" alanları >
arama/filtre/sıralama (nadir ama var, özellikle "sort expression"
alanları) > export/import (özellikle şablon tabanlı export formatları,
örn. "özel CSV/HTML export şablonu") > form/sayfa builder'lar (no-code
araçlar) > hata sayfası/log görüntüleme mekanizmaları (kullanıcı verisi
hata mesajına template olarak basılıyorsa). Bu sıra, hangi kategoriye
**önce** zaman/request bütçesi ayrılacağını belirler; bir hedefte daha
düşük sıradaki bir kategori gerçek zafiyeti barındırıyor olabilir, bu
yüzden düşük öncelikli kategoriler "atlanır" değil "sonraya bırakılır".

**Yüksek öncelikli parametre isimleri:** `template`, `tpl`, `view`,
`render`, `layout`, `theme`, `format`, `content`, `body`, `message`,
`subject`, `email_body`, `preview`, `snippet`, `expression`, `formula`,
`filter`, `sort`, `query_template`, `report_template`, `signature`,
`banner_html`, `custom_html`, `page_content`. Response içinde geçen
"Unable to compile template", "Template syntax error", "unexpected
token" gibi ifadeler de aday belirlemede güçlü sinyaldir. JS
dosyalarından (webpack bundle, API client kodları) ve
OpenAPI/Swagger/GraphQL introspection çıktısından bu isimler
regex/keyword taraması ile otomatik çıkarılabilir; Burp history'de bu
isimlere sahip parametreler otomatik olarak "yüksek öncelik" etiketiyle
işaretlenmelidir.

**Risk skorlama modeli (basit ağırlıklandırma):** parametre adı eşleşmesi
(+3), endpoint kategorisi eşleşmesi (+3), response'ta template-hata
sinyali (+4), teknoloji fingerprint'inin bilinen bir engine'e işaret
etmesi (+2), stored/indirect zincir şüphesi (+2). Toplam skor bir eşiğin
üzerindeyse (örn. ≥5) generic probe kuyruğuna öncelikli olarak alınır.

### 6–7. Generic SSTI Detection ve Payloadlar **[→ detection]**

Generic detection, **engine bilinmediğinde** güvenli/düşük riskli
probe'larla "template evaluation oluyor mu?" sorusuna cevap aramaktır.
İlk probe'lar düşük riskli olmalıdır çünkü bu aşamada hangi engine ile
karşı karşıya olunduğu bilinmez; agresif bir payload hem WAF/alarm
tetikleyebilir hem de hatalı biçimde hedef sistemi etkileyebilir
(örn. DoS'a yol açan ağır bir expression).

**Aşamalı generic probe sırası (her birine biricik bir canary eklenir,
örn. `AAA<random>` öneki/sonu):**

1. **Marker-only probe** (kontrol amaçlı): `AAA_SSTI_1234_ZZZ` — yalnızca
   reflection olup olmadığını, encoding/stripping davranışını öğrenmek
   için (evaluation'la ilgisi yok, baseline'dır).
2. **Arithmetic probe (delimiter matrisi):**
   `{{6666*6666}}`, `${6666*6666}`, `#{6666*6666}`, `<%= 6666*6666 %>`,
   `[[6666*6666]]`, `{{=6666*6666}}`
   — hepsi tek bir request'te değil, ayrı ayrı, sonucu `44435556` üreten
   varyantlar önce en yaygın olanlardan (`{{ }}`, `${ }`) başlanarak
   denenir.
3. **String evaluation probe:** `{{7*'7'}}` (Jinja2'de `7777777`
   üretir, Twig'de hata verir) — bu, aynı zamanda **engine ayrımına**
   başlar çünkü farklı motorlar string*int işlemini farklı yorumlar.
   Bu probe'un amacı sayısal sonucu doğrulamak değil, **coercion
   davranışını** gözlemlemektir; bu yüzden burada küçük bir sayı
   (`7`) kasıtlı olarak korunur — büyük bir çarpan (örn. `6666`)
   binlerce karakterlik bir string üretip response'u şişirir ve
   pratik açıdan anlamsızlaşır. Madde 2'deki "birincil arithmetic
   identity probe" ile bu "ikincil coercion probe"unu karıştırmayın.
4. **Boolean/comparison probe:** `{{1==1}}` / `{{1==2}}` çiftinin
   response farkının izlenmesi (True/False, 1/0, farklı HTML çıktısı).
5. **Variable interpolation probe:** Uygulamanın kendi bilinen bir
   değişkenini (örn. kullanıcı adı) template sözdizimiyle çağırmayı
   deneme: `{{username}}` gibi — eğer uygulama gerçekten o değişkeni
   basıyorsa bu güçlü bir sinyaldir.
6. **Error-based probe:** Kasıtlı olarak bozuk sözdizimi
   (`{{6666*6666`, `${6666*6666`, `<%= 6666*6666`) gönderip **stack
   trace / şablon hatası** dönüp dönmediğine bakma — hata mesajları
   çoğu zaman engine adını doğrudan verir (bkz. Bölüm 8).

**Arithmetic Probe Seçim Kuralı:** SSTI detection metodolojisinde
`7*7 → 49` gibi küçük ve response içinde doğal olarak bulunma ihtimali
yüksek arithmetic probe'lar **birincil identity probe olarak
kullanılmaz** (false-positive riskini artırır — sayfa numarası, ID,
zaman damgası, ürün adedi gibi bağlamlarda `49` zaten doğal olarak
geçebilir). Bunun yerine:
- Küçük ve yaygın sonuçlardan kaçınılır.
- Sonucun response içinde doğal olarak bulunma ihtimali düşük olmalıdır.
- Sonuç deterministic ve kolay aranabilir (grep edilebilir) olmalıdır.
- Binlik ayraç **kullanılmaz**: `6666*6666` işleminin beklenen ham
  sonucu `44435556`'dır; `"44,435,556"`, `"44.435.556"` veya başka
  locale-specific biçimler aranmaz/beklenmez. Agent, locale/format
  farklılıkları nedeniyle raw response'ta `44435556` döndüğünde bunu
  gereksiz yere "sonuç bulunamadı" (false negative) olarak
  değerlendirmemelidir — arama ham, formatlanmamış sayı üzerinden
  yapılmalıdır.
- Detection tek bir arithmetic probe'a bağımlı olmamalıdır; agent
  gerektiğinde farklı, yüksek ayırt ediciliğe sahip başka deterministic
  sonuçlar da (örn. `1337*1337=1787569`) kullanabilmelidir — önemli
  olan sabit bir sayı değil, yukarıdaki dört kritere uyan **herhangi**
  bir sonuçtur.
- Arithmetic sonucunun response içinde bulunması **tek başına** SSTI
  kanıtı sayılmaz; aşağıdaki evidence/classification ayrımı hâlâ
  geçerlidir.

**Evidence/classification ayrımı (kritik — Bölüm 15 ile tutarlı
olmalıdır):** "Probe pozitif mi?" sorusu ile "SSTI confirmed mi?"
sorusu **iki farklı katmandır** ve birbirine indirgenmemelidir. Önceki
sürümde burada "(a) marker + (b) sonuç + (c) negative control'ün
üçünün birden zorunlu olduğu" bir kural vardı; bu, Bölüm 15'teki
"Confirmed = yeterli ve bağımsız evaluation evidence, sabit bir
kombinasyon değil" ilkesiyle çelişiyordu ve düzeltildi. Doğru model:

1. **Probe/Evaluation signal (ham gözlem katmanı)** — her biri kendi
   başına ayrı bir evidence kaydıdır, birbirine bağımlı değildir:
   - Aritmetik sonuç (`44435556`) response'ta görüldü mü? (evet/hayır)
   - Canary marker response'ta görüldü mü? (evet/hayır — **marker'ın
     görülmemesi, aritmetik sonucun evaluation kanıtı olmadığı
     anlamına gelmez**; marker yalnızca reflection konumunu bulmaya
     yarayan ayrı bir sinyaldir, örn. `{{6666*6666}}` gönderilip
     marker hiç eklenmemiş veya farklı bir render noktasında
     tüketilmiş olabilir)
   - Negative control (encode edilmiş/kaçırılmış hali) farklı
     davrandı mı? (evet/hayır/denenmedi)
   Bu üç gözlem **bağımsız olarak kaydedilir**; herhangi biri eksik
   olduğu için diğerleri otomatik olarak geçersiz sayılmaz.

2. **SSTI classification (yorum katmanı)** — yukarıdaki evidence
   kayıtlarının toplamına göre agent şu beş durumdan birine karar
   verir: **Negative** (hiçbir evaluation sinyali yok) →
   **Inconclusive** (belirsiz/kısmi sinyal, ek probe gerekir) →
   **Suspected** (tek bir evaluation sinyali var ama bağımsız ikinci
   kanıt yok) → **Strong candidate** (evaluation sinyali + en az bir
   bağımsız destekleyici kanıt, ör. negative control farkı **veya**
   ikinci bağımsız probe ailesi) → **Confirmed** (Bölüm 15'teki gibi,
   birbirinden bağımsız yeterli evaluation evidence — marker+aritmetik+
   negative control üçlüsü bunun **örnek bir yeterli kombinasyonudur,
   zorunlu tek yol değildir**).

Marker+aritmetik+negative-control üçlüsü artık **"pozitif probe" için
zorunlu şart" değil, "Strong candidate/Confirmed'e ulaşmak için
kullanılabilecek güçlü bir örnek kombinasyon"** olarak okunmalıdır.
Baseline/negative control ve response diffing, mümkün olduğunda
bağımsız bir evaluation evidence (örn. Bölüm 12'deki error-based veya
string-coercion probe) ile desteklenmelidir, ama bunların hiçbiri
diğerinin evidence kaydını geçersiz kılmaz.

### 8. Template Engine Fingerprinting **[→ fingerprinting]**

Fingerprinting, generic detection **pozitif** çıktıktan sonra "hangi
engine" sorusuna cevap arayan aşamadır. Karar ağacı yaklaşık şöyledir:

```
{{6666*6666}} → 44435556 mü?
 ├─ Evet → {{7*'7'}} sonucu?
 │    ├─ "7777777" → Jinja-like coercion signal (Jinja2/Nunjucks ailesiyle
 │    │     tutarlı, ama tek başına kesin engine tespiti değil — bu tek
 │    │     bir "medium" sinyaldir; {{config}}/{{self}} gibi bağımsız bir
 │    │     ikinci sinyalle desteklenmeden Jinja2 vs Nunjucks ayrımı
 │    │     yapılmamalı) → {{config}} / {{self}} dener → Jinja2 vs
 │    │     Nunjucks ayrımı
 │    ├─ Hata/boş → Twig olabilir → {{7*'7'}} yerine {{'7'*7}} dener,
 │    │     Twig filtre sözdizimini dener: {{6666*6666}}{{_self}}
 │    └─ Diğer davranış → Django Templates (daha kısıtlı, {{6666*6666}}
 │          çoğu zaman çalışmaz çünkü Django Templates aritmetik
 │          desteklemez) → negatif sinyal de fingerprint'tir
 └─ Hayır → ${6666*6666} → 44435556 mü?
      ├─ Evet → Freemarker/Velocity/Thymeleaf ailesi
      │    → Freemarker'a özgü `<#assign>`, Velocity'ye özgü `#set`,
      │      Thymeleaf'e özgü `th:` attribute davranışı denenir
      └─ Hayır → #{6666*6666} / <%= 6666*6666 %> / [[6666*6666]]
           denenir (Ruby/EJS/Pebble)
```

**Önemli sınırlama:** Bu ağaç bir **karar prosedürü** değil, bir
**sinyal toplama sırasıdır**. Her dal aslında bir olasılık tahminidir,
kesinlik değil — çünkü aynı davranış engine sürümüne, configuration'a,
custom filter/function'lara, sandbox'a ve context'e göre değişebilir
(örn. bir Jinja2 hedefi custom sandbox nedeniyle `{{7*'7'}}`'de hata
verebilir). Bu nedenle her yaprak düğüm bir **confidence seviyesiyle**
etiketlenmelidir, kesin sonuç olarak değil:
- **Strong indicator:** error-message fingerprinting (engine adı stack
  trace'te doğrudan geçiyor) veya birden fazla bağımsız sinyalin
  (delimiter + string-coercion + error signature) aynı engine ailesine
  işaret etmesi.
- **Medium indicator:** delimiter + arithmetic + string-coercion
  üçlüsünün tek başına tutarlı sonuç vermesi (config/versiyon
  bağımlılığı nedeniyle tek başına kesin kabul edilmez).
- **Weak indicator:** yalnızca delimiter/arithmetic eşleşmesi (birçok
  engine aynı delimiter'ı paylaşır).
- **Negative indicator:** beklenen davranışın **olmaması** da bir
  sinyaldir (örn. Django Templates'te aritmetik çalışmaması), ama
  tek başına başka bir engine'i doğrulamaz.

Fingerprint sonucu, engine-specific confirmation aşamasına geçmeden
önce mümkünse en az bir **strong** veya iki bağımsız **medium**
sinyalle desteklenmelidir. Ek sinyaller:

- **Error message fingerprinting:** `TemplateSyntaxError` (Jinja2/Django),
  `Twig\Error\SyntaxError`, `freemarker.core.ParseException`,
  `org.apache.velocity.exception`, `org.thymeleaf.exceptions` gibi ifadeler
  stack trace'te doğrudan engine adını verir — en güvenilir sinyaldir.
- **HTTP header/teknoloji sinyalleri:** `X-Powered-By`, session cookie
  isimlendirmesi (`JSESSIONID`→Java, `laravel_session`→Blade/Twig
  değil ama Laravel→Blade olasılığı), `Server` header'ı — bunlar
  **doğrulayıcı** değil **öncelik belirleyici** sinyallerdir.
- **HTML/kaynak artefaktları:** CMS'e özgü meta tag'ler
  (`<meta name="generator" content="Craft CMS">`) doğrudan Bölüm 10'daki
  CMS→engine tablosuna yönlendirir.

Birden fazla engine aynı uygulamada bulunabilir (örn. ana site Twig,
e-posta alt sistemi Freemarker) — bu nedenle fingerprinting **her
endpoint için ayrı** yapılmalı, tek bir sonuç tüm uygulamaya
genellenmemelidir. Engine fingerprint edilemezse (tüm sinyaller
negatif/belirsiz), agent **context detection**'a (Bölüm 9) geçmeli ve
polyglot payload'larla (Bölüm B-31) denemeye devam etmelidir.

### 9. Context Detection **[→ context]**

Context, payload'ın template kaynağı içinde **nerede** durduğudur:
düz metin, HTML etiketi içi, HTML attribute içi, string literal içi
(tırnak içinde), doğrudan expression içi, ya da statement (kontrol
yapısı) içi. Aynı payload farklı context'lerde farklı davranır çünkü
bazı context'lerde ekstra kapanış karakteri (`"`, `'`, `}}`) gerekir.

**Context tespiti için probe stratejisi:** Önce **kapatma karakteri
olmadan** salt bir marker gönderilir; response'ta marker'ın etrafındaki
karakterler incelenir (örn. `value="MARKER"` görülüyorsa attribute
context'tir). Sonra sırasıyla `"`, `'`, `}}`, `%}`, `-->` gibi olası
kapatıcı diziler eklenerek hangisinin syntax hatasını **düzelttiği**
(yani hatayı ortadan kaldırdığı) gözlenir — hatayı gideren kapatıcı,
doğru context'i işaret eder. Context bilgisi elde edildikten sonra
payload otomatik olarak bu kapatıcı ön-ek ile zenginleştirilir (örn.
`"}}{{6666*6666}}{{"` gibi).

### 10. CMS / Framework / Teknoloji Eşlemesi **[→ reference]**

| CMS/Framework | Engine | Not |
|---|---|---|
| Craft CMS | Twig | Twig SSTI'de klasik hedeflerden; sandbox genelde aktif |
| Django | Django Templates (bazen Jinja2 de yapılandırılabilir) | Django Templates aritmetik yapmaz, bu negatif sinyal |
| Flask | Jinja2 | En sık karşılaşılan Python SSTI hedefi |
| Laravel | Blade (derlenmiş halde aslında PHP) | Blade SSTI'de doğrudan PHP execution riski yüksektir |
| Rails | ERB | Genelde geliştirici hatası ile `render inline:` kullanımı |
| Shopify/Jekyll | Liquid | Sandbox güçlü, dosya sistemine erişim genelde yok |
| Grav / October CMS | Twig | |
| Magento | Smarty (legacy) / Blade değil | |
| Confluence/Jira (eski sürümler) | Velocity | Bilinen public CVE'ler mevcut |
| Adobe Experience Manager | Sling/JSP tabanlı | Özel araştırma gerektirir |
| Spring (genel) | Thymeleaf / Freemarker | SpEL ile karışabilir, dikkatli ayrılmalı |
| ASP.NET (genel) | Razor | `@()` sözdizimi |
| Go web uygulamaları | text/template veya html/template | html/template'te auto-escape SSTI etkisini azaltır |

**Kesinlik uyarısı:** Yukarıdaki tablodaki notlar ("sandbox genelde
aktif", "risk yüksektir" vb.) **default/tipik davranış** özetleridir,
kesin kural değildir. Gerçek davranış dört eksende değişebilir:
default behavior (kurulumdan hemen sonraki hâl), configuration-dependent
behavior (uygulamanın sandbox/extension ayarları), version-dependent
behavior (engine/framework sürümü) ve application-specific behavior
(geliştiricinin eklediği custom filter/context). Agent, bu tablodaki
bir notu **doğrulanmış bir gerçek** gibi rapora yazmamalı, yalnızca
"öncelik belirleyici bir varsayım" olarak kullanmalı ve gerçek
davranışı hedefte ayrıca doğrulamalıdır.

### 11–12. Stored / Indirect ve Blind SSTI **[→ workflow + detection]**

**Stored/Indirect metodolojisi:** Payload'ı olası bir "kaynak" alana
(profil, ayar, form) marker'lı olarak gönder → uygulamanın bu veriyi
nerede kullanabileceğini haritalandır (e-posta bildirimleri, admin
panel listeleri, PDF/rapor export'ları, haftalık özet e-postaları,
public profil sayfaları) → her olası "render noktası"nı tetikleyip
(mümkünse) veya bekleyip kontrol et. Bu bir **zincir haritalama**
gerektirir: `giriş noktası → depolama → tetikleyici → render noktası`.
Zincir uzunsa (2+ adım) agent, her adımı ayrı ayrı doğrulamalı (örn.
veri gerçekten kaydedildi mi, tetikleyici gerçekten çalıştı mı) ki
"payload çalışmadı" ile "render noktasına hiç ulaşmadı" ayrımı net
olsun.

**Blind SSTI:** Response'ta doğrudan kanıt yoksa iki yol var:
1. **Timing-based:** Engine'e özgü "yapay olarak yavaş" bir expression
   (örn. Jinja2'de büyük bir range üzerinde iterasyon, Java engine'lerde
   ağır string tekrarı) enjekte edip response süresini baseline ile
   karşılaştırma. Ağ gecikmesi/varyansı elemek için birden fazla ölçüm
   ve istatistiksel eşik (örn. median + 3×IQR) kullanılmalı.
2. **OOB (out-of-band):** Engine'in dosya/network erişimi varsa
   (örn. Jinja2 üzerinden `os.popen('curl ...')`, SSTI'nin RCE'ye
   evrildiği noktalarda) bir DNS/HTTP callback alan adına istek
   attırılır ve bu alan adına gelen istek doğrulama kanıtı sayılır.
   OOB davranışı **yalnızca "sandbox yok" durumuna bağlı değildir**:
   sandbox mevcut olsa bile template environment'a bilerek expose
   edilmiş network-capable bir fonksiyon/helper/filter (örn. bir
   "resim URL'sinden getir" filtresi, bir HTTP-fetch helper'ı) varsa
   OOB yine mümkün olabilir. Doğru genelleme şudur: **OOB, template
   environment'ın erişebildiği fonksiyon/object/helper'ların network
   etkileşimine izin vermesine bağlıdır; sandbox varlığı tek başına
   belirleyici değildir.**

   **OOB'nin kanıt gücü yüksek olması, her blind SSTI durumunda
   otomatik olarak denenmesi gerektiği anlamına gelmez.** OOB, koşullu
   bir confirmation dalı olarak modellenmelidir:

   ```
   Blind SSTI şüphesi
        ↓
   OOB altyapısı mevcut mu? (agent'ın kontrol ettiği bir
   DNS/HTTP callback alan adı var mı?)
        ↓ hayır ──────────────────────► Yalnızca timing-based confirmation
        ↓ evet                           kullanılır (daha zayıf kanıt, ama
   Program kapsamı/yetkilendirmesi        tek seçenek budur)
   OOB/network-egress testine izin
   veriyor mu? (bazı bug bounty
   programları yalnızca in-band
   kanıt ister, dışarıya istek
   attırmayı ayrıca kısıtlayabilir)
        ↓ hayır ──────────────────────► Yalnızca timing-based confirmation
        ↓ evet
   Engine/context'in network-capable
   bir fonksiyona erişimi olduğuna
   dair yeterli sinyal var mı?
   (Bölüm 32'deki gadget/attribute
   erişim kanıtı, fonksiyon listesi
   fingerprinting'i vb.)
        ↓ hayır ──────────────────────► Timing-based ile devam edilir,
        ↓ evet                           OOB denemesi ertelenir
   Low-impact, tek seferlik OOB
   confirmation denemesi yapılır
   ```

   Yani sıralama "önce timing, sonra izin varsa OOB" gibi otomatik bir
   tercih değil, **kapsam/yetkilendirme ve teknik ön-koşulların
   birlikte sağlandığı** durumlarda OOB'ye geçilen koşullu bir dal
   olarak ele alınmalıdır. Program kuralları OOB/network-egress
   testini kısıtlıyorsa (bazı programlar yalnızca in-band PoC ister),
   agent OOB denemesi yapmamalı ve bunu timing-based kanıtla
   sınırlamalıdır.

### 13–14. Encoding/Transformation ve WAF/Filter **[→ detection + fingerprinting]**

Input, template motoruna ulaşmadan önce şu katmanlardan geçebilir:
URL decode → uygulama seviyesi custom decode (örn. Base64) → charset
dönüşümü → framework'ün otomatik unescape'i → (opsiyonel) WAF/filter
kontrolü → template motoruna geçiş. Her katman SSTI sinyalini
bozabilir. Pratik yaklaşım: bir parametrenin Base64/hex/URL-encoded
olup olmadığı **response davranışından** çıkarılır (örn. decode edilmiş
haliyle anlamlı bir alanla eşleşiyor mu); şüpheleniliyorsa payload hem
düz hem encode edilmiş halde denenir, ikisi de negatifse "muhtemelen
çoklu encode katmanı var" varsayımıyla çift/üçlü encode varyantları
otomatik üretilip denenir.

**Filtre/WAF karşısında** iki farklı amaç ayrılmalı: (1) **Detection**
aşamasında amaç WAF'ı atlatmak değil, "filtre var mı yok mu"yu
anlamaktır — filtrelenen karakter/kelime tespit edilir (örn. `{{` her
zaman 403 döndürüyor ama `{ %raw% }`-tarzı parçalanmış hali dönmüyor).
(2) Bypass denemeleri (concatenation, case değişikliği, whitespace/yorum
ekleme, encoding katmanları) yalnızca detection **pozitif** çıktıktan
sonra, ayrı ve daha az sayıda request ile, agresiflik artan sırada
denenmelidir — bu, gereksiz request'i azaltıp WAF tarafından
engellenme/ban riskini düşürür.

### 15. False Positive / False Negative Eliminasyonu **[→ detection]**

**Beş kademeli sınıflandırma (Bölüm 6-7'deki evidence/classification
ayrımıyla birebir aynı terminoloji):** Negative → Inconclusive →
Suspected → Strong candidate → Confirmed. Bu bölümdeki "Confirmed"
tanımı, Bölüm 6-7'de tanımlanan evidence/classification katmanlarının
aynısıdır; iki bölüm arasında farklı kural seti yoktur.

- **Confirmed:** Yeterli ve birbirinden bağımsız server-side
  evaluation evidence'ı. Bu evidence farklı kombinasyonlardan
  gelebilir. Örneğin güçlü bir template compile error (engine adını
  doğrudan veren bir stack trace) + engine-specific bir evaluation
  davranışı + bağımsız bir confirmation, arithmetic probe hiç
  kullanılmadan da "confirmed" için yeterli olabilir — özellikle
  arithmetic probe'un WAF tarafından engellendiği veya context'in
  arithmetic denemeye uygun olmadığı durumlarda. Aşağıdaki örnek
  kombinasyonlardan **herhangi biri** (birbirinden bağımsız en az iki
  farklı evidence kategorisi şartıyla) confirmed sayılabilir:
  - Marker + doğru hesaplanmış aritmetik sonuç (örn. `44435556`) +
    negatif kontrolün (encode edilmiş/kaçırılmış hali) farklı davrandığı
    + mümkünse ikinci bağımsız bir expression'ın (örn. `{{7*'7'}}` gibi
    string-coercion testi) de tutarlı sonuç verdiği durum — bu, **örnek
    bir yeterli kombinasyondur, zorunlu tek yol değildir**; örneğin
    marker görülmese bile aritmetik sonuç + negative control farkı +
    bağımsız bir string-coercion sinyali tek başına yeterli olabilir.
  - Engine adını doğrudan veren bir error-based sinyal (stack trace/hata
    mesajı) + bağımsız bir context/behavior doğrulaması (örn. aynı
    hedefte farklı bir expression'ın da tutarlı biçimde evaluate
    edildiğinin gösterilmesi).
  - OOB callback kanıtı (Bölüm 12) + reflection/marker eşleşmesi.
- **Strong candidate:** Tek bir güçlü evaluation sinyali (örn. doğru
  aritmetik sonuç veya bir error-based sinyal) var, ama henüz bağımsız
  ikinci bir kanıt kategorisiyle desteklenmemiş — örn. aritmetik sonuç
  doğru ama negatif kontrol doğrulanamadı (rate limit nedeniyle tekrar
  denenemedi) veya marker görülmedi ama sonuç beklenen konumda net.
- **Suspected:** Zayıf/tekil bir sinyal var (örn. yalnızca delimiter
  eşleşmesi, aritmetik sonuç olmadan) — Strong candidate'e geçmek için
  ek probe gerekir.
- **Inconclusive:** Response'ta belirsiz/kısmi bir sinyal var (örn.
  status code değişti ama body aynı) ama net kanıt yok; ek probe
  gerektirir.
- **Negative:** Hiçbir probe ailesi (arithmetic/string/boolean/error)
  hiçbir evaluation sinyali vermedi.

Ortak kural: kanıtlar **birbirinden bağımsız evidence kategorilerinden**
gelmelidir (bkz. Bölüm 18/30 "Evidence bağımsızlığı"). İkinci bir
expression **aynı temel evaluation mekanizmasına** dayanıyorsa (örn.
sadece delimiter'ı değiştirilmiş aynı aritmetik işlem) bağımsız bir
kanıt olarak sayılmaz — gerçekten farklı bir evidence kategorisi
(error-based, string-coercion, boolean, OOB) olmalıdır. Skill dosyası
bu maddeyi "confirmed için A+B+C zorunludur" değil, "confirmed için
yeterli ve bağımsız evaluation evidence'ı gerekir; aşağıdakiler kabul
edilen örnek kombinasyonlardır" şeklinde yazmalıdır.



**Yaygın false-positive kaynakları:** CDN/cache'in eski bir response'u
tekrar sunması (cache-busting parametresi eklenerek elenir); WAF'ın
kendi hata sayfasının SSTI hatasıyla karıştırılması (WAF imzası
genelde farklı bir HTML yapısına/başlığa sahiptir, karşılaştırmalı
kontrolle ayrılır); **istemci tarafı (CSTI)** template motorlarının
(AngularJS `{{}}`, Vue `{{}}`) tarayıcıda render olup sonucun HTML'e
düşmesi — bu **kesinlikle SSTI değildir**, response'un "Content-Type"
ve render'ın sunucu tarafında mı tarayıcıda mı olduğu (view-source ile
ham response incelenerek) mutlaka doğrulanmalıdır; uygulamanın kendi
meşru "hesap makinesi/formül" özelliğinin aritmetik sonucu doğal olarak
göstermesi.

### 16. Request/Response Analizi **[→ detection]**

Her probe için: (a) baseline request/response saklanır, (b) probe
request'in body length, status code, response time, header farkları
baseline ile karşılaştırılır, (c) yalnızca body içeriği değil headers
ve status code da izlenir (bazı engine hataları 500, bazıları farklı
bir hata sayfası/redirect üretir). Birden fazla probe sonucu bir
"evidence tablosu" halinde tutulmalı (payload, context, sonuç,
kanıt tipi) — bu tablo hem confidence scoring'e hem de raporlamaya
girdi olur.

### 17. Recon → SSTI Workflow **[→ workflow]**

Sıra: subdomain/URL discovery → HTTP probing (canlı host'ları belirle)
→ teknoloji fingerprinting (CMS/framework tespiti; bu SSTI'ye özel
değil ama önceliklendirmeyi doğrudan besler) → JS/OpenAPI/GraphQL
üzerinden endpoint + parametre discovery → Bölüm 5'teki risk skorlama
modeliyle önceliklendirme → yüksek skorlu adaylarda generic detection →
pozitif çıkanlarda fingerprinting/context → engine-specific
detection/confirmation → stored/indirect ve blind kontrolleri (yalnızca
doğrudan reflect olmayan yüksek öncelikli adaylarda) → raporlama.

### 18. AI Agent SSTI Testing Methodology + 30. Confidence Scoring / State Yönetimi **[→ workflow]**

**Öncelik sırası:** Yüksek risk skorlu (Bölüm 5) endpoint/parametre
çiftleri önce; her çift için önce **generic probe seti** (tek tur, ~5-6
request), pozitifse **fingerprinting** (~3-5 request), sonra
**engine-specific confirmation** (~2-3 request). Bu, engine bilinmeden
doğrudan onlarca engine-specific payload denemekten çok daha az
request harcar.

**Confidence scoring modeli (örnek/öneri, evrensel standart değil):**
Aşağıdaki puanlama, gerçek bir sektör standardına dayanmaz; agent'ın
"dur/devam et" kararını somutlaştırmak için **önerilen bir örnek
modeldir**, skill dosyasına da bu şekilde ("suggested model", zorunlu
kural değil) yazılmalıdır. Her kanıt parçası bir puan katkısı yapar
(marker reflection +1, aritmetik doğru sonuç +3, negatif kontrol farkı
+3, error-based engine adı eşleşmesi +4, ikinci bağımsız probe
tutarlılığı +2, OOB callback alındı +5). Toplam ≥8 → confirmed; 5–7 →
probable (ek doğrulama tetikler); 2–4 → inconclusive (agent bir
sonraki probe ailesine geçer); 0–1 → negative (agent bu aday için
durur).

**Evidence bağımsızlığı (kritik kural):** Puanlar yalnızca **birbirinden
bağımsız** kanıt kategorilerinden geldiğinde toplanmalıdır. Kanıt
kategorileri: reflection evidence, evaluation evidence, engine
fingerprint evidence, context evidence, independent confirmation,
stored/indirect evidence, OOB evidence. İki farklı payload aynı
underlying evaluation davranışına dayanıyorsa (örn. yalnızca delimiter
değiştirilmiş iki aritmetik probe), bunlar **iki ayrı kanıt olarak
sayılmaz** — tek bir "evaluation evidence" puanı verir. Bu ayrım
yapılmazsa confidence score yapay olarak şişer ve gerçekte tek bir
zayıf sinyale dayanan bir bulgu "confirmed" gibi görünebilir.

**Ne zaman durulmalı:** (a) skor "confirmed" eşiğine ulaştığında —
gereksiz ek payload denenmez (bug bounty'de minimal-impact prensibi);
(b) belirlenen request bütçesi (örn. aday başına maksimum 15 request)
tükendiğinde — sonuç "inconclusive" olarak işaretlenip bir sonraki
adaya geçilir; (c) WAF/rate-limit block'u art arda 3+ kez tetiklenirse
— agent bekleme/backoff uygular veya bypass denemesine geçer, sonsuz
tekrar etmez.

**State/duplicate önleme:** Agent, test ettiği (endpoint, parametre,
context, payload-ailesi) dörtlüsünü bir state tablosunda tutmalı; aynı
kombinasyon tekrar denenmeden önce state kontrolü yapılmalı. Bu hem
request bütçesini korur hem de WAF tetiklenme riskini azaltır.

**Paralel/sıralı testler:** Farklı endpoint'lerdeki generic probe'lar
paralel yürütülebilir (birbirinden bağımsız). Aynı endpoint içindeki
fingerprinting adımları **sıralı** olmalıdır çünkü her adımın sonucu
bir sonraki payload seçimini belirler (karar ağacı yapısı gereği).

### 19. SSTI Decision Tree **[→ workflow, üst düzey özet]**

Önerilen tam akış (Bölüm A'daki eklemelerle güncellenmiş). Önceki
sürümde stored/indirect ve blind dallanması akışın sonuna, "reflected
değilse" koşuluna bağlı olarak ekleniyordu; bu yanıltıcıdır çünkü
async e-posta/PDF/rapor sistemlerinde response'ta **hiçbir zaman**
doğrudan bir kanıt görünmeyebilir — bu durumda agent "reflected mi?"
sorusuna gelene kadar zaten yanlış yola girmiş olur. Bu yüzden
reflected/stored-indirect/blind ayrımı, generic detection'dan hemen
sonra **paralel bir dallanma** olarak modellenmelidir, sona bırakılan
ikincil bir adım olarak değil:

```
Recon → Endpoint/Parametre Discovery → Risk Skorlama
   ↓
[Yüksek skorlu aday seçildi]
   ↓
Source → Sink adayı belirlendi mi? (Bölüm 35)
   ↓
Generic SSTI Probes (marker + arithmetic + string + boolean + error)
   ↓
Evaluation evidence var mı? ──Hayır──> Inconclusive/Negative → sıradaki adaya geç
   │Evet
   ↓
Nerede gözlemleniyor? (bu üç dal paralel değerlendirilir, birbirini dışlamaz)
   ├─ Reflected (aynı response'ta doğrudan görünüyor)
   ├─ Stored/Indirect (Bölüm 11: giriş→depolama→tetikleyici→render zinciri
   │     haritalanır; her adım ayrı doğrulanır)
   └─ Blind/OOB şüphesi (Bölüm 11: response'ta kanıt yok; async
         worker/queue/e-posta/PDF gibi render noktaları araştırılır)
   ↓ (hangi dal geçerliyse oradan devam)
Context Detection (payload nerede duruyor?)
   ↓
Template Engine Fingerprinting (delimiter/error/karar ağacı — sinyal
gücü Strong/Medium/Weak/Negative olarak etiketlenir, Bölüm 8)
   ↓
Engine belirlendi mi? ──Hayır──> Polyglot/cross-engine probing dene
   │Evet                              │
   ↓                                   ↓
Engine-Specific Detection/Confirmation  (yine belirsizse) Inconclusive
   ↓
Encoding/Filter analizi (varsa) → gerekirse bypass denemesi
   ↓
Confirmation (düşük etkili, side-effect-free payload'larla önce;
Blind/OOB dalındaysa Bölüm 11'deki koşullu OOB akışı uygulanır)
   ↓
False-Positive Elimination (negatif kontrol, CSTI ayrımı, cache/WAF kontrolü)
   ↓
Severity/Impact Değerlendirme
   ↓
Raporlama
```

Her aşamadan çıkabilecek üç sonuç vardır: **devam et** (pozitif/daha
fazla kanıt gerekli), **dur** (negative/confirmed), **dallan** (örn.
engine belirsizse polyglot'a, gözlem noktası reflected/stored/blind
arasında farklıysa ilgili dala). Reflected/Stored-Indirect/Blind
dalları **birbirini dışlamaz** — aynı payload aynı anda hem reflected
hem de (farklı bir render noktasında) stored olarak da gözlemlenebilir;
agent her gözlem noktasını ayrı bir evidence kaydı olarak tutmalıdır.

### 20. Template Engine-Specific Profiller **[→ engines, ayrı dosya/dosyalar]**

Aşağıdaki tablo her önemli engine için Bölüm A'da istenen alanların
özet halidir (tam detaylandırılmış hali, skill dosyalarına aktarılırken
her engine kendi alt-dosyasında genişletilmelidir):

| Engine | Dil | Delimiter | Aritmetik Probe | Confirmation (bilgi sızdırma) | Sandbox |
|---|---|---|---|---|---|
| Jinja2 | Python | `{{ }}` `{% %}` | `{{6666*6666}}`→44435556 | `{{config}}`, `{{self}}`, `{{cycler.__init__.__globals__}}` | Yok (varsayılan) / Sandboxed env opsiyonel |
| Nunjucks | Node.js | `{{ }}` `{% %}` | `{{6666*6666}}`→44435556 | `{{range.constructor("return process.env")()}}` benzeri | Kısmi |
| Twig | PHP | `{{ }}` `{% %}` | `{{6666*6666}}`→44435556 | `{{_self}}`, `{{dump(app)}}` | Genelde aktif (sandbox extension) |
| Smarty | PHP | `{ }` | `{6666*6666}`→44435556 | `{php}...{/php}` (eski sürümler) | Sürüme göre değişir |
| Freemarker | Java | `${ }` `<# #>` | `${6666*6666}`→44435556 | `<#assign ex="freemarker.template.utility.Execute"?new()>` | Yok (varsayılan) |
| Velocity | Java | `${ }` `#set` | `#set($x=6666*6666)$x`→44435556 | `#set($e="e")$e.getClass()...` | Yok |
| Thymeleaf | Java | `${ }` `th:*` | `${6666*6666}`→44435556 | SpEL üzerinden `T(java.lang.Runtime)` erişimi | Kısmen (SpEL bağlamına göre) |
| Pebble | Java | `{{ }}` `{% %}` | `{{6666*6666}}`→44435556 | Sürüme göre `execution` erişimi | Aktif (genelde) |
| ERB | Ruby | `<%= %>` | `<%= 6666*6666 %>`→44435556 | `<%= \`id\` %>`, `system()` | Yok |
| Slim/Haml | Ruby | Ruby-benzeri | Ruby ifadesi | ERB benzeri | Yok |
| Liquid | Ruby/Shopify | `{{ }}` `{% %}` | Aritmetik desteği sınırlı, filtre bazlı | Genelde çok kısıtlı | Güçlü sandbox |
| EJS | Node.js | `<%= %>` | `<%= 6666*6666 %>`→44435556 | `<%= process.mainModule.require('child_process').execSync('id') %>` | Yok |
| Pug | Node.js | `#{ }` | `#{6666*6666}`→44435556 | JS ifadesi doğrudan çalışır | Yok |
| Handlebars | Node.js | `{{ }}` | Yok (logic-less) | Helper injection ile dolaylı | Güçlü (logic-less) |
| Mustache | Çok dilli | `{{ }}` | Yok (logic-less) | Yok | Güçlü (logic-less) |
| Razor | .NET | `@( )` | `@(6666*6666)`→44435556 | Sürüme/konfigürasyona bağlı | Genelde derleme zamanlı, runtime SSTI nadir |
| DotLiquid/Scriban | .NET | `{{ }}` | Sınırlı/Scriban'da var | Scriban'da daha esnek | Liquid mantığıyla kısıtlı |
| Go text/template | Go | `{{ }}` | Yok (fonksiyon çağrısı ile) | `{{.}}`, kayıtlı fonksiyonlarla sınırlı | Fonksiyon whitelist modeli |
| Go html/template | Go | `{{ }}` | Aynı ama auto-escape var | Context-aware escape SSTI etkisini büyük ölçüde azaltır | Güçlü (context-aware) |

Sandbox davranışı, "izin verilen obje/fonksiyon listesi"nin (whitelist)
sorgulanmasıyla test edilir: motorun exception mesajı genelde hangi
tür/metodun engellendiğini açıkça belirtir, bu da hem fingerprint hem
sandbox-doğrulama sinyalidir. Versiyon farkları önemlidir (örn. Twig
1.x'te bazı `_self` erişimleri farklı davranırken, sonraki sürümlerde
sandbox extension varsayılan hale gelmiştir); bu nedenle
confirmation aşamasında versiyon-spesifik payload alternatifleri de
denenmelidir.

### 21. Sandbox ve Template Security **[→ engines]**

Sandbox, motorun hangi Python/Java/Ruby native objelerine erişime izin
verdiğini kısıtlayan bir güvenlik katmanıdır (örn. Jinja2
`SandboxedEnvironment`, Twig `SandboxExtension`). Sandbox varlığı,
bilinen "kaçış" (escape) obje zincirlerinin (`__class__`, `__mro__`,
`__globals__` gibi) denenip **açıkça engellendiğini gösteren** bir
hata mesajı alınmasıyla doğrulanır (aksi halde "sandbox yok" ya da
"gadget bulunamadı" arasında ayrım yapılamaz — bu ikisi de confirmation
açısından farklı ele alınmalı: "yok" ise RCE'ye kadar gidilebilir,
"var ama gadget bulunamadı" ise yalnızca bilgi sızıntısı seviyesinde
kalınmalı). Custom filter/function/loader'lar sandbox'ı **genişletme**
veya **daraltma** yönünde etkileyebilir; bu nedenle "genel olarak X
engine sandboxludur" varsayımı yerine her hedefte ayrıca doğrulanmalıdır.

### 22. Version ve Environment Differences **[→ engines + fingerprinting]**

Aynı engine'in farklı sürümleri farklı sandbox varsayılanlarına, farklı
hata mesajı formatlarına ve farklı "gadget" erişilebilirliğine sahip
olabilir. Debug/development modu genelde daha ayrıntılı stack trace
verir (bu hem fingerprinting'i kolaylaştırır hem de bilgi sızıntısı
riskini artırır). Bir uygulamada birden fazla template engine bulunması
mümkündür (örn. ana sayfa Twig, e-posta alt sistemi Freemarker); bu
nedenle her render noktası **bağımsız olarak** fingerprint edilmelidir,
tek bir global varsayım kullanılmamalıdır.

### 23. Impact ve Confirmation **[→ workflow + reference]**

Confirmation, minimum ve **side-effect-free** kanıtla yapılmalıdır:
önce yalnızca bilgi sızdıran expression'lar (`{{config}}`, `{{self}}`,
ortam değişkeni okuma) denenir; yalnızca gerekliyse ve platform
politikası izin veriyorsa (bug bounty scope'unda "RCE demo" beklenen
bir kanıt biçimiyse) zararsız bir komut (`id`, `whoami`, `sleep 5`)
denenir — dosya silme/değiştirme, ağır DoS oluşturacak komutlar veya
kalıcı sistem değişikliği yapan hiçbir şey **asla** denenmemelidir.
Severity değerlendirmesi üç eksende yapılır: (a) sandbox var mı/aşıldı
mı, (b) yalnızca bilgi sızıntısı mı yoksa RCE'ye kadar gidiliyor mu,
(c) etkilenen veri/sistemin hassasiyeti (tek kullanıcı verisi mi,
sunucu genelinde mi).

### 24. SSTI Reporting **[→ reference]**

Rapor şu unsurları içermelidir: hedef URL/parametre, tespit edilen
template engine ve versiyon (varsa), kullanılan detection payload'ı ve
tam request/response (marker dahil), confirmation için kullanılan
ikinci bağımsız payload, beklenen ve gerçekleşen sonucun net
karşılaştırması, false-positive olmadığını gösteren negatif kontrol
kanıtı, severity gerekçesi. Gereksiz olan: RCE ile elde edilebilecek
zararlı komutların ayrıntılı listesi, hedef sistemin gereksiz iç
bilgilerinin (ilgisiz environment değişkenleri vb.) rapora eklenmesi —
yalnızca zafiyeti kanıtlamaya yetecek minimum bilgi paylaşılmalıdır.

### 25. Payload Database / Reference Yapısı **[→ tüm dosyalara dağıtık, bkz. Bölüm C]**

Payload'lar üç eksende etiketlenmelidir: **engine** (veya "generic"),
**amaç** (detection / fingerprinting / confirmation), **context**
(plain/HTML/attribute/string/expression). Her payload için tutulacak
metadata: engine, (varsa) minimum/maksimum versiyon, syntax, context,
amaç, beklenen sonuç, alternatif/eşdeğer syntax'lar, bilinen encoding
varyantları, risk seviyesi (safe/low/medium/high), false-positive
riski (düşük/orta/yüksek). Generic payload'lar `detection` dosyasında,
engine'e özgü payload'lar ilgili `engines/<engine>.md` dosyasında,
context'e göre seçim mantığı `context.md` dosyasında, encoding
varyantları ayrı bir alt bölüm olarak `detection.md` içinde
tutulmalıdır (ayrı "payloads/" klasörü kullanılmayacağı belirtildiği
için).

### 26 / 29. Eksik Attack Surface ve Modern Uygulamalar (No-Code/Low-Code dahil) **[→ workflow]**

Headless/API-first CMS'lerde SSTI genelde "içerik modelleme" alanlarında
(özel HTML blokları, e-posta şablon alanları) aranır; render genelde
API tüketen ayrı bir frontend'de değil, **backend'in kendi e-posta/
webhook/export özelliğinde** olur — bu nedenle "headless" olması SSTI
riskini ortadan kaldırmaz, render noktasını görünmez kılar (indirect
SSTI ile aynı mantık). Microservice mimarilerinde SSTI'nin bulunduğu
servis ile render'ın gerçekleştiği servis farklı olabilir; bu, zincir
haritalamayı servisler arası (API çağrıları, mesaj kuyrukları) takip
etmeyi gerektirir. Queue/worker sistemlerinde (Celery, Sidekiq, Bull)
render genelde **asenkron** olur — bu doğrudan Blind SSTI
metodolojisiyle örtüşür. No-code/low-code platformlar (form builder,
otomasyon araçları) kullanıcının kendi "formül/template" yazmasına
izin verdiği için **tasarım gereği** bir template motoruna erişim
sunar; buradaki asıl güvenlik sorusu "kullanıcı yalnızca kendi
verisine mi erişebiliyor yoksa sandbox'ı aşıp başka kullanıcıların
verisine/sunucu kaynaklarına mı ulaşabiliyor" sorusudur — bu, klasik
SSTI'den ziyade **yetki sınırları aşımı + SSTI** kombinasyonu olarak
değerlendirilmelidir.

### 28. Client-Side vs Server-Side Ayrımı (CSTI) **[→ detection, FP eliminasyonu içinde]**

`{{6666*6666}}` gibi bir payload'ın tarayıcıda (AngularJS/Vue gibi
client-side framework'lerin render ettiği) `44435556`'ya dönüşmesi
**SSTI değildir**; bu CSTI'dir ve tamamen farklı bir zafiyet sınıfıdır
(kapsam dışı). Ayrım şöyle yapılır: ham HTTP response (view-source /
curl çıktısı) incelenir — eğer `44435556` zaten **sunucudan gelen ham
HTML/JSON içinde** varsa SSTI'dir; eğer ham response'ta hâlâ
`{{6666*6666}}` yazıyor ve yalnızca tarayıcıda JavaScript çalıştıktan
sonra `44435556` görünüyorsa bu CSTI'dir. Agent, DOM'u render eden bir tarayıcı yerine ham HTTP
response üzerinden çalıştığı için bu ayrım genelde otomatik olarak
doğru çıkar, ancak headless-browser tabanlı bir tarama aracı
kullanılıyorsa bu kontrol **açıkça** yapılmalıdır.

### 31. Polyglot / Cross-Engine Probing **[→ detection]**

Engine bilinmediğinde tek bir istekte birden fazla delimiter ailesini
aynı anda test etmek için polyglot payload'lar kullanılabilir, örn.:
`${{<%[%'"}}%\.` gibi bir dizi, farklı motorlarda farklı parse
hatalarına veya kısmi evaluation'a yol açar; response'taki hata
mesajı/davranış farkı, hangi delimiter ailesinin "tanındığını" (parse
edilmeye çalışıldığını) gösterir. Bu, generic detection'ın ilk
turundan **önce**, çok düşük risk/maliyetle bir ön-eleme (triage) adımı
olarak kullanılabilir; kesin engine tespiti için hâlâ Bölüm 8'deki
karar ağacı gerekir.

### 32. Type Confusion / Object-Context SSTI **[→ context]**

Bazı SSTI'ler klasik "string içine gömülü template" modeline uymaz:
uygulama, kullanıcı girdisini doğrudan bir **attribute/özellik adı**
olarak template motoruna geçirir (örn. bir "sort by" parametresi
`{{ getattr(obj, user_input) }}` şeklinde arka planda kullanılıyorsa).
Bu durumda klasik delimiter probe'ları işe yaramaz; bunun yerine
motorun **attribute-access sözdizimi** (`.`, `[]`, `__class__` gibi)
doğrudan parametre değeri olarak denenmelidir. Bu, "hangi parametreler
zaten bir expression bağlamında kullanılıyor olabilir" sorusunu
Bölüm 5'teki parametre önceliklendirmesine ek bir kategori olarak
sokar: "sort", "filter", "field", "attr", "expr" gibi isimler bu
açıdan ayrıca işaretlenmelidir.

**Sınır çizgisi (önemli):** "Object/property access injection" ile
"SSTI'nin object/context kaynaklı varyantı" birbirine karıştırılmamalıdır.
`getattr(obj, user_input)` gibi bir kod yolunun varlığı **tek başına**
SSTI değildir — bu genel bir unsafe attribute/property access
problemidir ve etkisi (hangi attribute'lara erişilebildiği) tamamen
farklı bir değerlendirme gerektirir. Bunun bir SSTI varyantı sayılması
için, erişilen attribute zincirinin gerçekten **template engine'in
expression/evaluation mekanizmasına** geri bağlanması gerekir (örn.
`__class__.__mro__` üzerinden bir gadget zincirine ulaşıp kod
çalıştırma potansiyeli doğurması). Yalnızca rastgele bir attribute'un
okunabilmesi (örn. `obj.some_field`) genel bir bilgi ifşası/IDOR-benzeri
sorun olabilir; SSTI sınıflandırması için evaluation zincirine
bağlanan bir kanıt aranmalıdır.

**Agent karar akışı (netleştirilmiş):**

```
user input
    ↓
attribute/property access tespit edildi mi? (örn. sort=name → getattr(obj, name))
    ↓ evet
Bu tek başına SSTI DEĞİLDİR — henüz yalnızca bir
unsafe attribute/property access adayıdır.
    ↓
Attribute-access sözdizimi (`.`, `[]`, `__class__`, `__mro__` vb.)
parametre değeri olarak denenir
    ↓
Sonuç template engine'in EXPRESSION/EVALUATION
mekanizmasına geri bağlanan bir davranış üretiyor mu?
(örn. gadget zincirine ulaşma, kod çalıştırma potansiyeli,
template compile/parse hatası tetiklenmesi)
    ↓ evet                              ↓ hayır
SSTI (object-context varyantı)     Genel bilgi ifşası / IDOR-benzeri
olarak SSTI workflow'una girilir   sorun — SSTI olarak sınıflandırılmaz,
                                    ayrı bir zafiyet sınıfı olarak
                                    raporlanır (kapsamdaysa)
```

Bu akış, ssti-context.md dosyasına aktarılırken bire bir korunmalı;
agent'ın "attribute erişimi var → SSTI" gibi kestirme bir çıkarım
yapmasını engelleyen tek somut kontrol noktası budur.

### 33. Engine-Specific Escaping Filtreleri (WAF/Filter bağlamında) **[→ fingerprinting + detection]**

Her engine'in kendi "safe/escape" filtresi (Jinja2 `|safe`/`|escape`,
Twig `|raw`, Freemarker `?html`/`?no_esc`) hem bir fingerprint sinyali
(bir filtrenin kabul edilip edilmediği engine'i daraltır) hem de
filter-bypass bağlamında bir araçtır: uygulamanın kendi sanitizer'ı
belirli delimiter'ları temizliyorsa, filtre zincirleme (örn. Twig'de
`{{ '{{' }}` gibi kendi delimiter'ını dinamik üretme) veya yorum/
whitespace ekleyerek imza kırma teknikleri denenebilir. Bu teknikler
yalnızca **confirmed** bir SSTI şüphesi WAF tarafından engelleniyorsa,
ayrı ve sınırlı sayıda denemeyle uygulanmalıdır.

### 35. Source → Transformation → Sink Modellemesi **[→ workflow]**

Bir parametrenin var olması, SSTI'ye açık olduğu anlamına gelmez;
agent'ın asıl sorması gereken soru şudur: **"Bu input gerçekten
template engine sink'ine ulaşıyor mu?"** İki akış birbirinden
tamamen farklıdır:

```
(A) parametre → controller → sanitizer/serializer → database
       → business logic → template'e "değer" olarak enjekte edilir
       (SSTI değil, normal template kullanımı)

(B) parametre → (doğrudan veya string concatenation ile)
       → Template(user_input) / render_template_string(user_input)
       → template engine'in KAYNAK KODU olarak derlenir
       (SSTI adayı)
```

Kara-kutu (black-box) bug bounty testinde bu ayrımı doğrudan kod
okuyarak yapmak mümkün olmayabilir; bu yüzden agent, davranışsal
sinyallerle **dolaylı olarak** çıkarım yapar: (a) girdi değeri kısmen
değiştirilmiş (örn. delimiter'lar temizlenmiş) şekilde mi dönüyor —
bu, ham string'in bir yerlerde işlendiğine işaret eder; (b) girdiye
eklenen bozuk sözdizimi bir **template compile hatası** mı üretiyor
yoksa sadece "değer" olarak mı görünüyor; (c) girdi başka bir
kullanıcıya özgü template değişkeniyle etkileşime giriyor mu (örn.
`{{username}}` yazıldığında gerçek kullanıcı adı çıkıyorsa, bu
parametrenin expression bağlamında değerlendirildiğinin güçlü bir
göstergesidir). Source → Sink ilişkisi kurulamadan yalnızca "parametre
var" bilgisiyle SSTI iddia edilmemelidir; bu, generic detection
(Bölüm 6-7) ile birlikte çalışan tamamlayıcı bir doğrulama katmanıdır.

### 36. SSTI Sink Discovery **[→ workflow + reference]**

Agent yalnızca HTTP parametrelerini aramamalı, uygulamanın **render
sink'lerini** de (mümkün olduğu ölçüde: JS bundle'ları, API şema/
OpenAPI/GraphQL introspection çıktısı, hata mesajları, dosya adları,
response header'ları üzerinden dolaylı olarak) haritalandırmalıdır.
Aranacak örnek fonksiyon/API adı desenleri (engine/framework'e göre
değişir, bunlar yalnızca örnektir): `render()`, `render_template()`,
`render_template_string()`, `compile()`, `template()`, `Template()`,
`parse()`, `evaluate()`, `preview()`, `generate()`, `renderEmail()`,
`renderPdf()`, `renderReport()`. Kara-kutu testte bu isimler doğrudan
görülmez; ancak açık kaynak bileşenler (JS bundle, mobil app
decompile, public API dokümantasyonu, hata mesajlarındaki dosya
yolları/stack trace) üzerinden dolaylı sinyaller toplanabilir. Bu
sinyaller, Bölüm 5'teki risk skorlama modeline ek bir girdi olarak
kullanılmalı — bir endpoint hem yüksek öncelikli bir parametre adı
**hem de** bir render-sink işaretine sahipse öncelik daha da
artırılmalıdır.

### 34. CVE-Tabanlı Payload Deseni Araştırması **[→ engines, referans notu]**

Twig, Freemarker, Velocity, Thymeleaf ve Pebble için yıllar içinde
yayınlanmış public SSTI/SSTI-türevi CVE'ler (özellikle sandbox bypass
teknikleri), engine profillerindeki "confirmation" payload'larının
kaynağıdır. Skill dosyaları oluşturulurken her engine profiline "bilinen
sandbox-bypass deseni" alt başlığı eklenmesi, agent'ın sandbox'lı bir
hedefte confirmation başarısız olduğunda deneyebileceği ikinci bir
payload seti sağlar. (Bu doküman aşamasında somut CVE numaraları
listelenmemiştir; SKILL.md üretim aşamasında güncel kaynaklardan
doğrulanarak eklenmesi önerilir.)

---

## BÖLÜM C — İçeriğin Skill Dosyalarına Dağıtımı

Önerilen parçalanmış dosya yapısı ve her dosyaya giden içerik:

- **`ssti-core.md`** — Bölüm 1 (temel tanım, türler, oluşma koşulları),
  Bölüm B-28 (CSTI ayrımı — kısa özet, detay detection'da).
- **`ssti-workflow.md`** — Bölüm 3-5 (attack surface + öncelik skorlama),
  17-19 (recon→SSTI zinciri, karar ağacı), 23 (confirmation prensipleri
  ve etik sınırlar), 26/29 (modern mimari/no-code senaryoları), 30
  (confidence scoring, state yönetimi, request bütçesi), 35 (Source →
  Transformation → Sink modellemesi), 36 (SSTI Sink Discovery).
- **`ssti-detection.md`** — Bölüm 6-7 (generic detection + payload
  aileleri), 13-14 (encoding/WAF etkisi), 15-16 (FP/FN, evidence
  tablosu), 31 (polyglot probing), payload metadata şeması (Bölüm 25).
- **`ssti-fingerprinting.md`** — Bölüm 8 (karar ağacı), 22 (versiyon
  farkları), 33 (escaping filtreleri fingerprint sinyali olarak).
- **`ssti-context.md`** — Bölüm 9 (context tespiti), 32 (type
  confusion/object-context SSTI).
- **`ssti-engines/<engine>.md`** (her engine için ayrı dosya veya
  aile bazlı gruplanmış dosyalar, örn. `jinja-family.md`,
  `java-family.md`, `ruby-node-family.md`, `dotnet-go-family.md`) —
  Bölüm 2 (dil→engine haritası), 20 (engine profil tablosu ve
  detaylandırılmış hali), 21 (sandbox), 34 (CVE desenleri).
- **`ssti-reference.md`** — Bölüm 10 (CMS/framework eşlemesi), 24
  (raporlama şablonu), 25 (payload organizasyon prensipleri — somut
  payload listeleri ilgili detection/engine dosyalarında tutulur, bu
  dosyada yalnızca "nerede ne var" indeksi bulunur).

Bu doküman henüz bir SKILL.md değildir; talebiniz üzerine bir sonraki
adımda bu yapı doğrultusunda gerçek SKILL.md ve alt dosyalar
oluşturulabilir.
