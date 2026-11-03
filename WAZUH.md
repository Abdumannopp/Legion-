# Wazuh → Legion integratsiyasi

Wazuh menejeri xavfsizlik hodisasini aniqlaganda uni Legion'ga yuboradi.
Legion uni alertga aylantiradi va WebSocket orqali dashboardga jonli uzatadi.

```
Wazuh agent → Wazuh manager → custom-legion → POST /security-events/webhook → Legion → dashboard
```

---

## 1. Legion tomonida webhook kalitini yarating

Har bir tashkilotning **o'z tasodifiy kaliti** bor: `KEY_ID:SECRET`
(`whk_…:whs_…`). Umumiy sir yo'q. Kalitni Legion administratori yaratadi va
**sir faqat bir marta ko'rsatiladi**. Server shifrlash kaliti
(`WEBHOOK_ENCRYPTION_KEY`, `npm run setup` yaratadi) sirlarni bazada shifrlab
saqlaydi.

Server konsolidan (tenant ID kerak — 2-qadam):

```bash
npm run webhook:credential -w server -- create --tenant TENANT_ID --label "wazuh-manager-1"
```

yoki administrator sifatida API orqali: `POST /security-events/credentials`.

**Muhim:** kalit bo'lmasa, tashkilot nomidan hech narsa qabul qilinmaydi (401).
Legion'ni qayta ishga tushirish shart emas.

---

## 2. Tenant ID ni oling

```bash
# DATABASE_URL — server/.env dagi qiymat
psql "$DATABASE_URL" -c "SELECT id, name FROM tenants;"
```

Yoki Settings sahifasidagi "Tashkilot ID". Tenant ID endi faqat kalit
yaratishda kerak; Wazuh uni **yubormaydi** — tashkilot kalitning o'zidan aniqlanadi.

---

## 3. Skriptlarni Wazuh menejeriga ko'chiring

Ikkala fayl ham kerak — Wazuh kengaytmasiz nomni chaqiradi, u esa `.py` ni ishga tushiradi.

```bash
cp integrations/custom-legion     /var/ossec/integrations/
cp integrations/custom-legion.py  /var/ossec/integrations/

chmod 750 /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py
chown root:wazuh /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py
```

Ruxsatlar noto'g'ri bo'lsa Wazuh skriptni umuman ishga tushirmaydi.

---

## 4. `ossec.conf` ga qo'shing

`/var/ossec/etc/ossec.conf` faylida, `<ossec_config>` ichiga:

```xml
<integration>
  <name>custom-legion</name>
  <hook_url>http://LEGION_MANZILI:8000/security-events/webhook</hook_url>
  <api_key>whk_XXXXXXXXXXXXXXXXXXXXXX:whs_YYYYYYYY…</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

| Maydon | Izoh |
|---|---|
| `hook_url` | Legion API manzili — ishlab chiqarishda **`https://`**. [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md) bo'yicha o'rnatilgan bo'lsa: `https://DOMENINGIZ/api/security-events/webhook`. Wazuh Legion bilan bir serverda bo'lsa `http://127.0.0.1:8000/security-events/webhook` |
| `api_key` | 1-qadamda chiqqan `KEY_ID:SECRET`, ikki nuqta bilan ajratilgan |
| `level` | Shu darajadan yuqori alertlar yuboriladi. `7` — oqilona boshlanish |
| `alert_format` | **Albatta `json`** bo'lishi kerak |

Wazuh'ni qayta ishga tushiring:

```bash
systemctl restart wazuh-manager
```

---

## 5. Tekshirish

**Loglar:**

```bash
tail -f /var/ossec/logs/integrations.log
```

Muvaffaqiyatli natija:

```
legion: OK rule=5720 status=202 {"status":"ingested","alert_id":"SEC-123559EACCF4DC48"}
```

**Qo'lda sinov** (Wazuh'ni kutmasdan):

```bash
python3 /var/ossec/integrations/custom-legion.py \
  /tmp/test-alert.json \
  "whk_XXXX…:whs_YYYY…" \
  "http://localhost:8000/security-events/webhook"
```

---

## Daraja (level) → Legion muhimligi

| Wazuh level | Legion severity |
|---|---|
| 12+ | critical |
| 9–11 | high |
| 5–8 | medium |
| 0–4 | low |

---

## Mumkin bo'lgan javoblar

| Javob | Ma'nosi | Yechim |
|---|---|---|
| `202 ingested` | Alert qabul qilindi | — |
| `202 skipped, duplicate` | Aynan shu hodisa allaqachon bor | Normal holat |
| `202 skipped` | `rule.description` bo'sh | `alert_format` `json` ekanini tekshiring |
| `401 Invalid webhook credentials` | Kalit noto'g'ri, **bekor qilingan** yoki muddati tugagan (ataylab bir xil javob) | `api_key` ni tekshiring; kerak bo'lsa yangi kalit yarating |
| `401 … too far from this server's clock` | Wazuh serverining soati noto'g'ri | Wazuh serverida NTP'ni yoqing |
| `401 This request was already received` | Aynan shu so'rov qayta yuborildi (replay) | Skript har urinishda yangi nonce ishlatadi; qo'lda qayta yubormang |
| `401 … script is out of date` | Eski `custom-legion.py` yoki `TENANT_ID:SECRET` formati | Yangi skriptni o'rnating, 1-qadamdagi kalitni qo'ying |
| `401 Malformed webhook authentication headers` | Sarlavha formati buzilgan | Rasmiy skriptdan foydalaning |

---

## Xavfsizlik eslatmasi

Ishlab chiqarishda (production) Legion'ni **HTTPS** orqasiga qo'ying —
`deploy/nginx.conf` da namuna bor. Legion API'ni standart holatda faqat
`127.0.0.1` da tinglaydi (`LEGION_BIND_ADDRESS`), ya'ni boshqa serverdagi
Wazuh unga faqat HTTPS proxy orqali yeta oladi — bu ataylab qilingan.

Autentifikatsiya: har bir xabar **imzolanadi**, sir tarmoq orqali yuborilmaydi.
Sarlavhalar: `x-legion-key-id` (ochiq ID — tashkilot shundan aniqlanadi),
`x-legion-timestamp`, `x-legion-nonce` (har so'rovda yangi tasodifiy qiymat) va
`x-legion-signature` = `"v2=" + HMAC-SHA256(sir, "v2." + timestamp + "." + nonce
+ "." + xom_tana)`. Rad etiladi: o'zgartirilgan tana, boshqa xabar/kalit imzosi,
`WEBHOOK_MAX_SKEW_SECONDS` (5 daqiqa) dan eski/kelajakdagi vaqt, **oldin ko'rilgan
nonce (replay)**, bekor qilingan yoki muddati tugagan kalit. `x-tenant-id`
e'tiborga olinmaydi (bo'lsa, kalit egasiga mos bo'lishi shart).

## Kalitni almashtirish (rotate) va bekor qilish (revoke)

```bash
# yangi kalit; eskisi yana 24 soat ishlaydi (overlap)
npm run webhook:credential -w server -- rotate --tenant TENANT_ID --key whk_… --overlap-hours 24
# darhol o'chirish
npm run webhook:credential -w server -- revoke --tenant TENANT_ID --key whk_…
# hodisa (incident): tashkilotning barcha kalitlari
npm run webhook:credential -w server -- revoke-all --tenant TENANT_ID
```

Tartib: rotate → `ossec.conf` dagi `<api_key>` ni yangilang →
`systemctl restart wazuh-manager` → eski kalit muddati o'zi tugaydi (yoki revoke).
API: `GET/POST /security-events/credentials`, `POST …/:id/rotate`, `DELETE …/:id`.

## Ma'lum cheklovlar

1. ~~Sarlavha — doimiy parol~~, ~~bitta global sir~~, ~~replay himoyasi yo'q~~ —
   **tuzatildi (2026-09-29)**: har kalit tasodifiy va alohida, tenant kalitdan
   aniqlanadi, nonce Postgres'da eslab qolinadi, rotate/revoke bor.
2. **Kalit shifrlash kaliti (KEK) hali `.env` da**, secret manager/KMS'da emas
   (ADR-003). `.env` va DB zaxirasi birga sizsa, kalitlar ochiladi.
3. **Rate limit yo'q:** noto'g'ri imzoli so'rovlar har biri bitta DB so'rovi
   (kalit ID bo'yicha) va HMAC hisoblaydi. Nginx/WAF darajasida cheklang.
4. **Sensor tomonda sir ochiq matnda** (`ossec.conf`, fayl huquqlari bilan
   himoyalangan). Wazuh serveri buzilsa, faqat **shu tashkilotning** kaliti
   ketadi — uni revoke qiling.
5. `http://` orqali yuborilsa, tana ochiq ko'rinadi (imzo uni yashirmaydi).
   Production'da HTTPS shart.

---

## Legion unreachable: nothing is lost (spool)

When Legion cannot be reached (restart, outage, network) or answers 5xx/429,
`custom-legion.py` retries a few times and then **keeps the event on disk**
in `/var/ossec/tmp/legion-spool/<key id>/` (owner-only permissions; the secret
is never written). The next alert re-sends the backlog first, oldest first,
signed afresh. Legion de-duplicates by event id, so a re-send is never a
second alert, and the original Wazuh `timestamp` is kept as the alert's
`occurred_at`.

For quiet periods, run the drain every minute on the manager:
`deploy/wazuh-legion-drain.service` + `.timer` (instructions inside).

- Each credential has its own spool: one organisation's backlog is never sent
  with another organisation's credential.
- An event Legion **refuses** (401/403 — e.g. a revoked credential — or 400)
  is kept in `<key id>/dead/`, not retried. After rotating a credential,
  re-send what the old one could not deliver:
  `custom-legion.py --drain <new KEY_ID:SECRET> <hook_url> --from <old key id>`
- The spool holds at most `LEGION_SPOOL_MAX_FILES` events (50 000); beyond
  that the oldest are dropped and the integration log says so.

---

## Avtomatik javob: hujumchini Wazuh orqali bloklash

Avtomatlashtirilgan va AI yordamidagi hujumlar bir necha soniyada o'nlab
urinish qiladi. Legion bog'liq ogohlantirishlarni **hujum kampaniyalariga**
birlashtiradi (Dashboard → **Himoya**) va xohlasangiz hujumchi manzilini Wazuh
menejeringiz orqali **taxminan bir daqiqada** bloklaydi.

### Legion nimani "kampaniya" deb biladi

| Qoida | Shart | Avtomatik bloklanadimi |
|---|---|---|
| Tez ko'p bosqichli hujum (`rapid_chain`) | bitta manzildan 15 daqiqada ≥ 3 xil MITRE usuli | ha |
| Ko'p serverlarni aylanib chiqish (`wide_sweep`) | bitta manzildan 10 daqiqada ≥ 5 server | ha |
| Keskin faollik (`velocity`) | bitta manzildan 5 daqiqada ≥ 30 ogohlantirish | ha |
| Parol hujumi (`credential_attack`) | bitta manzildan 10 daqiqada ≥ 10 ta muvaffaqiyatsiz kirish yoki ≥ 5 xil hisobga urinish | ha |
| Hisob buzib kirildi (`account_compromise`) | o'sha manzil ≥ 3 xatodan keyin 30 daqiqa ichida hisobga kirdi | ha (hujumchi manzili) |
| Ko'p manzil, bitta server (`swarm`) | 10 daqiqada ≥ 10 manzil bitta serverga | **yo'q** (manzillar juda ko'p; bu DDoS — EDGE-SECURITY.md) |
| AI'ni aldashga urinish (`ai_manipulation`) | log ichida AI'ga buyruq ("ignore previous instructions", yashirin belgilar, model tokenlari…) | **yo'q** (manzil emas, matn) |

Har bir yangi kampaniya — **bitta** ogohlantirish ("Hunter" agenti), har
urinish uchun alohida emas.

### Xavfsizlik chegaralari (o'chirib bo'lmaydi)

- Standart holatda **o'chiq** — faqat aniqlaydi va xabar beradi. Yoqishni
  administrator Himoya sahifasida qiladi (audit jurnalida yoziladi).
- Faqat **ommaviy** IP manzillar: ichki (10.x, 192.168.x, 172.16–31.x),
  CGNAT, loopback, hujjat manzillari hech qachon avtomatik bloklanmaydi.
- **Istisnolar ro'yxati** (o'z ofisingiz, hamkorlar, skanerlaringiz) — hech
  qachon avtomatik bloklanmaydi.
- Soatiga ko'pi bilan **50** avtomatik bloklash, bir vaqtda ko'pi bilan **1000**.
- Har bir bloklash muddatli (5 daqiqa – 7 kun, standart 1 soat), audit
  jurnalida yoziladi va Himoya sahifasida bir tugma bilan bekor qilinadi.

### Wazuh menejerida bir martalik sozlash

```bash
# 1. Skript (3-bo'limdagi bilan bir xil) va qoida
cp integrations/wazuh/legion_rules.xml /var/ossec/etc/rules/legion_rules.xml
chown root:wazuh /var/ossec/etc/rules/legion_rules.xml

# 2. Sensor kaliti faylda (ossec.conf'dagi bilan bir xil KEY_ID:SECRET)
echo 'whk_...:whs_...' > /var/ossec/etc/legion.key
chown root:wazuh /var/ossec/etc/legion.key && chmod 640 /var/ossec/etc/legion.key

# 3. Wazuh o'qiydigan fayl — qayta ishga tushirishdan OLDIN
touch /var/ossec/logs/legion-blocklist.log
chown wazuh:wazuh /var/ossec/logs/legion-blocklist.log
```

4. `integrations/wazuh/ossec-legion-response.xml` dagi uchta blokni
   (`wodle`, `localfile`, `active-response`) `ossec.conf` ichiga qo'shing,
   `LEGION_URL` ni o'z `hook_url` ingiz bilan almashtiring.
5. `/var/ossec/bin/wazuh-analysisd -t` (xato yo'qligini tekshiring), keyin
   `systemctl restart wazuh-manager`.

Tekshirish: `/var/ossec/logs/integrations.log` da har daqiqada
`BLOCKLIST n active, m sent to active response` qatori chiqadi.

### Qanday ishlaydi

1. Har daqiqada Wazuh `custom-legion.py --sync-blocklist` ni ishga tushiradi;
   u Legion'dan **imzolangan** so'rov bilan ro'yxatni oladi (faqat shu
   tashkilotniki).
2. Yangi manzil uchun `legion-blocklist.log` ga bitta JSON qator yozadi.
3. Wazuh qoida 100950 shu qatorni ko'radi va `firewall-drop` active
   response'ni **barcha agentlarda** ishga tushiradi.
4. Wazuh bloklashni `<timeout>` (600 s) dan keyin o'zi olib tashlaydi.
   Legion hali bloklashni xohlasa, skript manzilni har 5 daqiqada qayta
   e'lon qiladi — shuning uchun blok uzilmaydi.
5. Legion'da blokdan chiqarsangiz, skript e'lon qilishni to'xtatadi va Wazuh
   uni ko'pi bilan **10 daqiqada** olib tashlaydi.

Legion'ning o'z bloklash hodisalari (guruh `legion_response`) Legion'ga yangi
ogohlantirish bo'lib qaytib kelmaydi — ikki tomonda ham tekshiriladi.

### Halol cheklovlar

- **Hech bir tizim barcha hujumlarni to'xtatmaydi.** Bu tezlikni oshiradi:
  odam ogohlantirishni o'qishidan oldin hujumchi to'xtatiladi.
- Ko'p manzilli hujumni (botnet, DDoS) IP bloklash to'xtatmaydi — buning uchun
  Cloudflare kabi chekka himoya kerak (EDGE-SECURITY.md).
- Hujumchi log'dagi manzilni soxtalashtirishi mumkin (masalan, boshqa birovning
  IP'si yozilgan log qatori). Shuning uchun: faqat ommaviy manzillar, istisnolar
  ro'yxati, soatlik chegara va muddatli bloklar. O'z muhim manzillaringizni
  istisnolarga qo'shing.
- Bloklashni Wazuh agentlari bajaradi (`firewall-drop` → iptables). Agent
  yo'q yoki iptables bo'lmagan joyda blok ishlamaydi. Bizning avtomatik
  sinovimizda (`ops/tests/e2e-wazuh-response.mjs`, haqiqiy Wazuh 4.9.2)
  Wazuh `firewall-drop` ni ishga tushirgani tekshirildi; Docker obrazida
  iptables yo'qligi sababli yadro qoidasining o'zi tekshirilmadi.
- Yangi `legion-blocklist.log` fayli: Wazuh kech topgan faylni oxiridan o'qiydi.
  Yuqoridagi `touch` qadamini o'tkazib yuborsangiz, skript faylni o'zi yaratadi
  va 2 daqiqa kutadi — birinchi bloklash shuncha kechikadi.
