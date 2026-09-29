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
