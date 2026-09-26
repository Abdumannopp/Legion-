# Wazuh → Legion integratsiyasi

Wazuh menejeri xavfsizlik hodisasini aniqlaganda uni Legion'ga yuboradi.
Legion uni alertga aylantiradi va WebSocket orqali dashboardga jonli uzatadi.

```
Wazuh agent → Wazuh manager → custom-legion → POST /security-events/webhook → Legion → dashboard
```

---

## 1. Legion tomonida sirni yoqing

Docker bilan o'rnatilgan bo'lsa (`./install.sh`), sir **allaqachon yaratilgan** —
`.env` faylidagi `SECURITY_EVENT_WEBHOOK_SECRET`. Hech narsa qilish shart emas.

Node.js yo'lida `server/.env` faylida:

```env
SECURITY_EVENT_WEBHOOK_SECRET=uzun-tasodifiy-satr-shu-yerga
```

Tasodifiy sir yaratish:

```bash
openssl rand -hex 32
```

**Muhim:** sir bo'sh bo'lsa, webhook `503` qaytaradi va butunlay o'chiq bo'ladi.

Legion'ni qayta ishga tushiring — Docker: `./install.sh`, Node.js: `npm start`.
(`npm run dev` — faqat dasturchi uchun, ishlab turgan serverda ishlatmang.)

---

## 2. Tenant ID ni oling

Legion 2.0 dan beri ma'lumot PostgreSQL'da saqlanadi — eski
`server/data/legion.json` fayli **endi yo'q**, undan ID olib bo'lmaydi.

```bash
# Docker bilan o'rnatilgan bo'lsa
docker compose exec postgres psql -U legion -d legion -c "SELECT * FROM tenants;"

# Node.js yo'lida (DATABASE_URL — server/.env dagi qiymat)
psql "$DATABASE_URL" -c "SELECT * FROM tenants;"
```

`id` ustunidagi qiymat kerak. U shunga o'xshash bo'ladi:
`9fb5aede-cbb0-40c2-b95c-44fc17517d5b`

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
  <api_key>TENANT_ID:SIZNING_SIRINGIZ</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

| Maydon | Izoh |
|---|---|
| `hook_url` | Legion API manzili — ishlab chiqarishda **`https://`** (pastdagi eslatmaga qarang). Wazuh shu serverda bo'lsa `http://127.0.0.1:8000/...` |
| `api_key` | `TENANT_ID` va sir, ikki nuqta bilan ajratilgan |
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
  "TENANT_ID:SIZNING_SIRINGIZ" \
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
| `401 Invalid webhook signature` | Sir yoki tenant ID noto'g'ri | `api_key` ni qayta tekshiring |
| `400 Unknown tenant` | Tenant ID bazada yo'q | 2-qadamdagi ID ni qayta oling |
| `503 webhook is disabled` | `SECURITY_EVENT_WEBHOOK_SECRET` bo'sh | 1-qadamni bajaring |

---

## Xavfsizlik eslatmasi

Ishlab chiqarishda (production) Legion'ni **HTTPS** orqasiga qo'ying —
`deploy/nginx.conf` da namuna bor. Docker o'rnatmasi API'ni standart holatda
faqat `127.0.0.1` da tinglaydi, ya'ni boshqa serverdagi Wazuh unga faqat
HTTPS proxy orqali yeta oladi — bu ataylab qilingan.

Autentifikatsiya: `x-security-event-secret` sarlavhasi = `HMAC(sir, tenant_id)`.

## Ma'lum cheklovlar (2026-09 audit)

Bular hujjatlar va sozlamalar asosida aniqlangan; server kodi tekshiruvga
berilmagan, shuning uchun kod tuzatilmaguncha ular **ochiq** hisoblanadi.

1. **Sarlavha — doimiy parol, imzo emas.** Qiymat faqat tenant ID dan
   hisoblanadi: so'rov tanasi, vaqt va nonce'ni qamramaydi va hech qachon
   o'zgarmaydi. Uni bir marta ko'rgan (log, proxy, HTTP trafigi) odam istalgan
   soxta alertni yubora oladi yoki eski so'rovni qayta yubora oladi.
2. **Bitta global sir.** Barcha tenantlarning sarlavhasi bitta
   `SECURITY_EVENT_WEBHOOK_SECRET` dan chiqadi. Sirni bilgan odam istalgan
   tenant nomidan alert yubora oladi (`ADR-QARORLAR.md`, ADR-003).
3. **Wazuh o'zi qayta urinmaydi.** `integratord` har alert uchun skriptni bir
   marta ishga tushiradi. Legion o'sha paytda ishlamay tursa (yangilash,
   qayta ishga tushirish, baza uzilishi), `custom-legion.py` o'zi navbatga
   yozmasa, alert Legion'ga **hech qachon yetmaydi**. Skript tekshiruvga
   berilmagan — buni birinchi navbatda tekshiring.
4. **`202 skipped, duplicate` ≠ "hammasi yetkazildi".** Birinchi urinishda
   alert bazaga yozilib, email yoki jonli bildirishnoma xato bilan tugagan
   bo'lsa, qayta yuborilgan hodisa "dublikat" deb o'tkazib yuboriladi va
   bildirishnoma qayta urinilmaydi.

Tavsiya etilgan tuzatish (server kodida): har tenant uchun alohida,
shifrlangan sir; imzo = `HMAC(sir, timestamp + "." + xom_tana)`; 5 daqiqalik
vaqt oynasi va nonce/hodisa ID bo'yicha replay himoyasi; bildirishnomalarni
alert bilan bir tranzaksiyada yoziladigan "outbox" jadvali orqali qayta
urinish bilan yuborish.
