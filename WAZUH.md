# Wazuh → Legion integratsiyasi

Wazuh menejeri xavfsizlik hodisasini aniqlaganda uni Legion'ga yuboradi.
Legion uni alertga aylantiradi va WebSocket orqali dashboardga jonli uzatadi.

```
Wazuh agent → Wazuh manager → custom-legion → POST /security-events/webhook → Legion → dashboard
```

---

## 1. Legion tomonida sirni yoqing

`server/.env` faylida:

```env
SECURITY_EVENT_WEBHOOK_SECRET=uzun-tasodifiy-satr-shu-yerga
```

Tasodifiy sir yaratish:

```bash
openssl rand -hex 32
```

**Muhim:** sir bo'sh bo'lsa, webhook `503` qaytaradi va butunlay o'chiq bo'ladi.

Legion'ni qayta ishga tushiring:

```bash
npm run dev
```

---

## 2. Tenant ID ni oling

Har bir Legion o'rnatmasida tenant (tashkilot) ID si bo'ladi:

```bash
# Linux / macOS
cat server/data/legion.json | python3 -c "import json,sys; print(json.load(sys.stdin)['tenants'][0]['id'])"
```

```powershell
# Windows PowerShell
(Get-Content server\data\legion.json | ConvertFrom-Json).tenants[0].id
```

Natija shunga o'xshash bo'ladi: `9fb5aede-cbb0-40c2-b95c-44fc17517d5b`

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
| `hook_url` | Legion API manzili. Lokal sinov uchun `http://localhost:8000/...` |
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
`deploy/nginx.conf` da namuna bor. Sir HTTP orqali ochiq yuborilmasligi kerak.

Autentifikatsiya HMAC-SHA256 imzosi orqali: imzo = `HMAC(sir, tenant_id)`.
Skript imzoni har safar o'zi hisoblaydi, shuning uchun `ossec.conf` da
faqat sir saqlanadi.
