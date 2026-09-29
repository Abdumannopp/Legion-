# Legion — arxitektura qarorlari (ADR)

**Sana:** 2026-08-24
**Kontekst:** Production audit (2026-08-24) 26-bo'limida 10 ta ochiq qaror sanab o'tilgan.
Ular kod yozishdan **oldin** yopilishi kerak, chunki har biri keyingi ishning shaklini belgilaydi.

Har bir qaror uchun: bugun kodda nima bor, variantlar, tavsiyam va kim hal qilishi kerak.

> **Belgilar**
> 🔧 — men tavsiya bera olaman, texnik qaror
> 💼 — biznes/yuridik qaror, buni siz hal qilasiz
> ⛔ — boshqa ishlarni bloklaydi

---

## ADR-001 ⛔💼 Identity: bitta odam = bitta tashkilotmi?

**Bugun kodda:** `users.email` **global unique**, har foydalanuvchida bitta `tenant_id`.
`index.ts` da `user.tenant_id` **44 joyda** ishlatiladi.

Amaliy oqibat: bir odam ikkita Legion workspace'ida bo'la olmaydi. Uchta mijozni
kuzatadigan MSSP analitigi, yoki ikkita kompaniyada ishlaydigan konsultant —
hozirgi modelda **mavjud bo'la olmaydi**. Taklif oqimi ham `400 — bu email
allaqachon ishlatilmoqda` qaytaradi.

| Variant | Ma'nosi | Narxi |
|---|---|---|
| **A. Hozirgicha qoldirish** | 1 email = 1 tashkilot | 0. Lekin MSSP bozori yopiladi |
| **B. `identities` + `memberships`** | 1 email = N tashkilot, rol har biriga alohida | Katta: auth, RBAC, taklif, sessiya va 44 ta so'rov joyi |

**Tavsiyam:** bu **texnik emas, savdo qarori**. Javob "kim sotib oladi?" degan savolga
bog'liq:

- Xaridor **Wazuh o'rnatgan, SOC jamoasi yo'q SMB** bo'lsa → **A** yetarli, hozircha qoldiring.
- Xaridor **MSSP yoki konsalting firmasi** bo'lsa → **B** majburiy, va uni **hozir**
  qilish kerak. Keyinroq qilish 44 ta joyni qayta yozish demak, ustiga ishlab turgan
  mijoz ma'lumoti bilan migratsiya.

Yo'l xaritasida bu savolni ochiq qoldirgan edik. Endi u eng qimmat qarorga aylandi —
avval shunga javob bering.

---

## ADR-002 ⛔🔧 Durable queue: nima ishlatamiz?

**Bugun kodda:** queue yo'q. Alert ingestion HTTP so'rov ichida DB yozadi, email
yuboradi va AI chaqiradi. Sekin vendor = sekin webhook = Wazuh timeout.

Redis allaqachon ishlatiladi: `ratelimit.ts` va `realtime.ts`.

| Variant | Foyda | Kamchilik |
|---|---|---|
| **Redis Streams** | Consumer group, ack, DLQ — mavjud Redis bilan | Redis'ni durable qilish kerak |
| **Boshqariladigan queue** (SQS, Pub/Sub) | Operatsion yuk yo'q, kafolatlangan durability | Yangi vendor, cloud'ga bog'lanish |
| **Postgres outbox + poller** | Yangi infratuzilma yo'q, tranzaksion kafolat | Yuqori yukda DB'ga bosim |

**Tavsiyam: Redis Streams** — ikkita komponent uchun allaqachon Redis bor,
uchinchisini qo'shish yangi vendor keltirmaydi.

> ⚠️ **Diqqat — bu mening o'zim qo'ygan tuzoq.** `docker-compose.yml` da Redis shunday:
> ```yaml
> command: ["redis-server", "--save", "", "--appendonly", "no"]
> ```
> Persistence **ataylab o'chirilgan**, chunki men uni faqat rate-limit hisoblagichi
> uchun qo'shgandim (izohda ham shunday yozilgan). Agar Redis queue ham bo'lsa,
> bu konfiguratsiya **restartda ishlarni yo'qotadi**. Queue qo'shilsa, AOF yoqilishi
> shart — yoki queue uchun alohida Redis instansiyasi.

---

## ADR-003 ✅ Webhook siri qanday saqlanadi?

> **Hal qilindi (2026-09-29):** har credential uchun tasodifiy 256-bit sir
> (`webhook_credentials`), AES-256-GCM bilan shifrlangan; KEK — `WEBHOOK_ENCRYPTION_KEY`
> env (yo'q bo'lsa `JWT_SECRET`'dan HKDF). Tenant credential'ning o'zidan aniqlanadi
> (`x-legion-key-id`), imzo = HMAC-SHA256 over `v2.<ts>.<nonce>.<xom tana>`, nonce
> Postgres'da eslab qolinadi (replay), rotate — overlap bilan, revoke — darhol.
> Qolgan qism: KEK hali secret manager/KMS'da emas (pastdagi "Tavsiyam" 2-bosqichi).
> Quyidagi matn qaror qabul qilingan paytdagi holat.

**Bugun kodda:** `HMAC(GLOBAL_SECRET, tenantId)` — ya'ni bitta global sirdan har
tenant uchun credential hosil qilinadi. Global sirni bilgan odam **istalgan tenant
uchun** credential yasay oladi.

Muhim nuance: sir HMAC tekshiruvi uchun **qayta o'qilishi** kerak, shuning uchun
parol kabi hash qilib bo'lmaydi — u shifrlanishi kerak.

| Variant | Baho |
|---|---|
| Har credential uchun tasodifiy sir, ochiq matnda DB'da | Global sir muammosini yechadi, lekin DB sizsa hammasi ochiladi |
| **Envelope encryption (KEK bilan)** | DB sizsa ham sirlar ochilmaydi. KEK secret manager'da |
| Asimmetrik imzo (sensor privat kalit bilan) | Eng kuchli, lekin Wazuh tomonda murakkab |

**Tavsiyam:** envelope encryption. Bosqichma-bosqich: avval KEK'ni secret
manager'dan olinadigan env o'zgaruvchisi sifatida, keyinroq haqiqiy KMS'ga.
Wazuh integratsiyasi tomondan bu shunchaki yangi header'lar — `WAZUH.md` yangilanadi.

---

## ADR-004 🔧💼 To'lamagan tenant bilan nima qilamiz?

**Bugun kodda** (men yozganman): `ok` / `readonly` / `blocked` holatlar bor.
Muhim tanlov: **Wazuh webhook access gate'dan chiqarilgan** — ya'ni bloklangan
tenantning telemetriyasi yozilishda **davom etadi**.

Buni ataylab qildim: to'lov kechikkani uchun mijozning xavfsizlik tarixida
hech qachon to'ldirib bo'lmaydigan teshik qoldirish noto'g'ri. Lekin bu
**xarajat** demakdir — to'lamagan mijoz sizning diskingizni va (agar AI yoqilgan
bo'lsa) API byudjetingizni ishlatishda davom etadi.

**Tavsiyam:** hozirgi mantiqni saqlang, lekin ikkita chegara qo'shing:

1. `blocked` tenant uchun ingest **saqlanadi, lekin qayta ishlanmaydi** — AI
   tushuntirish va email yuborilmaydi (xarajat nolga tushadi, ma'lumot yo'qolmaydi).
2. `blocked` holatda kvota (masalan 30 kun yoki N hodisa), undan keyin yangi
   hodisalar rad etiladi va mijozga aniq xabar beriladi.

💼 Aniq raqamlar (necha kun, necha hodisa) — sizning qaroringiz. Va bu raqamlar
Terms hujjatida yozilgan bo'lishi kerak.

---

## ADR-005 💼 Tarif va kvota katalogi

**Bugun kodda:** kvota tushunchasi umuman yo'q. Har bir tenant cheksiz alert,
cheksiz AI so'rovi va cheksiz email ishlatadi.

Qaror qilinishi kerak: nima bo'yicha cheklaysiz — hodisa soni, saqlash muddati,
AI so'rovi, foydalanuvchi soni, asset soni?

**Tavsiyam (texnik shakli):** kvotalar kodda emas, **bazada versiyalangan
entitlement** sifatida. Aks holda har tarif o'zgarishi deploy talab qiladi va
mijozga individual chegara berib bo'lmaydi.

💼 Qiymatlarning o'zi — narx strategiyangiz. Men buni siz uchun hal qila olmayman.

---

## ADR-006 💼⚖️ Ma'lumot qayerda saqlanadi?

**Bugun kodda:** bitta `DATABASE_URL`. Ma'lumot qayerda bo'lsa — o'sha yerda.

EU mijozi birinchi savolda so'raydi. Rossiya, Xitoy va yana bir qancha
yurisdiksiyada bu qonuniy talab.

| Variant | Baho |
|---|---|
| **Bitta region** | Eng oddiy. "Ma'lumot X da saqlanadi" deb ochiq yozasiz |
| Regional tenancy | Har region uchun alohida deployment. Katta operatsion narx |

**Tavsiyam:** launch uchun **bitta region** tanlang va uni saytda ochiq yozing.
Regional tenancy'ni faqat shuni talab qiladigan mijoz pul to'lashga tayyor
bo'lganda quring.

⚖️ Qaysi region — bu yuridik maslahat talab qiladi. Men yurist emasman; maqsad
bozoringiz va mijozlaringiz yurisdiksiyasi bo'yicha maslahat oling.

---

## ADR-007 💼 RPO / RTO — qancha yo'qotishga rozisiz?

**Bugun kodda:** `ops/backup.sh` kunlik dump. Ya'ni **RPO ≈ 24 soat** — falokat
bo'lsa bir kunlik mijoz telemetriyasi yo'qoladi.

Tiklash protsedurasi sinalgan (`BACKUP.md`), lekin faqat sandbox'da.

**Tavsiyam:** boshqariladigan Postgres'da PITR yoqing → RPO daqiqalarga tushadi.
Bu 1 soatlik ish va kunlik dump'dan ko'ra ancha kuchli.

💼 Rasmiy maqsad raqami (mijozga va'da qiladiganingiz) — sizning qaroringiz.
Va'da qilishdan **oldin** o'lchang.

---

## ADR-008 🔧 Support xodimi mijoz ma'lumotini ko'ra oladimi?

**Bugun kodda:** hech qanday admin/support kirish mexanizmi **yo'q**. Siz
mijozning dashboard'ini ko'ra olmaysiz.

Bu bugun eng xavfsiz holat, lekin birinchi "menda nimadir ishlamayapti" murojaatida
muammo bo'ladi.

**Tavsiyam:** hozircha **hech narsa qurmang**. Kerak bo'lganda JIT (just-in-time)
model bilan quring: vaqt bilan cheklangan, MFA talab qiladigan, sabab yozishni
majburlaydigan va o'chirib bo'lmaydigan audit yozuvi qoldiradigan kirish.

Eng yomon variant — jimgina "super admin" bayrog'i qo'shish. Bu SOC 2 auditida
darhol savol tug'diradi va mijoz ishonchini yo'qotadi.

---

## ADR-009 🔧 CSP strategiyasi

**Bugun kodda:** `frontend/next.config.mjs` — hech qanday xavfsizlik header'i yo'q:

```js
const nextConfig = { reactStrictMode: true, output: "standalone" };
```

Ya'ni CSP, HSTS, `frame-ancestors` — hech biri yo'q. Backend'da `helmet` bor,
lekin u API javoblariga tegishli; brauzer sahifasini frontend beradi.

Murakkablik: Paddle checkout `@paddle/paddle-js` orqali Paddle CDN'dan skript
yuklaydi va checkout'ni iframe sifatida ochadi. Ya'ni CSP allowlist kerak.

**Tavsiyam:** Next.js'ning rasmiy nonce naqshi + minimal Paddle allowlist.
Avval `Content-Security-Policy-Report-Only` bilan chiqaring, hisobotlarni
kuzating, keyin majburiy qiling. Darhol enforce qilish checkout'ni sindirishi
mumkin va buni faqat to'layotgan mijoz aniqlaydi.

---

## ADR-010 ⚖️ AI ga mijoz ma'lumoti yuborilishi

**Bugun kodda** (`ai.ts`): Groq'ga alert sarlavhasi, `summary` (2000 belgigacha),
`source_ip`, `target` (hostname) va MITRE texnikasi yuboriladi. Copilot uchun
oxirgi 30 alert konteksti ham.

Ya'ni **mijozning xavfsizlik telemetriyasi uchinchi tomon AI provayderiga
uzatiladi**. Hostname va IP — ko'p yurisdiksiyada shaxsiy ma'lumot hisoblanadi.

Hozir bu hech qayerda oshkor qilinmagan va mijoz uni o'chira olmaydi.

**Tavsiyam:**

1. Maxfiylik siyosatida **ochiq yozing**: qaysi provayder, qanday ma'lumot, qancha saqlanadi.
2. Tenant darajasida **o'chirish tugmasi** bering (o'chirilganda deterministik
   fallback ishlaydi — u allaqachon yozilgan).
3. Groq bilan DPA imzolang yoki zero-retention rejimi borligini tasdiqlang.

⚖️ Bu GDPR nuqtai nazaridan jiddiy — mijozning ma'lumotini sub-processor'ga
uzatyapsiz. Yurist bilan maslahatlashing; men yurist emasman.

---

## Xulosa: nima birinchi hal bo'lishi kerak

| Qaror | Kim | Nega shoshilinch |
|---|---|---|
| **ADR-001** identity | 💼 siz | Eng qimmat. Keyin qilish 44 ta joyni qayta yozish |
| **ADR-006** region | ⚖️ siz + yurist | Deployment shaklini belgilaydi |
| **ADR-010** AI siyosati | ⚖️ siz + yurist | Bugun oshkor qilinmagan holda ishlayapti |
| ADR-002 queue | 🔧 men tavsiya berdim | Boshqa P0 ishlar shunga quriladi |
| Qolganlari | aralash | Yuqoridagilardan keyin |

Uchta 💼/⚖️ qaror hal bo'lmaguncha, texnik ishni boshlash **erta** — chunki
ADR-001 ning javobi keyingi barcha kodning shaklini belgilaydi.
