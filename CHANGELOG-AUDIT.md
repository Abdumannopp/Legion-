# Legion — audit tuzatishlari

**Sana:** 2026-08-20
**Kontekst:** jahon bozori uchun SaaS. Auditda topilgan uchta "uzilgan zanjir" va xavfsizlik kamchiliklari tuzatildi.

Tekshiruv holati: `tsc` toza (server + frontend), **96 ta test real Postgres'da o'tadi**, `next build` muvaffaqiyatli, `npm audit` — 0 zaiflik.

> **2.1 (2026-08-21):** backup, Redis rate limit, MFA va refresh token qo'shildi — 8-bo'limga qarang.

---

## 1. Jamoa zanjiri ulandi — RBAC endi jonli

Ilgari `POST /users` umuman yo'q edi: har bir mijozda abadiy bitta foydalanuvchi qolardi va `analyst`/`viewer` rollari hech qachon yaratilmasdi.

**Yangi endpointlar**

| Endpoint | Kim | Vazifasi |
|---|---|---|
| `POST /users/invite` | admin | Email + rol bo'yicha taklif yaratadi va yuboradi |
| `POST /users/:id/resend-invite` | admin | Yangi token bilan qayta yuboradi (eski link o'ladi) |
| `POST /auth/accept-invite` | ochiq | Parol o'rnatadi, **mavjud** tenantga qo'shiladi |
| `GET /auth/invite/:token` | ochiq | Qabul qilish sahifasi uchun ko'rib chiqish |
| `DELETE /users/:id` | admin | Hisobni **deaktivatsiya** qiladi (o'chirmaydi) |
| `POST /auth/change-password` | har kim | Kirgan foydalanuvchi parolini almashtiradi |

**Muhim qarorlar**

- `/auth/accept-invite` `/auth/register` dan butunlay alohida yo'l. Register doim **yangi tenant** yaratadi; taklif esa **mavjud tenantga** qo'shadi. Ular chalkashsa, taklif qilingan odam o'z workspace'ini yaratib qo'yardi.
- O'chirish emas, deaktivatsiya: audit jurnalidagi yozuvlar foydalanuvchiga havola qiladi va ular haqiqiy shaxsga yechilishi kerak. `status: "disabled"` + `token_version += 1` → seanslar darhol uziladi.
- "Kamida bitta admin" qoidasi endi **faol** adminlarni sanaydi — deaktivatsiya qilingan admin hisobga olinmaydi (ilgari bu teshik bor edi).
- Email login identifikatori bo'lgani uchun u barcha tenantlar bo'ylab noyob.

**Frontend:** `/accept-invite` sahifasi, Settings → Team'da taklif formasi, rol tanlash, qayta yuborish va deaktivatsiya tugmalari, status belgilari.

---

## 2. Pul zanjiri ulandi — obuna endi haqiqatan cheklaydi

Ilgari Paddle integratsiyasi obunani faqat **ko'rsatardi**. Bekor qilingan mijoz cheksiz foydalanishda davom etardi.

**Yangi `accessState(tenantId)` mantiqi**

| Holat | Natija |
|---|---|
| `active` yoki `trialing` obuna | `ok` — to'liq kirish |
| Obuna yo'q, sinov muddati davom etmoqda | `ok` |
| Obuna yo'q, sinov tugagan | `blocked` → `402` |
| `past_due` | `readonly` — `GET` ruxsat, yozish `402` |
| `paused` / `canceled` | `blocked` → `402` |

**Ataylab qilingan tanlovlar**

- **`/auth/*` va `/billing/*` hech qachon bloklanmaydi.** Kira olmaydigan yoki billing portalini ocha olmaydigan mijoz hech qachon qayta to'lay olmaydi.
- **Wazuh webhook hech qachon bloklanmaydi.** To'lov kechikkani uchun mijozning telemetriyasini tashlab yuborish uning xavfsizlik tarixida hech qachon to'ldirib bo'lmaydigan teshik qoldiradi. Billing UI'ni cheklaydi, hodisalarni yozishni emas.
- `past_due` qorong'ilik emas, **faqat o'qish**. To'lanmagan hisob-faktura tufayli jonli insidentni yashirish noto'g'ri savdo.
- `Tenant.trial_ends_at` alohida maydon — savdo sinov muddatini kodga tegmasdan uzaytira oladi.

**Frontend:** `AccessBanner` komponenti (dashboard + settings). Normal holatda **hech narsa ko'rsatmaydi** — doim turadigan banner o'qilmay qoladi. Sinovga 5 kun qolganda, `readonly` va `blocked` holatlarda paydo bo'ladi.

---

## 3. AI zanjiri ulandi — Copilot endi savolni o'qiydi

Ilgari `/copilot/chat` `body.message` ni parse qilardi va **umuman ishlatmasdi** — nima so'ralishidan qat'i nazar bir xil shablon javob qaytarardi.

Yangi `server/src/ai.ts`:

- Copilot foydalanuvchi savolini, suhbat tarixini (oxirgi 10 xabar) va tenantning oxirgi 30 alertidan tuzilgan kontekstni Groq'ga uzatadi.
- Oracle (`/alerts/:id/explain`) ham shu qatlamdan foydalanadi.
- **Prompt injection himoyasi:** alert matni (`full_log`, hostname'lar) mijoz muhitidan keladi — log qatorini keltirib chiqara oladigan hujumchi u yerga so'z qo'ya oladi. Alert ma'lumoti fence ichida beriladi va system prompt uni ishonchsiz ma'lumot deb e'lon qiladi.
- Kalitsiz yoki model ishlamasa — eski deterministik javob **fallback** sifatida qoladi. AI uzilishi dashboardni yiqitmaydi (20s timeout).
- Javobda `source: "ai" | "local"` qaytadi.

---

## 4. Assets endi jonli inventarizatsiya

Wazuh webhook alert yaratardi, lekin asset yaratmasdi — Assets sahifasi abadiy demo ma'lumot ko'rsatardi.

Endi har bir hodisa `agent.name` bo'yicha asset'ni upsert qiladi: `last_seen`, `ip_address`, `os` yangilanadi.

**Risk hisoblash:** eng yomon ko'rilgan severity'ga "qotirib" qo'yilmaydi — oxirgi **7 kunlik oyna** bo'yicha qayta hisoblanadi. Aks holda bitta critical alert asset'ni abadiy qizil qoldirardi. Endi tinch turgan asset o'zi pastga tushadi.

---

## 5. Xavfsizlik tuzatishlari (auditdagi 1-7)

| # | Muammo | Tuzatish |
|---|---|---|
| 1 | Demo admin production'da | `SEED_DEMO_DATA` production'da majburan `false`. Production bo'sh baza bilan ishga tushadi. |
| — | Zaif production konfiguratsiyasi | Server `JWT_SECRET` (32+), `COOKIE_SECURE=true`, `https://` FRONTEND_URL va `SMTP_HOST` bo'lmasa **ishga tushishdan bosh tortadi** va sababini ro'yxat qilib chiqaradi. |
| 2 | `/auth/register` race condition | Hash endi tekshiruvdan **oldin** hisoblanadi; tekshirish va yozish orasida `await` yo'q. Test: 3 ta parallel so'rovdan faqat 1 tasi 201 qaytaradi. |
| 4 | WS `?token=` fallback | Butunlay olib tashlandi — faqat cookie. JWT endi proxy/access loglarga tushmaydi. |
| 5 | Reset token `===` taqqoslash | `timingSafeEqual` (`safeEqual` helper). Invite tokenlarga ham qo'llanildi. |
| 6 | Login formadagi demo email | Olib tashlandi. |
| — | Deaktivatsiya qilingan hisob | `auth` middleware endi `status !== "active"` bo'lsa 401 qaytaradi (WS ham). |

---

## 6. PostgreSQL migratsiyasi (2.0)

JSON store butunlay olib tashlandi. **Postgres yagona haqiqat manbai** — xotirada nusxa saqlanmaydi.

Bu ataylab qilingan va migratsiyaning butun sababi: xotirada nusxa bo'lsa, ikkinchi instansiya eskirgan ma'lumot ko'rsatadi va bir pod'dagi yozuv boshqasiga ko'rinmaydi — bu esa bittadan ortiq instansiya ishlatishni ma'nosiz qiladi.

### Yangi tuzilma

```
server/src/db/pool.ts      pg Pool, query/transaction helperlari, migrate()
server/src/db/schema.sql   6 jadval, indekslar, CHECK cheklovlari
server/src/store.ts        Repository — barcha SQL faqat shu yerda
server/src/seed.ts         Demo ma'lumot (production'da hech qachon)
server/src/scripts/        JSON -> Postgres import
```

Sxema har startda idempotent qo'llanadi. Bir vaqtda ko'tarilayotgan instansiyalar **advisory lock** bilan ketma-ketlashtiriladi — aks holda parallel `CREATE INDEX` bir-biriga deadlock qilib, bir nechta pod'ni bir vaqtda yangilaydigan deploy'ni buzardi.

### Bazaga ko'chirilgan kafolatlar

Ilgari ilova kodida (va shuning uchun ishonchsiz) bo'lgan qoidalar endi baza cheklovlari:

| Kafolat | Ilgari | Endi |
|---|---|---|
| Email noyobligi | `users.some(...)` tekshiruvi | `UNIQUE INDEX ON lower(email)` |
| Alert dublikati | `alerts.some(...)` tekshiruvi | `ON CONFLICT (tenant_id, id) DO NOTHING` |
| Asset upsert | o'qib-keyin-yozish | bitta `INSERT ... ON CONFLICT` |
| Paddle tartibi | ilovada `if (stale) return` | `WHERE ... EXCLUDED.last_event_at >= ...` |
| Tenant+admin atomikligi | yo'q (yetim tenant qolardi) | bitta tranzaksiya |
| `token_version` oshirish | o'qib-keyin-yozish | `SET token_version = token_version + 1` |

**Real yuk ostida tasdiqlangan:**

- 200 ta parallel Wazuh hodisasi → 0.96 soniya (~209/sek), hammasi to'g'ri yozildi
- Bir xil hodisa 30 marta parallel → **aynan 1 ta** alert
- Bir xil email bilan 20 ta parallel ro'yxatdan o'tish → **1 ta foydalanuvchi, 1 ta tenant** (yetim tenant yo'q)

### Xavfsizlik yaxshilanishi: alert ID endi tenant doirasida

`alerts` jadvalining birlamchi kaliti — `(tenant_id, id)`, global `id` emas.

Ilgari bir tenant foydalanuvchisi `POST /alerts` ga boshqa tenantda mavjud ID ni yuborsa, "Alert ID already exists" javobini olardi — ya'ni boshqa workspace'dagi alert ID sining mavjudligini aniqlay olardi. Endi bu mumkin emas va ikki tenant bir xil ID dan bemalol foydalana oladi.

### Boshqa o'zgarishlar

- `/health` endi bazaga so'rov yuboradi. Bazaga tegmaydigan health check har so'rov 500 qaytarayotgan paytda ham "ok" deb turaverardi.
- Login noma'lum email uchun ham bcrypt taqqoslashni bajaradi — javob vaqti orqali email mavjudligi aniqlanmaydi.
- Token qidiruvi (`invite_token`, `reset_token`) SQL'da emas, ilovada constant-time taqqoslanadi: `WHERE invite_token = $1` so'rov vaqti orqali moslik pozitsiyasini oshkor qilardi.
- Audit jurnalining sun'iy 20 000 qatorlik chegarasi olib tashlandi — Postgres'da bunga ehtiyoj yo'q.
- Statistika bitta agregat so'rov bilan hisoblanadi (ilgari barcha alertlar xotiraga yuklanardi).
- `SIGTERM`/`SIGINT` da ulanishlar drenaj qilinadi, 10 soniyalik majburiy timeout bilan.

### Ma'lumotni ko'chirish

```bash
npm run import:json -w server -- ./data/legion.json
```

Idempotent, JSON faylni o'zgartirmaydi. Eski sxemadagi yo'q maydonlar to'ldiriladi: `status='active'`, `token_version` saqlanadi, tenant'ga **yangi** sinov oynasi beriladi (yaratilish sanasidan hisoblansa, ko'chirish paying mijozni bloklab qo'yardi).

### DX o'zgarishi — buni bilib qo'ying

README'dagi "PostgreSQL lokal ishlash uchun talab qilinmaydi" endi to'g'ri emas. Lokal ishlash uchun Postgres kerak (`docker compose up postgres -d`). Bu SaaS uchun to'g'ri savdo: mijoz brauzerdan foydalanadi, Postgres faqat sizning infratuzilmangizda.

---

## 7. Diskka yozish — eski JSON store (2.0 gacha)

**Muammo:** har bir mutatsiya butun bazani JSON'ga serialize qilib qayta yozardi. Alert qabul qilish ikki marta mutatsiya qiladi (alert + audit). Wazuh burst'ida bu sekundiga yuzlab to'liq qayta yozuv va navbat drenajdan tez o'sardi.

**Qilingan ish:** yozuvlar **koalesing oynasi** ichida birlashtiriladi (`PERSIST_FLUSH_MS`, standart 200ms). Bir oynadagi barcha `persist()` chaqiruvlari bitta yozuvni bo'lishadi. Durability o'zgarmadi — `await persist()` hamon baytlar diskka tushgandan keyin yakunlanadi, o'sha atomik temp+rename orqali. `SIGTERM`/`SIGINT` da kutilayotgan yozuv majburan flush qilinadi.

Burst'da 1000 alert = 2000 to'liq yozuv o'rniga ~5 ta.

**Nima uchun to'liq SQLite migratsiyasi qilinmadi.** Endpointlar ma'lumotni to'g'ridan-to'g'ri mutatsiya qiladi (`alert.status = body.status`). Haqiqiy SQLite migratsiyasi ~30 ta yozuv nuqtasini qayta yozishni talab qiladi. Buni shoshib qilish — aynan xavfsizlik mahsulotida tenant izolyatsiyasi xatosini kiritishning yo'li. Testlar xulq-atvorni qoplaydi, saqlash qatlamini emas.

**Keyingi qadam (alohida ish):** yozuvlar hamon `O(baza hajmi)`. To'g'ri yechim — real baza. Ko'p instansli SaaS uchun **Postgres**, chunki SQLite bitta process bilan chegaralangan. Migratsiya rejasi: (1) repository interfeysi ajratiladi, (2) mutatsiyalar aniq operatsiyalarga aylantiriladi, (3) mavjud 47 test qizil bo'lmasligini kuzatib qatlam almashtiriladi.

Qo'shimcha: audit jurnali endi 20 000 qator bilan chegaralangan (ilgari cheksiz o'sardi). Bu ham vaqtinchalik chora — to'g'ri yechim arxivlash.

---

## Yangi konfiguratsiya

```env
NODE_ENV=development          # production'da qat'iy tekshiruvlar yoqiladi
SEED_DEMO_DATA=true           # production'da majburan false
TRIAL_DAYS=14                 # yangi tenant sinov muddati
INVITE_DAYS=7                 # taklif linki amal qilish muddati
PERSIST_FLUSH_MS=200          # yozuvlarni birlashtirish oynasi
```

Production'da majburiy: `JWT_SECRET` (32+ belgi), `COOKIE_SECURE=true`, `FRONTEND_URL=https://...`, `SMTP_HOST`.

---

## Testlar

`npm test` — 47 ta test, ~4 soniya. Qoplangan sohalar:

- **Tenant izolyatsiyasi** — alertlar, foydalanuvchilar, status o'zgartirish, boshqa tenantning rolini o'zgartirishga urinish
- **RBAC** — viewer/analyst/admin chegaralari
- **`token_version` bekor qilish** — rol o'zgarishi va deaktivatsiya eski tokenlarni o'ldiradi
- **Taklif oqimi** — yaratish, ko'rib chiqish, qabul qilish, qayta ishlatish, muddati o'tishi, qayta yuborish, qabul qilinmaguncha login qila olmaslik
- **Deaktivatsiya himoyalari** — o'zini, oxirgi adminni
- **Obuna gate** — sinov, active, canceled, past_due readonly, exempt yo'llar
- **Webhook** — imzo, noma'lum tenant, dedup, asset yaratish, bloklangan tenantda ham qabul qilinishi
- **Ro'yxatdan o'tish** — dublikat, race condition, email enumeration yo'qligi, parol almashtirish
- **Yozuv koalesingi**


---

## 8. Ishlab chiqarishga tayyorlik (2.1)

To'rtta bo'shliq yopildi. Har biri real muhitda o'lchandi, faraz qilinmadi.

### 8.1 Backup va falokatdan tiklash

Postgres yagona haqiqat manbai bo'lgach, backup'siz bitta yomon kun = barcha mijoz ma'lumoti.

```
ops/backup.sh          dump + o'qilishini tekshirish + eski nusxalarni tozalash
ops/verify-backup.sh   vaqtinchalik bazaga tiklab, ma'lumotni TEKSHIRISH
ops/restore.sh         mavjud baza ustiga tiklash (--single-transaction)
BACKUP.md              runbook: RPO/RTO, cron, offsite, falokat protsedurasi
```

`verify-backup.sh` shunchaki "tiklandi" demaydi: kutilgan jadvallar borligini, tenant'lar
bo'sh emasligini va yetim foydalanuvchi yo'qligini tekshiradi. **Sinalgan:** 40 alert
yaratildi → backup → `DROP SCHEMA public CASCADE` → tiklash → login va alertlar
serverni qayta ishga tushirmasdan ishladi.

Skript o'z qiymatini darhol isbotladi — sxemada `refresh_tokens` jadvali yo'qligini
aniqlab, "bu backupga ishonmang" deb xato qaytardi.

### 8.2 Rate limit ko'p instansiyada

`express-rate-limit` standart store'i xotirada hisoblaydi. Postgres migratsiyasi
gorizontal masshtabni ochgan edi, lekin limiter hamon bitta instansiya mantig'ida
ishlayotgan edi.

**O'lchangan (3 instansiya, limit 10/daqiqa, 36 urinish):**

| | O'tgan |
|---|---|
| Redis'siz | **30** — limitdan 3 barobar |
| Redis bilan | **10** — aynan limit |

Wazuh webhook, `/health` va Paddle webhook umumiy limitdan **chiqarilgan**: band SOC
dashboard uchun qulay bo'lgan har qanday chegaradan oshadi, va telemetriyani
cheklash mijozning xavfsizlik tarixida teshik qoldiradi.

Redis o'chsa `passOnStoreError` bilan so'rovlar o'tadi (himoya zaiflashadi, lekin
platforma yiqilmaydi) va xato log'ga yoziladi.

**Yo'l-yo'lakay topilgan ikkita bug:**

1. **Seed poygasi.** Uch instansiya bo'sh bazaga bir vaqtda ko'tarilganda hammasi demo
   ma'lumot yozmoqchi bo'lardi; yutqazganlar unique constraint'da **qulardi**. Replica
   bilan har yangi deploy'da pod restart-loop'ga tushardi. Advisory lock + lock ichida
   qayta tekshirish bilan hal qilindi.

2. **RedisStore ulanishdan oldin yaratilishi.** `store.init()` Lua skriptini yuklaydi;
   klient hali ulanmagani uchun bu jimgina muvaffaqiyatsiz bo'lardi va limiter
   **hamma narsani o'tkazib yuborardi**, Redis esa "ulandim" deb log yozardi.
   Monitoring yashil — himoya yo'q. Modul yuklanishida top-level `await connect()`
   bilan tuzatildi.

Ikkalasini ham typecheck ham, 53 test ham tutmagan edi — faqat real ko'p instansiyali
sinov ochdi.

### 8.3 MFA (TOTP)

Legion alert ko'rganda `"Reset affected credentials and enforce MFA"` deb maslahat
berardi, o'zida esa yo'q edi.

| Endpoint | Vazifasi |
|---|---|
| `POST /auth/mfa/setup` | Sir yaratadi, `otpauth://` URI qaytaradi |
| `POST /auth/mfa/enable` | Kodni tasdiqlaydi, 10 ta tiklash kodi beradi |
| `POST /auth/mfa/verify` | Login'ning **ikkinchi** bosqichi |
| `POST /auth/mfa/disable` | Parol **va** kod talab qiladi |
| `POST /auth/mfa/recovery-codes` | Yangi to'plam (eskisi o'ladi) |

Qarorlar:

- **Kod tasdiqlanmaguncha MFA yoqilmaydi** — noto'g'ri skanerlangan QR foydalanuvchini
  qulflab qo'ymasligi uchun.
- **Replay himoyasi:** har qabul qilingan TOTP hisoblagichi `mfa_used_counters` ga
  yoziladi. Kod 30 soniya amal qiladi; transitda ko'rilgan kod aks holda o'sha oyna
  ichida qayta ishlatilardi.
- **Tiklash kodlari faqat bcrypt hash sifatida** saqlanadi va bir marta ko'rsatiladi.
- **Challenge token sessiya emas.** U sessiya token'i bilan bir xil kalit va bir xil
  claim'lar bilan imzolanadi — `authenticate` endi `purpose` claim'i bor har qanday
  token'ni rad etadi. Busiz MFA'ni buni payqagan har kim aylanib o'tardi.

### 8.4 Refresh token

Access token 1 soat edi va yangilash yo'q edi: SOC analitigi smena davomida har soatda
chiqib ketardi. Muddatni cho'zish yomonroq bo'lardi — stateless JWT'ni bekor qilib
bo'lmaydi.

Endi: qisqa access token (15 daq) + `refresh_tokens` jadvalidagi uzoq refresh token
(30 kun), har ishlatishda **almashadi**.

- **O'g'irlikni aniqlash:** allaqachon almashtirilgan token qayta taqdim etilsa, uni ikki
  tomon ushlab turibdi va qaysi biri haqiqiy ekanini bilib bo'lmaydi — butun oila
  bekor qilinadi. Bu jimgina davom etayotgan kirishni **bitta ko'rinadigan chiqishga**
  aylantiradi.
- **Faqat SHA-256 hash saqlanadi** (bcrypt emas: token 256 bit tasodifiy, va refresh
  har sahifa yuklanishida ishlaydi).
- **Bir vaqtda ikki tab:** `FOR UPDATE` bilan aynan bittasi almashtiradi.
- **Frontend'da bitta umumiy refresh:** dashboard bir sahifada 6 ta so'rov yuboradi;
  har biri alohida refresh qilsa, g'olibdan boshqasi replay deb hisoblanib
  foydalanuvchi aynan sessiya haqiqiy paytda chiqib ketardi.
- Parol, rol yoki deaktivatsiya o'zgarishi **barcha sessiyalarni** bekor qiladi.
- 6 soatda bir marta eskirgan qatorlar tozalanadi (aks holda jadval har refresh'da
  bittadan o'sadi).

### 8.5 Hali yo'q

- **PITR** — kunlik dump'da RPO 24 soat. Boshqariladigan Postgres'da yoqing.
- **Backup shifrlash va offsite nusxa** — hujjatlashtirilgan, skriptga kiritilmagan.
- **Tenant darajasida MFA majburlash** — hozir har foydalanuvchi o'zi yoqadi.
- **SSO/SAML** — yirik korporativ xaridor talab qiladi.
- **Retention va observability** — 7-bo'limga qarang.
