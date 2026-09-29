# OpenRouter qo'shildi

**Sana:** 2026-09-19
**Versiya:** Legion 1.0.0 · testlar 119 → **134**

---

## Nima o'zgardi

Ilgari Legion faqat Groq bilan ishlardi. Endi **OpenRouter** ham bor —
bitta kalit bilan ko'p sotuvchining modellari ochiladi, jumladan **bepul
modellar**. Mijoz AI qismini pul to'lamasdan sinab ko'ra oladi.

Groq olib tashlanmadi. Ikkalasi ham ishlaydi.

## Mijoz nima qiladi

Hech narsa tanlashi shart emas — qaysi kalitni qo'ysa, o'sha ishlaydi:

```env
OPENROUTER_API_KEY=sk-or-…     # model tanlash: openrouter.ai/models
OPENROUTER_MODEL=              # bo'sh = OpenRouter hisobidagi standart model

GROQ_API_KEY=gsk-…             # muqobil
AI_PROVIDER=                   # ikkalasi ham qo'yilsa: groq deb yozish mumkin
```

Kalit umuman qo'yilmasa — hammasi eski holicha: lokal tahlil, serverdan
hech narsa chiqmaydi.

---

## Ikkita qaror va sabablari

**1. OpenRouter uchun standart model qo'yilmadi.**

Odatda kodga "mana shu modelni ishlat" deb yozib qo'yiladi. Men atay
yozmadim. Sabab: OpenRouter'da modellar ro'yxati o'zgarib turadi. Bugun
yozgan model nomi olti oydan keyin o'chirilsa, **o'sha kundan boshlab har bir
mijozning o'rnatmasida AI ishlamay qoladi** — va ular buni qaydan bilishadi?
Bo'sh qoldirsak, so'rovda model maydoni umuman yuborilmaydi va OpenRouter
mijozning o'z hisobidagi standart modelni ishlatadi. Mijoz modelni narxini
ko'rib turgan joyda tanlaydi.

**2. Noto'g'ri sozlamada AI o'chadi — boshqa xizmatga o'tmaydi.**

Mijoz `AI_PROVIDER=openrouter` deb yozsa-yu, OpenRouter kalitini qo'ymasa,
lekin Groq kaliti turgan bo'lsa — ko'p dastur jimgina Groq'ga o'tib ketardi.
Legion bunday qilmaydi: AI butunlay o'chadi va logda sabab yoziladi.

Sabab oddiy: mijoz qaysi kompaniya uning xavfsizlik ma'lumotini ko'rishini
**o'zi tanlaydi**. Bittasini nomlab, boshqasiga yuborib qo'yish — eng yomon
turdagi xato. Bu holat test bilan qoplangan.

Yana bir kichik narsa: OpenRouter `HTTP-Referer` sarlavhasini ham qabul
qiladi, lekin men uni **yubormadim** — u mijozning ichki server manzilini
oshkor qilardi. Faqat "Legion" degan nom yuboriladi.

---

## Hujjatlar ham tuzatildi

O'tgan safar maxfiylik sahifasidagi yolg'onni tuzatgandik. O'sha yerda
"Groq" deb aniq yozilgan edi — OpenRouter qo'shilgach bu **yana noto'g'ri**
bo'lib qolardi. Uch tilda ham tuzatildi: endi ikkala xizmat nomi ham bor va
"qaysi biri ishlatilayotganini administratoringiz aytadi" deyiladi.

Shuningdek `INSTALL.md` (8-bo'lim), `README.md`, `install.sh`,
`.env.example`, `setup.mjs`, `docker-compose.yml`, `try-local.mjs`.

---

## Tekshirildi

| Nima | Natija |
|---|---|
| Testlar | **134 o'tdi** (119 + 15 yangi) |
| Typecheck (server + frontend) | toza |
| Yangi bog'liqlik | **yo'q** — Node'ning o'zidagi `fetch` ishlatildi, NOTICE o'zgarmadi |
| Qurilgan koddan chiqadigan haqiqiy so'rov | 5 holat o'lchandi |
| Ishlab turgan server `/health` | `"ai_provider":"openrouter"` qaytardi |

Beshta holat qurilgan `dist/` kodi orqali o'lchandi, faqat manba kodi emas:
OpenRouter (modelsiz), OpenRouter (model bilan), Groq, ikkala kalit +
`AI_PROVIDER=groq`, va noto'g'ri sozlama. Oxirgisida **hech qanday so'rov
yuborilmadi** — bu taxmin emas, o'lchov.

**Eslatma:** bu sandbox'dan `openrouter.ai` ga chiqish yopiq, shuning uchun
haqiqiy kalit bilan jonli so'rov qilib ko'rilmadi. So'rovning manzili,
sarlavhalari va tarkibi to'g'ri ekani tasdiqlandi; javobni faqat siz haqiqiy
kalit bilan sinab ko'rasiz.

---

## Siz nima qilasiz

1. [openrouter.ai](https://openrouter.ai/) da ro'yxatdan o'ting, kalit oling
2. `server/.env` ga `OPENROUTER_API_KEY=` dan keyin qo'ying
3. Legion'ni qayta ishga tushiring
4. Biror alertni oching va "Oracle" tugmasini bosing

Ishlamasa — server logida sabab yoziladi (masalan "no credit" yoki
"unknown model"). Logni menga ko'rsating.


## AI xavfsizligi (2026-09-29)

**AI faqat maslahat beradi.** Provayderga yuboriladigan so'rovda hech qanday
`tools`/`functions` yo'q, shuning uchun model hech narsa *qila olmaydi*: uning
javobi — inson o'qiydigan matn. Dashboard, incident sahifasi va Copilot'da
modelning har bir javobi **"AI taklifi"** deb belgilanadi; Legion'ning o'z
qoidalari yozgan matn esa **"Legion tahlili"** deb belgilanadi.

| Himoya | Qanday |
|---|---|
| Ogohlantirish matni — ishonchsiz ma'lumot | Faqat user-xabarida, har so'rovda tasodifiy chegarali "fence" ichida; ko'rinmas belgilar va chat-template tokenlari olib tashlanadi |
| Xost nomi, IP, MITRE, ID | Formatga mos kelmasa, model o'rniga `(non-standard value omitted)` ko'radi |
| Sirlar provayderga ketmaydi | Parol, token, API kalit, JWT, private key, URL ichidagi login va serverning o'z sirlari yuborishdan oldin `[REDACTED:…]` qilinadi |
| Ma'lumotni kamaytirish | Maydonlar qisqartiriladi; **qat'iy rejim** IP, email va xost nomlarini `IP_1`, `HOST_1`… bilan almashtiradi va javobda qaytaradi |
| Chiqish | JSON/tuzilma tekshiriladi, HTML va rasmlar olib tashlanadi, havolalar zararsizlantiriladi (`hxxps://x[.]y`), sirlar yashiriladi, uzunlik cheklanadi; so'rovning o'z chegarasini qaytargan javob rad etiladi |
| Vaqt va xatolar | `AI_TIMEOUT_MS`, javob hajmi 256 KB, redirect taqiqlangan; ketma-ket xatolarda circuit breaker. Har qanday xatoda deterministik mahalliy tahlil qaytadi |
| Tashkilot nazorati | `GET/PATCH /ai/settings` va Settings → Profil'dagi "AI tahlili" kartasi (faqat administrator o'zgartiradi). O'chirilsa, agent skill'lari uchun ham hech narsa yuborilmaydi |
| Audit | `alert.explained` / `copilot.chat` yozuvida faqat provayder, hajm, necha sir yashirilgani, vaqt va xato sababi — prompt, javob yoki kalit emas |

**Hosted (SaaS) rejimda AI standart holatda O'CHIQ** — tashkilot administratori
yoqmaguncha uning ma'lumoti uchinchi tomonga ketmaydi. Self-hosted'da yoqilgan.
`AI_TENANT_DEFAULT=on|off` bilan o'zgartiriladi.

Testlar: `server/tests/ai-hardening.test.ts` (66 ta hujum ssenariysi),
`server/tests/ai-safety.test.ts`.
