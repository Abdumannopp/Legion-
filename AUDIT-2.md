# Legion — qayta audit

**Sana:** 2026-08-25
**Ko'lam:** oxirgi auditdan keyin o'zgargan hamma narsa — self-hosted rejim,
yangi o'rnatish skriptlari, port avtomatik tanlash, sinov rejimi
**Metod:** kod ko'rib chiqish + har bir topilmani **ishlab turgan tizimda o'lchash**

---

## Qisqacha

Ikkita haqiqiy topilma. Ikkalasi ham **bitta ildizdan** — bu ildiz shu
loyihada endi **uchinchi marta** chiqyapti.

| # | Topilma | Daraja | Holat |
|---|---|---|---|
| 1 | HTTPS orqasida ishlab turib sessiya cookie'si himoyalanmagan | Yuqori | ✅ tuzatildi |
| 2 | Uzoq bazaga sertifikat tekshiruvisiz ulanish mumkin | Yuqori | ✅ tuzatildi |

Yopilgan (tekshirildi, muammo emas): sinov bazasi paroli, `/billing` bloki,
rejimni so'rov orqali o'zgartirish, repodagi sirlar.

---

## Ildiz sabab: `NODE_ENV` ga bog'langan himoya

`config.ts` da xavfsizlik tekshiruvlari `if (isProduction)` bloki ichida edi.
`isProduction` esa `NODE_ENV === "production"` degani.

**Mijoz `NODE_ENV` ni hech qachon "production" deb belgilamaydi.** U shunchaki
`npm start` yoki `docker compose up` qiladi. Ya'ni o'sha blokdagi barcha
himoyalar self-hosted o'rnatmada **umuman ishlamaydi**.

Bu naqsh shu sessiyada uch marta chiqdi:

1. **JWT siri** — hammaga ma'lum standart sir bilan ishga tushardi
2. **Demo hisob** — `admin@legion.demo` / `legion123` mijoz serverida yaratilardi
3. **Quyidagi ikkita topilma** — bu audit

Har safar men bittasini tuzatdim va "boshqa shunday joy qolgan bo'lsa, u ham
shu naqsh bo'yicha chiqadi" dedim. Bu audit aynan shuni tekshirdi va qolgan
ikkitasini topdi.

---

## 1. HTTPS + himoyalanmagan cookie

**Holat:** `FRONTEND_URL=https://legion.mijoz.uz` va `COOKIE_SECURE=false`
bo'lsa, server hech qanday ogohlantirishsiz ishga tushardi.

**Nega muhim:** `Secure` bayrog'i bo'lmagan cookie brauzer tomonidan shu
domenga ochiq HTTP so'rov ketsa ham yuboriladi. Ya'ni HTTPS o'rnatgan mijoz
o'zi bilmagan holda sessiya tokenini himoyasiz qoldiradi — aynan HTTPS oldini
olishi kerak bo'lgan narsa.

**Nega chiqib qolgan:** README mijozga "HTTPS orqasiga qo'ying va
`COOKIE_SECURE=true` qiling" deydi. Ikkinchi qadamni unutish oson, va tizim
buni sezmasdi.

**Tuzatish:** bu kombinatsiya bilan server ishga tushmaydi. Xabar aniq sababni
aytadi.

**O'lchandi:** `FRONTEND_URL=https://…` + `COOKIE_SECURE=false` → to'xtadi.
`COOKIE_SECURE=true` → ishga tushdi. Ichki tarmoqdagi HTTP o'rnatma va lokal
sinov (`npm run try`) buzilmadi.

---

## 2. Uzoq bazaga tekshiruvsiz ulanish

**Holat:** `DB_SSL_INSECURE=true` faqat ogohlantirish berardi va server
ishlashda davom etardi — baza boshqa serverda bo'lsa ham.

**Nega muhim:** ulanish shifrlangan, lekin **autentifikatsiya qilinmagan**.
Baza bilan ilova orasidagi har qanday tomon o'zini baza qilib ko'rsatishi
mumkin. Bu — shifrlashning ma'nosini yo'q qiladi.

**Tuzatish:** baza **uzoqda** bo'lsa va tekshiruv o'chirilgan bo'lsa, server
ishga tushmaydi. Baza **shu mashinada** bo'lsa ruxsat beriladi — u yerda
oraliqda hech kim yo'q, va lokal tajribalar uchun kerak.

**O'lchandi:** uzoq host → to'xtadi. `localhost` → ishladi.

---

## Tekshirilib, muammo emas deb yopilgani

**Sinov bazasi paroli kodda ochiq.** `npm run try` bazasi
`legion-local-test` paroli bilan ishlaydi. Baza qaysi manzilda tinglashini
o'lchadim: `/proc/net/tcp` bo'yicha **faqat `127.0.0.1`**, va tashqi IP'dan
ulanishga urinish rad etildi. Tarmoqdan ko'rinmaydi — xavf yo'q.

**`/billing` bloki.** Self-hosted rejimda barcha billing marshrutlari 404
qaytaradi. Guard 848-qatorda, birinchi billing marshruti 855-da — ya'ni
webhook ham qamrab olingan. Testlar bilan tasdiqlangan.

**Rejimni so'rov orqali o'zgartirish.** `deploymentMode` faqat env
o'zgaruvchisidan o'qiladi; hech bir endpoint uni o'zgartira olmaydi.

**Repodagi sirlar.** Qidiruv hech narsa topmadi.

---

## O'lchangan holat

| Tekshiruv | Natija |
|---|---|
| Testlar | **119 o'tdi** (109 + 10 yangi) |
| Server typecheck | toza |
| Frontend typecheck | toza |
| `npm audit` (server) | 0 zaiflik |
| `npm audit` (frontend) | 0 zaiflik |

Yangi 10 ta test aynan yuqoridagi ikkita guardni qoplaydi — ular jimgina
buzilib qolmasligi uchun. Ilgari bu tekshiruvlar hech qanday test bilan
himoyalanmagan edi.

---

## Nima qilinmadi

- **Haqiqiy Wazuh bilan sinov** — menda Wazuh yo'q. Bu hamon eng katta
  tekshirilmagan joy.
- **Windows'da real sinov** — hammasi Linux'da o'lchandi. Siz Windows'dasiz.
- **Auditdagi eski P0'lar** (RLS, durable queue, observability) — ular
  ko'p-tenantli SaaS uchun edi va self-hosted yo'nalishda predmetsiz.

---

## Xulosa

Kod holati yaxshi. Lekin bu auditning asosiy natijasi topilmalarning o'zi
emas, balki **naqsh**: bu loyihada xavfsizlik tekshiruvi qo'shganda birinchi
savol "bu mijozning o'rnatmasida ham ishlaydimi?" bo'lishi kerak, chunki
mijoz muhitini "production" deb belgilamaydi.

Yangi tekshiruvlar bu naqshdan chiqarildi: ular `NODE_ENV` ga umuman
qaramaydi, faqat konfiguratsiyaning o'ziga qaraydi.
