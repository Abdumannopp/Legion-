# Mijozga tayyorlash — nima qilindi va nima qolgan

**Sana:** 2026-08-26

Bu hujjat "loyihani real mijozlar uchun tayyorla" vazifasining natijasi.
Kod xavfsizligi allaqachon auditdan o'tgan edi ([AUDIT-2.md](AUDIT-2.md));
bu safar yetishmayotgan narsa **mahsulot atrofidagi qatlam** edi — litsenziya,
haqiqatga mos hujjatlar va mijoz o'qiydigan qo'llanma.

---

## Eng muhim topilma: huquqiy sahifalar yolg'on gapirardi

`/privacy` sahifasi mijoz serverida ochilganda quyidagilarni da'vo qilardi:

- "biz qanday ma'lumot yig'amiz"
- "qonun talab qilsa, ma'lumotni oshkor qilishimiz mumkin"
- "cheklangan analitika cookie'laridan foydalanishimiz mumkin"

Men kodni tekshirdim: **bularning hech biri rost emas.** Legion'da analitika
ham, telemetriya ham, avtomatik yangilanish tekshiruvi ham yo'q. Butun kod
bazasida tashqariga ketadigan uchta manzil bor, xolos: Groq (faqat mijoz kalit
bersa), Paddle (self-hosted rejimda umuman o'chirilgan) va SMTP (mijozning o'z
pochta serveri).

Ya'ni sahifa mijozga *o'zi haqida* yolg'on aytardi — va aynan xavfsizlik
mahsulotida bu eng yomon joyda qilingan xato. Agar mijozning yuristi buni
o'qib, "demak siz bizning ma'lumotimizni yig'asiz" degan xulosaga kelsa,
sotuvni yo'qotasiz; agar ishonib qolsa, undan ham yomoni.

**Tuzatildi.** Ikkala sahifa ham (3 tilda) qaytadan yozildi va endi haqiqatni
aytadi: o'rnatmani mijoz boshqaradi, ma'lumot uning bazasidan chiqmaydi, va
ma'lumot bo'yicha so'rovlar sotuvchiga emas, mijozning o'ziga boradi.

Yangi mexanizm: sahifalarda `{operator}` o'rniga mijozning tashkiloti nomi
qo'yiladi — `NEXT_PUBLIC_OPERATOR_NAME` orqali. Bo'sh qolsa, sahifa buni ochiq
ko'rsatadi (`[the organisation running this installation]`) — noto'g'ri
odamning nomini jimgina yozib qo'ymaydi.

---

## Qolgan tuzatishlar

| Nima | Holat |
|---|---|
| Versiya to'rt joyda har xil edi (`/health` "2.0.0" derdi, package'lar "1.0.0") | Endi bitta manbadan — `package.json` dan o'qiladi, qayta ajralib keta olmaydi |
| `LICENSE` fayli umuman yo'q edi | Qoralama yozildi (pastga qarang) |
| Uchinchi tomon litsenziyalari hech qayerda ro'yxatlanmagan | `NOTICE` — 327 ta paket |
| Mijoz uchun o'rnatish qo'llanmasi yo'q edi (`SINOV.md` sizning noutbukingiz uchun) | `INSTALL.md` — 15 bo'lim, ingliz tilida |
| `npm run setup` frontend sozlamalarini yozmasdi | Endi `frontend/.env.local` ni ham yaratadi |

**Tekshirildi:** 119 test o'tdi, ikkala typecheck toza, server toza qurilishdan
ishga tushirilib `/health` haqiqatan `"version":"1.0.0"` qaytarishi
o'lchandi, va operator nomi almashtirilishi haqiqiy build'da sinaldi.

---

## LICENSE — diqqat bilan o'qing

Fayl boshida katta ogohlantirish bloki bor va u **atay** qo'yilgan:

> DRAFT — NOT YET VALID. DO NOT GIVE THIS FILE TO A CUSTOMER AS-IS.

Sabab ikkita:

1. **Siz hali ro'yxatdan o'tmagansiz.** Mavjud bo'lmagan yuridik shaxs
   nomidan dastur litsenziyalab bo'lmaydi. `[LEGAL ENTITY NAME]`,
   `[JURISDICTION]` kabi maydonlar shuning uchun bo'sh.
2. **Men yurist emasman.** Litsenziyaning eng muhim qismlari —
   javobgarlikni cheklash va kafolatdan voz kechish bandlari. Aynan shu
   bandlarni sud noto'g'ri yozilgan bo'lsa kuchsiz deb topadi. Xavfsizlik
   mahsulotida esa savol shunday turadi: **hujum aniqlanmay qolsa, kim
   javob beradi?** Bunga javobni yurist yozishi kerak.

Men konservativ variantni tanladim — "barcha huquqlar himoyalangan",
bitta o'rnatma uchun ichki foydalanish. Sababi: keyin istalgan vaqtda
yumshatish mumkin, lekin ochiq litsenziyani qaytarib ololmaysiz.

`NOTICE` da yuristga aytiladigan uchta narsa alohida ajratilgan (sharp/libvips
LGPL, lightningcss MPL, caniuse-lite CC-BY). Bularning hech biri sotishga
to'sqinlik qilmaydi — lekin bu mening muhandislik bahom, huquqiy xulosa emas.

---

## Hali ham tekshirilmagan

Bu ikkisi o'zgarmadi va faqat siz yopa olasiz:

1. **Haqiqiy Wazuh bilan sinov.** Menda Wazuh yo'q. Bu hamon eng katta
   noma'lum joy — mahsulotning butun ma'nosi shu integratsiyada.
2. **Windows'da to'liq sinov.** Hammasi Linux'da o'lchandi.

## Kichik, lekin sotuvda ko'zga tashlanadigan narsa

Standart qo'llab-quvvatlash manzili — `abdumannop.offical@gmail.com`. Ikkita
muammo: bu shaxsiy Gmail, va so'zda xato bor (`offical` → `official`). Mijoz
buni ko'radi. Domen olganingizda `support@` yoki `security@` ga o'tkazing.
