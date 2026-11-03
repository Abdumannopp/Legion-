# To'lov tekshiruvi: moliyaviy firibgarlikni pul ketishidan oldin to'xtatish

Biznes pochtasini buzish (BEC), soxta ovozli "direktor" qo'ng'irog'i va
o'g'irlangan hisoblar bir xil yakunlanadi: pul hujumchining hisobiga
jo'natiladi. Legion to'lov yo'lida turmaydi. Shuning uchun **to'lov dasturingiz
(ERP, bank ulagichi, buxgalteriya) pul jo'natishdan oldin Legion'dan
so'raydi**. Legion "ruxsat" yoki "to'xtat" deb javob beradi.

## Qachon to'xtatiladi

| Sabab | Ma'nosi |
|---|---|
| Yangi hisob | Bu hisob raqamiga sizning tashkilotingizdan hali hech qachon tasdiqlangan to'lov bo'lmagan. "Bank rekvizitlarimiz o'zgardi" — firibgarlikning eng keng tarqalgan boshlanishi. |
| So'ragan odam hujum ostida | To'lovni so'ragan xodimning hisobi yoki pochtasi buzilgan (Legion'da faol kampaniya bor). |
| Pochta egallanmoqda | So'nggi 48 soatda tashkilotdagi biror pochtada egallash belgilari bor. |
| Avval rad etilgan | Kimdir aynan shu to'lovni allaqachon rad etgan. |

To'xtatilgan to'lov Dashboard → **Himoya** → **To'xtatilgan to'lovlar** da
ko'rinadi va ogohlantirish yuboriladi (Executor agenti, MITRE T1657).

## Inson nima qiladi

1. Yetkazib beruvchiga yoki hamkasbingizga **oldindan bor bo'lgan** raqam
   orqali qo'ng'iroq qiling — xatdagi, hisob-fakturadagi yoki qo'ng'iroq qilgan
   odam bergan raqam orqali emas. Tanish ovoz yoki video soxta bo'lishi mumkin.
2. Tasdiqlansa — **"Telefon orqali tasdiqladim — ruxsat berish"** (faqat
   administrator). Hisob raqami shundan keyin "tasdiqlangan" bo'ladi va
   unga keyingi to'lovlar yangi hisob sifatida to'xtatilmaydi.
3. Tasdiqlanmasa — **"Rad etish"**. To'lov dasturi uni to'xtatib turaveradi.

Har bir tekshiruv, ruxsat va rad etish audit jurnaliga yoziladi.

## To'lov dasturini ulash

Wazuh uchun berilgan sensor kalitining o'zi ishlatiladi (Dashboard → Ulash).
Tayyor mijoz — `integrations/custom-legion.py`:

```bash
custom-legion.py --payment-check @/etc/legion.key \
  https://legion.example.com/security-events/webhook  payment.json
```

`payment.json`:

```json
{
  "beneficiary": { "account": "DE89 3704 0044 0532 0130 00", "name": "Acme Supplies Ltd" },
  "amount": 12500,
  "currency": "EUR",
  "requestedBy": "dana@acme.example",
  "reference": "INV-2026-0042"
}
```

Natija (chiqish kodi):

| Kod | Ma'nosi | To'lov dasturi nima qiladi |
|---|---|---|
| `0` | ruxsat | to'lovni jo'natadi |
| `3` | to'xtatildi | jo'natmaydi; keyinroq qayta so'raydi |
| `1` | xato (Legion'ga yetib bo'lmadi va h.k.) | **avtomatik jo'natmaydi** |

Javob JSON ko'rinishida ham chiqadi (sabablar va tasdiqlash bo'yicha
maslahat bilan). So'rov imzolanadi (HMAC, vaqt belgisi, bir martalik nonce)
va faqat to'lov tekshiruvi uchun qabul qilinadi.

## Maxfiylik

Hisob raqamining **o'zi saqlanmaydi**. Legion faqat kalitli xeshni (hisobni
qayta tanish uchun) va oxirgi 4 belgini (odam tanishi uchun) saqlaydi. Xesh
har bir tashkilot uchun farqli.

## Halol cheklovlar

- **To'lov dasturi Legion'dan so'ramasa, Legion uni to'xtata olmaydi.**
  Legion bankingizga yoki ERP'ga o'zi kira olmaydi; bu ulanish kerak.
- Xato bo'lsa (`1`) to'lov avtomatik jo'natilmasligi kerak — buni to'lov
  dasturining o'zi bajarishi lozim.
- Legion summani yoki hisob egasini bank orqali tekshirmaydi; u faqat
  tashkilot ichidagi tarixga va faol hujumlarga qaraydi.
- Tasdiqlash qo'ng'irog'i — inson qadami. Uni o'tkazib yuborib "ruxsat
  berish" tugmasini bosish himoyani yo'qqa chiqaradi.
