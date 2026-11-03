# Legion'ning beshta agenti va ularning skill'lari

Legion'da beshta agent bor. Har birining o'z vazifasi va o'z skill'lari bor.
Dashboardda ularni **Legion jamoasi** sahifasida ko'rasiz.

| Agent | Vazifasi | Skill'lari |
|---|---|---|
| **Sentinel** (kuzatadi) | Kirishlar, hisoblar va serverlardagi hodisalarni kuzatadi | `threat_detection`, `account_activity_watch`, `sensitive_access_watch` |
| **Hunter** (qidiradi) | Alohida hodisalarni bitta hujumga bog'laydi, ma'lumot o'g'irlanishini qidiradi | `attack_investigation`, `threat_intelligence`, `data_exfiltration_hunt` |
| **Guardian** (himoya qiladi) | Hujumga ochiq joylarni oldindan topadi, Legion'ning o'z himoyasini sinaydi | `vulnerability_analysis`, `ai_security_red_team`, `exposure_review`, `threat_coverage`, `secret_exposure_check` |
| **Oracle** (tushuntiradi) | Ogohlantirishni oddiy tilda tushuntiradi, nimani birinchi ko'rishni aytadi | `alert_analysis`, `security_reporting`, `triage_priority`, `response_sla_review` |
| **Executor** (javobni tayyorlaydi) | Keyingi qadamni dalillari bilan tayyorlaydi, **inson tasdiqlaydi** | `incident_response`, `containment_candidates`, `payment_fraud_review` |

## Yangi skill'lar

| Skill | Nima qiladi |
|---|---|
| `account_activity_watch` (Sentinel) | O'g'irlangan yoki topilgan hisobni sezadi: ko'p xatodan keyingi kirish, bitta hisobning ko'p manzildan ishlatilishi, bitta manzildan ko'p hisobni sinash (password spraying), kirishdan keyin yangi huquq yoki yangi hisob |
| `data_exfiltration_hunt` (Hunter) | Ma'lumot avval yig'ilib (baza nusxasi, arxiv), keyin yuborilishini topadi. Hajm va tashqi manzil ham ko'rsatiladi. Faqat yig'ish (masalan tungi zaxira nusxa) xabar qilinmaydi |
| `exposure_review` (Guardian) | Aktivlarni hujumga ochiqligi bo'yicha tartiblaydi: internetdan ko'rinadimi, ma'lum zaifliklari bormi, tuzatilgan versiya bormi. Eng arzon tuzatishlar birinchi |
| `threat_coverage` (Guardian) | Eng xavfli yetti hujum turi bo'yicha: Legion nimani aniqladi, nimani kuzatyapti va qayerda ma'lumot kelmagani uchun ko'rmaydi (HUJUMLAR.md) |
| `triage_priority` (Oracle) | Ochiq ogohlantirishlarni tartiblaydi: hozir / bugun / shu hafta. Har bir ball sababi bilan |
| `containment_candidates` (Executor) | Bloklashga arziydigan hujumchi manzillar va dalillari. Ichki (private) manzillar "bloklab bo'lmaydi" ro'yxatida. Ko'p manzilli hujumda "bloklash yordam bermaydi" deb ogohlantiradi |

## Biznes mijozlar (B2B) uchun skill'lar

| Skill | Nima qiladi |
|---|---|
| `secret_exposure_check` (Guardian) | Loglarga tushib qolgan parol, kalit, karta raqami (Luhn bilan tekshirilgan) va bank hisobini (IBAN, mod-97 bilan tekshirilgan) topadi. **Turi va joyini** aytadi, **qiymatini hech qachon** ko'rsatmaydi. Nima qilish kerakligini yozadi (kalitni almashtirish va h.k.) |
| `sensitive_access_watch` (Sentinel) | Mijozlar ma'lumoti, ish haqi, shartnomalar, kalitlar, zaxira nusxalarni **kim ochayotganini** kuzatadi. Bitta hisob 10+ turli nozik fayl ochsa yoki 3+ kompyuterda ko'rinsa belgilaydi |
| `response_sla_review` (Oracle) | Ochiq ogohlantirishlarni javob muddatiga solishtiradi (sukut: kritik 4 soat, yuqori 24 soat, o'rta 3 kun, past 7 kun; mijoz o'zgartiradi). Kechikkanlarini va "o'z vaqtida %" ni beradi: sizning hamkorlaringiz so'raydigan "xavfsizlik hodisasiga qanchalik tez javob berasiz?" savoliga javob |
| `payment_fraud_review` (Executor) | To'lov tekshiruvini ko'rib chiqadi: nechta to'lov ruxsat olgan, nechtasi to'xtatilgan, **qaysi biri telefon tasdig'ini necha soatdan beri kutyapti**, va firibgarlikka o'xshash qonuniyatlar (bir hisobga qayta-qayta urinish, rad etilgandan keyin qayta urinish, bitta so'ragan odam bir nechta yangi hisob so'rashi). Hisob raqamini ko'rsatmaydi (faqat oxirgi 4 belgi) |

`payment_fraud_review` yangi ruxsat talab qiladi: **`payments:read`** (faqat o'qish,
eng past daraja). Skill tanlash ruxsat bermaydi; sahifa buni yetishmayotgan
ruxsat sifatida ko'rsatadi.

## Skill'ni AI agentga qanday berish

1. Dashboard → **AI agentlar** → kerakli agentni oching → **Skill'lar** yorlig'i.
2. Kerakli skill'ni belgilang (faqat administrator).
3. Agentga skill o'qiydigan ruxsatlar ham kerak (masalan `alerts:read`). Skill
   tanlash **hech qanday ruxsat bermaydi**. Yetishmasa, sahifa qaysi ruxsat
   kerakligini ko'rsatadi; uni **Nima qila oladi** yorlig'ida berasiz.
4. Agent skill'ni chaqiradi:

```
POST /agent/v1/skills/triage_priority/invoke
Authorization: Bearer <agentning vaqtinchalik tokeni>
{"input": {"windowHours": 24}}
```

## Xavfsizlik qoidalari (o'zgartirib bo'lmaydi)

- Skill'lar **faqat o'qiydi va tavsiya beradi**. Hech qaysi skill hech narsani
  bloklamaydi, o'chirmaydi yoki o'zgartirmaydi. Hatto Executor skill'lari ham.
  Har bir tavsiya `executed: false` bilan keladi; uni inson tasdiqlab bajaradi
  (masalan Dashboard → **Himoya** sahifasida bloklash).
- Skill o'z tashkilotingizning ma'lumotini o'qiydi; boshqa tashkilotniki
  hech qachon (server qatordan keyin ham tekshiradi).
- Hodisa matni hujumchi tomonidan yozilgan bo'lishi mumkin. U **ma'lumot**
  sifatida o'qiladi, hech qachon ko'rsatma sifatida emas. AI'ni aldashga
  urinish aniqlansa, ball oshadi va belgilanadi.
- Har bir chaqiruv audit jurnaliga yoziladi (so'rov matni va javob emas).

## Halol cheklovlar

- **Foydalanuvchi nomi log matnidan olinadi.** Legion alohida "foydalanuvchi"
  maydonini saqlamaydi. Nom sshd, sudo, PAM va Windows loglaridagi tanish
  qatorlardan ajratiladi; tanimagan qatorda nom noma'lum bo'lib qoladi va
  taxmin qilinmaydi. Nomni log yozgan odam belgilaydi, shuning uchun u faqat
  ma'lumot sifatida ishlatiladi.
- **Ochiqlik taxminiy.** Aktivning manzili jamoat (public) IP bo'lsa, u
  "internetdan ochiq" deb hisoblanadi. Ichki manzil "noma'lum" bo'lib qoladi
  ("ichki" emas): u NAT yoki load balancer orqasida ochiq bo'lishi mumkin.
  Aniq ma'lumot kerak bo'lsa, aktivlarga ochiqlik belgisi qo'shiladi (rejada).
- **Tarmoq hajmini Legion o'lchamaydi.** Ma'lumot hajmi faqat hodisa uni
  yozgan bo'lsa ma'lum. Zaxira nusxa va ko'chirish ishlari ham "yig'ish va
  yuborish"ga o'xshaydi; natija — tekshirish uchun yo'nalish, isbot emas.
- **Skill'larni agent chaqiradi.** Legion ularni o'zi jadval bo'yicha
  ishga tushirmaydi. Legion'ning o'z aniqlashi va avtomatik bloklashi
  alohida ishlaydi (WAZUH.md, "Avtomatik javob").
- **Tartiblash dalilga asoslanadi, biznes qiymatiga emas.** Sinov serveridagi
  yuqori ball to'lov tizimidagi o'rtachadan yuqori chiqishi mumkin.
  Aktiv qiymati va muhimligi keyingi bosqichda (aktiv modeli) qo'shiladi.
- Log ichidagi manzil soxtalashtirilgan bo'lishi mumkin. Bloklashdan oldin
  ikkinchi manbadan tasdiqlang.
- **`response_sla_review` yopilgan ogohlantirishlar vaqtini bilmaydi.** Legion
  ogohlantirish qachon yopilganini yozmaydi, shuning uchun faqat hali ochiq
  turganlarning necha soatdan beri kutayotganini o'lchaydi. Muddatlar sizning
  tanlovingiz; sukut qiymatlar yuridik yoki shartnoma standarti emas.
- **`sensitive_access_watch` faqat sensor aytgan fayl kirishini ko'radi.** Fayl
  yoki bazaga kirish hodisalari (Wazuh syscheck, audit, baza auditi) ulanmagan
  bo'lsa, u "0" deydi, "xavfsiz" demaydi. Nozik ma'lumotni nomi bo'yicha
  taniydi (customers, payroll, backup...); oddiy nom bilan saqlangan ma'lumot
  ko'rinmaydi.
- **`secret_exposure_check` faqat tanish shakllarni topadi.** O'zingiz yaratgan
  sir yoki g'alati format ko'rinmaydi; "password=" kabi so'zlar bo'yicha taxmin
  xato bo'lishi mumkin. Sirning hali amal qilishini bilmaydi.
- Pul, kripto va moddiy aktivlar hali yo'q: bu keyingi bosqichlar.
