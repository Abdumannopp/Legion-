# Eng xavfli yetti hujum turi: Legion nima qiladi, nima qila olmaydi

Dashboard → **Himoya** sahifasida har bir tur uchun holat ko'rinadi:

- **Aniqlandi** — so'nggi 7 kunda belgisi topildi (dalil bilan).
- **Kuzatmoqda** — kerakli ma'lumot kelyapti, belgi topilmadi.
- **Ko'rmaydi** — kerakli ma'lumot Legion'ga **kelmayapti**. Sahifa nimani
  ulash kerakligini aytadi. Jim dashboard ma'lumot kelmasa hech narsani
  anglatmaydi — shuning uchun buni ochiq aytamiz.
- **Qisman ko'radi** — faqat AI aldovi uchun (pastga qarang).

Belgi topilsa, Legion darhol bitta ogohlantirish chiqaradi (Hunter agenti,
"Hujum kampaniyalari" ro'yxatida) va nima qilish kerakligini yozadi.

| # | Hujum | Legion nimani ushlaydi | Ko'rishi uchun nima ulanishi kerak |
|---|---|---|---|
| 1 | **Ransomware** | Soya nusxalar o'chirilishi (`vssadmin delete shadows`), tiklashni o'chirish (`bcdedit`, `wbadmin`), to'lov talabi xati, fayllarning ommaviy shifrlanishi, **bitta serverda 10 daqiqada 50+ fayl o'zgarishi**. Jiddiylik: kritik. | Wazuh fayl butunligi nazorati (syscheck), jarayon hodisalari |
| 2 | **BEC** (biznes pochtasini buzish) | Xatni tashqariga yo'naltiruvchi yoki yashiruvchi pochta qoidasi, pochtaga kirish berilgan ilova (OAuth), o'chirilgan ikkinchi bosqichli himoya (MFA), o'zgartirilgan bank rekvizitlari. Hisob bo'yicha guruhlanadi. | Microsoft 365 yoki Google Workspace audit loglari (Wazuh office365 moduli) |
| 3 | **Fishing** | Word/Excel/Outlook skript (PowerShell va h.k.) ishga tushirishi, makros, zararli havola bosilishi | Pochta xavfsizlik shlyuzi, kompyuterlardan jarayon hodisalari (Sysmon) |
| 4 | **DDoS** | Loglardagi flood belgilari; ko'p manzilli hujum (`swarm`) va keskin faollik (`velocity`) kampaniyalari. Legion'ning **o'zi** DDoS'dan himoyalangan (EDGE-SECURITY.md) | Veb-server, firewall yoki WAF loglari |
| 5 | **AI hujumi** (deepfake, soxta ovoz/video) | AI'ni boshqarish uchun log ichiga yozilgan matn; soxta qo'ng'iroqdan **keyingi** o'zgarishlar (rekvizit almashishi, xat yo'naltirish, "ovoz klonlash" eslatilgan hodisalar) | Pochta audit loglari + tashkiliy qoida (pastga qarang) |
| 6 | **Kiber josuslik** | Bitta serverda **6+ soat** davomida: o'rnashib olish (persistence) + parol o'g'irlash (mimikatz, lsass) yoki boshqaruv kanali (beacon, DNS tunnel). Jiddiylik: kritik | Jarayon, PowerShell va DNS/firewall hodisalari |
| 7 | **Ta'minot zanjiri hujumi** | Imzo yoki checksum xatosi, zararli paket (typosquatting, dependency confusion), **paket o'rnatilgandan keyin 60 daqiqa ichida** hujumchi harakati (reverse shell, beacon) | Paket o'rnatish va dastur yangilanishi hodisalari |

Barcha yangi qoidalar bir xil: bitta kampaniya = bitta ogohlantirish (har
hodisa uchun alohida emas), har bir tashkilot faqat o'zinikini ko'radi.
Avtomatik IP bloklash bu qoidalarda **ishlamaydi** — ular manzil haqida emas,
server va hisob haqida; ular uchun to'g'ri javob serverni ajratish va hisobni
tiklash (ogohlantirish matnida yozilgan).

## Guardian skill'i: `threat_coverage`

AI agentlaringizga beriladigan skill: yetti tur bo'yicha xuddi shu holatni
(aniqlandi / kuzatmoqda / ko'rmaydi) dalillari bilan qaytaradi.
AGENTLAR.md'ga qarang.

## Halol cheklovlar

- **Legion faqat o'ziga kelgan ma'lumotni ko'radi.** Pochta loglari ulanmagan
  bo'lsa, BEC va fishingni ko'rmaydi — sahifa buni "Ko'rmaydi" deb aytadi.
- **Deepfake qo'ng'iroq yoki video Legion'ga umuman kelmaydi.** Hech qanday
  log tizimi telefondagi soxta ovozni eshitmaydi. Legion faqat undan keyin
  sodir bo'ladigan o'zgarishni ko'radi. Eng yaxshi himoya — **tashkiliy qoida**:
  to'lov rekvizitlari yoki shoshilinch pul o'tkazish so'rovi kelsa, avval
  ma'lum (oldindan saqlangan) raqamga qo'ng'iroq qilib tasdiqlang; xatdagi
  yoki qo'ng'iroq qilgan odam bergan raqamga emas.
- **DDoS'ni saytingizda Legion to'xtatmaydi.** Buning uchun Cloudflare kabi
  chekka xizmat kerak. Legion uni loglardan ko'radi va o'zini himoya qiladi.
- **Belgilar log matniga asoslangan.** Hujumchi log matnini yozishi mumkin;
  topilma — tekshirish uchun yo'nalish, isbot emas. Zaxira nusxa olish va
  rejali yangilanishlar ba'zan shunga o'xshaydi.
- **Ransomware bloklanmaydi, faqat erta aniqlanadi.** Legion fayllarni
  shifrlanishdan to'xtata olmaydi; u bir necha daqiqada ogohlantiradi —
  serverni ajratish va zaxira nusxalarni o'chirilgan (offline) holda saqlash
  sizning qo'lingizda. Offline zaxira nusxa — ransomware'ga qarshi eng ishonchli
  himoya.
- **Josuslik ataylab sekin va jim bo'ladi.** Legion 7 kun ichidagi bosqichlarni
  bog'laydi; undan uzoqroq yoki faqat tarmoq trafigida ko'rinadigan harakatni
  ko'rmasligi mumkin.
- **Ta'minot zanjiri:** Legion yangi paketning ichidagi zararli kodni tahlil
  qilmaydi; u imzo xatosi, ma'lum zararli paket nomi yoki o'rnatishdan keyingi
  shubhali harakat orqali sezadi. Legion'ning **o'z** kutubxonalari esa CI'da
  har safar tekshiriladi (zaiflik topilsa, chiqarilish to'xtaydi).

## To'xtatish: Legion qayerda hujumni to'xtatadi

Aniqlash yetarli emas — Legion qo'li yetadigan joyda hujumni to'xtatadi:

| Hujum | Qanday to'xtatiladi |
|---|---|
| **Ruxsatsiz kirish** (parol topish, spraying) | Bitta manzildan 10 daqiqada 10+ xato yoki 5+ xil hisobga urinish → `credential_attack`. Avtomatik javob yoqilgan bo'lsa, manzil Wazuh orqali **bloklanadi** (WAZUH.md, "Avtomatik javob"). |
| **Buzib kirilgan hisob** | O'sha manzil xatolardan keyin hisobga kirdi → `account_compromise` (kritik). Hujumchi manzili **bloklanadi**; ogohlantirish parolni almashtirish, sessiyalarni tugatish va ikkinchi bosqichli himoyani yoqishni aytadi. |
| **Moliyaviy hujum** (BEC, soxta direktor, o'g'irlangan hisob) | **To'lov tekshiruvi**: to'lov dasturi pul jo'natishdan oldin so'raydi; shubhali to'lov inson telefon orqali tasdiqlaguncha **to'xtatiladi** (TOLOV-TEKSHIRUVI.md). |
| **Fishing** | Fishingning maqsadi — parol yoki pul. O'g'irlangan parol bilan kirish → yuqoridagi bloklash; pul so'rash → to'lov tekshiruvi. Office hujjati skript ishga tushirsa, darhol ogohlantirish. |

Halol chegara: fishing xatining o'zini pochta qutisiga kelishidan oldin
to'xtatish — pochta xavfsizlik shlyuzining (Microsoft Defender for Office,
Google Workspace, Proofpoint va h.k.) ishi; Legion pochta serveringizni
boshqarmaydi. Avtomatik bloklash sukut bo'yicha **o'chiq** — Himoya
sahifasida administrator yoqadi. Ichki (private) manzillar va istisnolar
hech qachon bloklanmaydi.
