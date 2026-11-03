# VEYRA — yuk mashinasi uchun qisqa qo'llanma

Bu qo'llanma texnik bilim talab qilmaydi. Unda VEYRA'da bitta yukni
buyurtmadan yetkazib berishgacha qanday olib borish tushuntirilgan.

## Rollar

| Rol | Kim | Nima qila oladi |
|---|---|---|
| **Admin** | Rahbar | Hamma narsa + xodim qo'shish, rolini o'zgartirish, bloklash |
| **Operations** | Operatsiya menejeri | Yuk yaratish, statusni o'zgartirish, tashuvchi biriktirish (dispatch), analitika |
| **Operator** | Dispetcher | Yuk yaratish, mashina qayerdaligini yozish, ro'yxatlarni ko'rish |

## Bitta yukning yo'li

1. **Buyurtma keldi.** "New Shipment" tugmasi → mijoz, qayerdan, qayerga,
   sanalar, og'irlik (kg), mashina turi. Mijoz to'laydigan narxni ham yozsa
   bo'ladi (ixtiyoriy).
2. **Tashuvchi qidirish.** Yukni **Sourcing** holatiga o'tkazing.
3. **Mashina band qilish (Dispatch).** Tashuvchini tanlang va yozing:
   - tashuvchiga to'lanadigan narx;
   - mijoz to'laydigan narx — **marja (foyda) darhol ko'rinadi**;
     agar zarar bo'lsa, tizim ogohlantiradi;
   - mashina raqami, haydovchi ismi va telefoni.
4. **Yo'lda.** Yukni oching (ID ustiga bosing) → **"Where is the truck now?"**
   maydoniga joylashuvni yozing (masalan, "Chimkent" yoki "chegara"),
   kutilayotgan yetib kelish vaqti (ETA) va izoh. Haydovchiga qo'ng'iroq
   qilgan har safar shu yerga yozing.
   - 12 soat davomida yangilanmagan mashinalar qo'ng'iroqcha (bildirishnoma)
     orqali eslatiladi.
5. **Yetkazildi.** Statusni **In Transit** → **Delivered** qiling.
   Tashuvchi avtomatik yana bo'sh (Available) bo'ladi.
   - Muammo bo'lsa: **Exception**.
   - Mashina hali yuk olmasdan bekor qilinsa: Dispatched → **Cancelled**.

## Xodim qo'shish

Haqiqiy serverda begona odam o'zi ro'yxatdan o'ta olmaydi. Xodimlarni admin
qo'shadi: **Dashboard → Operations Console → Team Access → Add user**.
Boshlang'ich parolni xodimga shaxsan bering. Xodim ishdan ketsa, **Disable**
tugmasi uni darhol tizimdan chiqaradi.

## Sozlamalar (serverni o'rnatuvchi uchun)

`.env` faylida:

- `WEIGHT_UNIT=kg` — og'irlik birligi (`kg` yoki `lb`);
- `CURRENCY=UZS` — valyuta (USD, EUR, UZS, KZT …);
- `MAX_RATE=10000000000` — so'm kabi katta raqamli valyuta uchun eng katta narx;
- `INITIAL_ADMIN_NAME`, `INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_PASSWORD` —
  birinchi admin (parol kamida 12 belgi).

Batafsil: `DEPLOYMENT.md`.

## AI yordamchilar (agentlar)

| Agent | Nima qiladi | Nima kerak |
|---|---|---|
| **FLOW** | Mijozning xabarini (email, WhatsApp) "New Shipment" oynasiga qo'yasiz → **Read with AI** → forma o'zi to'ladi. Yetishmagan maydonlar sariq bilan belgilanadi va mijozga qanday savol berish kerakligi yoziladi. Yukni baribir siz **Create** bosib yaratasiz. | OpenRouter kaliti |
| **SCOUT** | Dispatch oynasida eng mos 3 ta tashuvchini ko'rsatadi: mashina turi to'g'ri keladimi, shu yo'nalishda necha marta yetkazgan, muammolari bo'lganmi. Shu yo'nalishdagi o'rtacha narxni ham taklif qiladi. Bossangiz forma to'ladi. | Hech narsa (bepul) |
| **RELAY** | Yuk oynasida "Messages": haydovchi, tashuvchi yoki mijozga tayyor matn (o'zbek, rus, ingliz tillarida). Matnni tahrirlab **Send** (SMS/WhatsApp) yoki **Copy text** bosib o'z telefoningizdan yuborasiz. | Avtomatik yuborish uchun Twilio |
| **NEXUS** | Boshqa agentlarni **o'zi ishga tushiradi** va natijani sizga **vazifa** qilib qo'yadi (chap menyuda **Inbox & tasks**). Masalan: email keldi → FLOW o'qidi → "Yangi buyurtma" vazifasi. Yuk Sourcing'ga o'tdi → SCOUT tashuvchilarni tanladi → "Tashuvchi band qiling" vazifasi. Mashina band qilindi → haydovchi, tashuvchi va mijozga xabar matnlari tayyor. Mashina 12 soat jim → "Qayerdasiz?" matni tayyor. | Hech narsa |
| **VAULT** | Yuk oynasida **Documents**: CMR yoki POD (rasm yoki PDF) yuklaysiz, AI o'qiydi va yuk bilan solishtiradi: og'irlik, mashina raqami, yuklash va tushirish joyi, mijoz, sana. Farq bo'lsa vazifa chiqadi. Hech narsa o'zgartirilmaydi. | OpenRouter kaliti va rasm/PDF o'qiy oladigan model |
| **Email inbox** | Mijoz email yozadi → VEYRA o'zi qabul qiladi, FLOW o'qiydi, siz **Inbox & tasks**da tayyor buyurtmani ko'rasiz va **Create load** bosasiz. | Email xizmati (pastda) |
| **GPS** | GPS provayderingiz mashina joylashuvini yuboradi, VEYRA uni mashina raqami bo'yicha yukka bog'laydi. Xaritada ochish havolasi ham bor. | GPS provayderi |

**Eng muhim qoida (NEXUS haqida):** NEXUS faqat **tayyorlaydi**. U hech qachon o'zi xabar yubormaydi, mashina band qilmaydi, yuk yaratmaydi va statusni o'zgartirmaydi. Har bir tashqi harakat uchun siz tugmani bosasiz ("Approve & send", "Create load", "Dispatch"). Bu xatoning narxi katta bo'lgan joyda AI'ga erkinlik bermaslik uchun ataylab shunday.

Har bir AI so'rovi qayd qilinadi: **Analytics → AI agents** jadvalida qancha so'rov bo'lgani va qancha token sarflangani (AI provayderi shu bo'yicha pul oladi) ko'rinadi. Xarajat nazorati: har bir kompaniya uchun kuniga 300 ta avtomatik AI so'rovi limiti bor, undan keyin email va hujjatlar o'qilmay, oddiy vazifa bo'lib qoladi.

## Kalitlarni qanday olish (bir martalik ish)

Bu kalitlarni men ololmayman: ular sizning nomingizga ochiladigan hisoblar.
Olgach, serverni o'rnatgan odamga bering yoki `.env` fayliga yozing.

1. **AI (FLOW, VAULT) — OpenRouter**
   - openrouter.ai saytida ro'yxatdan o'ting, hisobni to'ldiring (kichik summa
     bilan boshlash mumkin).
   - "Keys" bo'limida yangi kalit yarating → `OPENROUTER_API_KEY=` ga yozing.
   - FLOW uchun model tanlash shart emas: bo'sh qolsa, hisobingizdagi standart model ishlaydi.
   - **CMR o'qish uchun** rasm yoki PDF o'qiy oladigan model kerak. Standart model
     o'qiy olmasa, hujjatda "o'qib bo'lmadi" deb yoziladi. Unda `OPENROUTER_MODEL=`
     ga openrouter.ai/models ro'yxatidan rasm qo'llab-quvvatlaydigan modelni yozing.
2. **SMS / WhatsApp — Twilio (har bir kompaniya o'zining hisobi bilan)**
   - twilio.com da hisob oching. "Account SID" va "Auth Token"ni oling.
   - SMS uchun raqam sotib oling. WhatsApp uchun Twilio orqali WhatsApp
     jo'natuvchisini tasdiqlating (Meta tasdig'i kerak, bir necha kun olishi mumkin).
   - Dashboard → Integrations → **Connect Twilio** → ma'lumotlarni kiriting.
     VEYRA ularni avval Twilio'da **tekshiradi**, keyin **shifrlab** saqlaydi va
     hech qachon qayta ko'rsatmaydi.
   - Muhim: boshqa kompaniya sizning Twilio hisobingizdan **foydalana olmaydi**.
     Har bir mijoz kompaniya o'z hisobini ulaydi va xabar narxini o'zi to'laydi.
   - Telefon raqamlarini xalqaro formatda yozing: **+998 90 123 45 67**.
   - Serverda `SECRETS_KEY` (uzun tasodifiy matn) qo'ying va **saqlab qo'ying**:
     u o'zgarsa, saqlangan Twilio ma'lumotlari o'qilmay qoladi va qayta kiritiladi.
3. **Email (buyurtmalarni avtomatik qabul qilish)**
   - Dashboard → Integrations → **Email inbox → Create address**. Chiqqan manzil
     (faqat bir marta ko'rsatiladi) — bu pochta emas, veb-manzil.
   - Uni email xizmatiga bering: **Postmark** (inbound), **Mailgun** (route →
     "forward to URL") yoki **Zapier / Make** (yangi email → webhook POST). Keyin
     mijozlar yozadigan manzilni shu xizmatda sozlaysiz yoki o'z pochtangizdan
     buyurtmalarni unga yo'naltirasiz.
   - **Allowed senders**ni to'ldiring (masalan, `mijoz.com, boss@hamkor.com`):
     boshqa jo'natuvchilar o'qilmaydi va AI pulini sarflamaydi.
4. **GPS**
   - Dashboard → Integrations → **Create GPS token**. Chiqqan manzil va kalitni
     GPS provayderingizga bering (kalit faqat bir marta ko'rsatiladi).
   - Provayder har bir mashina uchun raqam, kenglik (lat) va uzunlik (lng) yuboradi.
     Mashina raqami dispatch paytida yozilgan raqam bilan bir xil bo'lishi kerak
     (bo'shliq va tire farq qilmaydi).

## Bir nechta kompaniya

Siz (birinchi administrator) **platforma egasisiz**. Dashboard → **Companies →
Add company** orqali yangi mijoz kompaniyani va uning administratorini
qo'shasiz. Har bir kompaniya faqat o'z yuklari, tashuvchilari, xodimlari,
hujjatlari, emaillari, vazifalari va Twilio hisobini ko'radi. Kompaniya
administratori o'z jamoasini o'zi qo'shadi.

## Ko'p yuk

Shipments sahifasi 50 tadan sahifalab ko'rsatadi ("Next →"). Qidiruv va
filtrlar barcha yuklar bo'yicha ishlaydi. CSV eksport hammasini yuklab oladi.

## Hujjatlar bilan ishlash

- Qabul qilinadi: PDF, JPG, PNG, WebP (8 MB gacha). Fayl turi nomiga qarab emas,
  haqiqiy mazmuniga qarab tekshiriladi; boshqa fayllar rad etiladi.
- Fayllar ma'lumotlar bazasi ichida saqlanadi, shuning uchun **zaxira nusxa**
  (backup) ularni ham qamrab oladi. Zaxira nusxani sozlashni unutmang.
- Hujjat o'qilgach, "mos" / "farq qiladi" ko'rsatiladi. "Farq qiladi" — bu faqat
  ogohlantirish: qog'ozni yuk bilan o'zingiz solishtirib, kerak bo'lsa
  tuzatasiz. Yozuv o'zi o'zgarmaydi.

## Hali yo'q narsalar

- Email xizmatlaridan multipart (fayl biriktirilgan) xatlarni to'g'ridan-to'g'ri
  qabul qilish (SendGrid Inbound Parse). Hozir Postmark, Mailgun (oddiy xatlar)
  va Zapier/Make ishlaydi. Xatga biriktirilgan CMR avtomatik yukka qo'shilmaydi:
  uni yuk oynasida o'zingiz yuklaysiz.
- Sizning serveringizda email qutisini to'g'ridan-to'g'ri o'qish (IMAP).
- Twilio xabarlarining yetkazilganlik holatini (delivered/read) qaytarib olish.
- ROUTE, PULSE, SENTINEL agentlari (marshrut, narx tahlili, xavf aniqlash).
