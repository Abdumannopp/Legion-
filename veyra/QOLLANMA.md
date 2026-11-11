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

## Xatdagi fayllar, xabar holati va uchta yangi agent

- **Xatga biriktirilgan fayllar (CMR).** Xat mavzusida yoki matnida yuk raqami
  (masalan `SHP-12`) yoki yukning o'z raqami (reference) bo'lsa, fayl o'sha
  yukning hujjatlariga o'zi qo'shiladi va VAULT uni o'qiydi. Yuk raqami
  bo'lmasa, fayl xat bilan birga "Inbox & tasks" sahifasida kutadi: "Attach
  files to a load" tugmasi bilan yukni ko'rsatasiz, yoki xatdan yangi yuk
  yaratsangiz fayl o'sha yukka o'tadi. Faqat PDF, JPG, PNG, WebP qabul
  qilinadi; bitta xatdan ko'pi bilan 5 ta fayl; imzodagi kichik logotiplar
  tashlab yuboriladi. Ruxsat berilmagan jo'natuvchining fayllari saqlanmaydi.
- **SendGrid va Mailgun.** Endi fayl biriktirilgan xatlar to'g'ridan-to'g'ri
  qabul qilinadi (SendGrid Inbound Parse, Mailgun, Postmark, Zapier/Make).
- **Xabar holati.** Yuk oynasidagi xabarlar ro'yxatida "sent ✓", "delivered ✓✓",
  "read ✓✓" yoki "not delivered" ko'rinadi. "Read" faqat WhatsApp'da va
  qabul qiluvchi o'qilganlik belgisini yoqqan bo'lsa keladi. Xabar yetib
  bormasa, "qo'ng'iroq qiling" degan vazifa paydo bo'ladi. Buning uchun server
  o'z internet manzilini bilishi kerak: Render va Railway'da bu o'zi ishlaydi,
  boshqa joyda `PUBLIC_URL=https://sizning-manzil` ni yozing.
- **ROUTE (marshrut).** Yuk oynasida: shu yo'nalish avval necha soat olgani,
  va'da qilingan sana yetadimi, mashina taxminan qachon yetib borishi, va
  yuklash shahriga yaqinda bo'shaydigan mashinalar (qaytish yuki uchun).
- **PULSE (narx).** Yuk oynasida va mashina band qilish oynasida: shu
  yo'nalishda odatda qancha to'langani, mijozga tavsiya narx, va narx
  odatdagidan 30% dan ko'p farq qilsa yoki yuk zarar keltirsa ogohlantirish.
- **SENTINEL (xavf).** "Inbox & tasks" sahifasi tepasida: mashina topilmagan
  va yuklash bugun/ertaga; yuklash kuni o'tdi, mashina jo'namadi; yetkazish
  kuni o'tdi; haydovchi aytgan vaqt va'dadan kech; haydovchi telefoni yoki
  mashina raqami yo'q; mashina jim; xabar yetmadi. Xavf yo'qolsa vazifa o'zi
  yopiladi.

ROUTE, PULSE va SENTINEL sun'iy intellekt kalitisiz ishlaydi: ular faqat
sizning o'z yuklaringiz tarixiga qaraydi. Shuning uchun yo'nalishda kamida
3 ta yetkazilgan yuk bo'lmaguncha ROUTE va PULSE "ma'lumot yetarli emas" deydi.

## Pochta qutisini o'qish, xarita va bozor narxlari

- **Pochta qutisi (IMAP).** "Integrations → Order mailbox" da pochta serveri
  (masalan `imap.gmail.com`), foydalanuvchi nomi va parolni kiritasiz. Gmail va
  Outlook uchun oddiy parol emas, "app password" (ilova paroli) kerak. VEYRA
  ulashdan oldin kirib ko'radi; parol shifrlab saqlanadi va hech qachon
  ko'rsatilmaydi. Keyin har 5 daqiqada yangi xatlarni o'zi o'qiydi, xuddi inbox
  manziliga kelgandek (CMR yukka qo'shiladi, buyurtma vazifaga aylanadi).
  Ulashdan oldingi eski xatlar olinmaydi; qutidagi hech narsa o'zgarmaydi va
  "o'qilgan" deb belgilanmaydi. Shaxsiy (ichki) tarmoq manzillari xavfsizlik
  uchun rad etiladi.
- **Fayl turini almashtirish.** Hujjat kartasida tur ro'yxati bor: noto'g'ri
  taxmin qilingan bo'lsa tanlab qo'yasiz, CMR/POD bo'lsa qaytadan o'qiladi.
- **Xarita (masofa, yo'ldan chetga chiqish).** Sukut bo'yicha O'CHIRILGAN, chunki
  yuk shaharlari nomlari OpenStreetMap xizmatlariga yuboriladi. Yoqish uchun
  serverda `GEO_PROVIDER=osm`. Keyin ROUTE yuk oynasida yo'l masofasini va
  haydash vaqtini ko'rsatadi (tarix bo'lmasa shundan taxmin qiladi), SENTINEL
  esa GPS bor mashina yo'ldan 60 km (`OFF_ROUTE_KM`) dan uzoqlashsa ogohlantiradi.
  Ommaviy xizmatlar yengil foydalanish uchun; har bir yo'nalish bir marta
  so'raladi va saqlanadi.
- **Bozor narxlari.** "Integrations → Market prices" da brokeringiz yoki yuk
  birjasidagi narxlarni qo'lda kiritasiz (har qatorda: `Yo'nalish boshi; oxiri;
  mashina turi (ixtiyoriy); narx`). PULSE ularni o'z tarixingiz bilan birga
  ko'rsatadi va narx bozordan 30% dan qimmat bo'lsa ogohlantiradi.

## Gmail/Outlook bilan ulash, tirbandlik va chegara kutish

- **Gmail / Outlook (IMAP'siz, ilova parolisiz).** "Integrations → Order mailbox"
  da "Connect Gmail" yoki "Connect Outlook" tugmasi bor. Bosilsa Google yoki
  Microsoft'ning o'z oynasi ochiladi, siz ruxsat berasiz va qaytasiz. VEYRA
  parolingizni ko'rmaydi: faqat "faqat o'qish" ruxsati va shifrlangan uzoq muddatli
  kalit saqlanadi. Xatlar faqat o'qiladi (o'chirilmaydi, belgilanmaydi), ulashdan
  oldingi eski xatlar olinmaydi.
  **Muhim:** bu tugmalar ishlashi uchun VEYRA egasi (siz) bir marta Google Cloud va
  Microsoft Entra'da "ilova" ro'yxatdan o'tkazib, `GOOGLE_CLIENT_ID`/`SECRET` va
  `MICROSOFT_CLIENT_ID`/`SECRET` ni serverga yozishi kerak (qadamlari
  `DEPLOYMENT.md` da). Google begona kompaniyalar pochtasini o'qiydigan ilovani
  tekshiradi: bu vaqt oladi. Shu vaqtgacha IMAP ishlaydi. Kalit yo'q bo'lsa tugma
  o'chiq turadi va sababi yoziladi.
- **Yo'ldagi tirbandlik.** `TRAFFIC_PROVIDER=tomtom` va TomTom kaliti kerak (xarita
  ham yoqilgan bo'lishi shart). Faqat yo'lga chiqqan mashina uchun ko'rsatiladi
  ("Traffic now: 90 min of delay"), 30 daqiqa saqlanadi. Bir hafta keyingi sayohat
  uchun bugungi tirbandlik hisobga olinmaydi, chunki u haqida hech narsa demaydi.
- **Chegarada kutish.** Jonli chegara navbatini beradigan bepul ochiq manba yo'q, shuning
  uchun "Integrations → Border waiting times" da chegara bo'yicha odatiy kutish
  soatini o'zingiz yozasiz (`UZ; KZ; 6`). Shahar nomi mamlakat kodi bilan
  tugashi kerak ("Tashkent, UZ"). ROUTE bu soatni faqat yo'nalishda o'z tarixingiz
  hali bo'lmaganda qo'shadi (tarixdagi sayohatlarda u allaqachon bor).

## Hali yo'q narsalar

- Chegara navbatini jonli ko'rish (bepul ochiq manba yo'q; hozircha qo'lda).
- Bozor narxlarini internetdan avtomatik olish (qo'lda kiritiladi).
- Gmail/Outlook, tirbandlik va xarita qismi haqiqiy xizmatlar bilan hali sinalmagan:
  faqat soxta javoblar bilan tekshirilgan. Birinchi ulashda natijani o'zingiz ko'rib chiqing.
