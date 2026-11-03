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
| **GPS** | GPS provayderingiz mashina joylashuvini yuboradi, VEYRA uni mashina raqami bo'yicha yukka bog'laydi. Xaritada ochish havolasi ham bor. | GPS provayderi |

Har bir AI so'rovi qayd qilinadi: **Analytics → AI agents** jadvalida qancha so'rov bo'lgani va qancha token sarflangani (AI provayderi shu bo'yicha pul oladi) ko'rinadi.

## Kalitlarni qanday olish (bir martalik ish)

Bu kalitlarni men ololmayman: ular sizning nomingizga ochiladigan hisoblar.
Olgach, serverni o'rnatgan odamga bering yoki `.env` fayliga yozing.

1. **AI (FLOW) — OpenRouter**
   - openrouter.ai saytida ro'yxatdan o'ting, hisobni to'ldiring (kichik summa
     bilan boshlash mumkin).
   - "Keys" bo'limida yangi kalit yarating → `OPENROUTER_API_KEY=` ga yozing.
   - Model tanlash shart emas: bo'sh qolsa, hisobingizdagi standart model ishlaydi.
2. **SMS / WhatsApp — Twilio**
   - twilio.com da hisob oching. "Account SID" va "Auth Token"ni oling.
   - SMS uchun raqam sotib oling. WhatsApp uchun Twilio orqali WhatsApp
     jo'natuvchisini tasdiqlating (Meta tasdig'i kerak, bir necha kun olishi mumkin).
   - `.env`: `MESSAGING_PROVIDER=twilio`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`,
     `TWILIO_SMS_FROM`, `TWILIO_WHATSAPP_FROM`.
   - Telefon raqamlarini xalqaro formatda yozing: **+998 90 123 45 67**.
3. **GPS**
   - Dashboard → Integrations → **Create GPS token**. Chiqqan manzil va kalitni
     GPS provayderingizga bering (kalit faqat bir marta ko'rsatiladi).
   - Provayder har bir mashina uchun raqam, kenglik (lat) va uzunlik (lng) yuboradi.
     Mashina raqami dispatch paytida yozilgan raqam bilan bir xil bo'lishi kerak
     (bo'shliq va tire farq qilmaydi).

## Bir nechta kompaniya

Siz (birinchi administrator) **platforma egasisiz**. Dashboard → **Companies →
Add company** orqali yangi mijoz kompaniyani va uning administratorini
qo'shasiz. Har bir kompaniya faqat o'z yuklari, tashuvchilari va xodimlarini
ko'radi. Kompaniya administratori o'z jamoasini o'zi qo'shadi.

## Ko'p yuk

Shipments sahifasi endi 50 tadan sahifalab ko'rsatadi ("Next →"). Qidiruv va
filtrlar barcha yuklar bo'yicha ishlaydi. CSV eksport hammasini yuklab oladi.

## Hali yo'q narsalar

- **NEXUS** (agentlarni avtomatik bir-biriga ulash): hozir har bir qadamni odam
  boshlaydi, agentlar yordam beradi. Bu ataylab shunday: avval natijani
  pilotda o'lchash kerak.
- Hujjatlar (CMR, yuk xati) yuklash va o'qish (VAULT).
- Kiruvchi xabarlarni avtomatik qabul qilish (mijoz email yuborsa, o'zi yukka
  aylanishi). Hozir xabarni nusxa olib FLOW'ga qo'yasiz.
- Har bir kompaniyaga alohida Twilio hisobi (hozir bitta umumiy).
