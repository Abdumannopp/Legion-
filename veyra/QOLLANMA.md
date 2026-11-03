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

## Hali yo'q narsalar

- AI agentlar (FLOW, SCOUT, RELAY, TRACE) — bu keyingi bosqich. Hozir hamma
  qadamni odam bajaradi, tizim esa tartib, nazorat va tarixni saqlaydi.
- GPS orqali avtomatik kuzatuv, SMS/WhatsApp xabarlar, hujjatlar (CMR) yuklash.
- Bir nechta kompaniya (tenant) bitta serverda.
- 200 tadan ortiq yukni ro'yxatda sahifalab ko'rsatish.
