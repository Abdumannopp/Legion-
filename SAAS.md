# Legion'ni pullik onlayn xizmat (SaaS) qilish

Bu qo'llanma oxirida:

- `https://legion.sizningdomen.uz` — mahsulot sahifasi, narx, shartlar;
- har kim o'zi ro'yxatdan o'tadi, emailini tasdiqlaydi va **14 kun bepul** foydalanadi;
- keyin karta bilan (Visa/Mastercard, dollarda) **oylik obuna** sotib oladi —
  pulni **Paddle** oladi, soliq va hisob-fakturalarni ham Paddle hal qiladi;
- to'lamasa — ish maydoni qulflanadi (ma'lumot o'chmaydi), to'lasa — ochiladi.

Kod tomoni tayyor va sinalgan. Quyida **faqat siz qila oladigan** ishlar:
hisoblar ochish, kalitlarni olish va ularni ikki faylga yozish.

> Qonuniy eslatma: shartlar, maxfiylik va qaytarish siyosati matnlari
> dasturning haqiqiy ishlashiga mos yozilgan namuna. Men yurist emasman —
> ishga tushirishdan oldin ularni yuristga ko'rsating. O'zbekistonda o'z
> daromadingiz bo'yicha soliq masalasini buxgalter bilan aniqlang
> (Paddle faqat xaridor tomonidagi QQS/sales tax'ni hal qiladi).

---

## 1-qadam. Serverni SaaS rejimida o'rnating

[DEPLOY-ONLINE.md](DEPLOY-ONLINE.md) dagi 0–7-qadamlarni bajaring, faqat
5-qadamda `setup` buyrug'iga `--saas` qo'shing:

```bash
sudo -u legion npm run setup -- --saas --domain legion.sizningdomen.uz
```

Bu `server/.env` va `frontend/.env.local` ga kerakli bo'sh maydonlarni
yozadi. Hozircha **build qilmang** — avval 2–4-qadamlardagi qiymatlarni
to'ldiring. Server email sozlanmaguncha ataylab ishga tushmaydi (tasdiqlash
xatini yubora olmaydigan SaaS — ishlamaydigan SaaS).

Eslatma: SaaS rejimida 8-qadam (setup token) kerak emas — o'z hisobingizni
ham oddiy mijozdek `/signup` orqali ochasiz.

---

## 2-qadam. Email — Resend

Tasdiqlash, parol tiklash, taklif va alert xatlari shu orqali ketadi.
Resend'ni tanladim: bepul tarifda oyiga 3 000 ta (kuniga 100 ta) xat, SMTP
bor, xatlarga reklama qo'shmaydi. Mijozlar ko'paysa — pullik tarifga
o'tasiz, sozlama o'zgarmaydi.

1. <https://resend.com> da ro'yxatdan o'ting.
2. **Domains → Add domain** → `sizningdomen.uz` (yoki `mail.sizningdomen.uz`).
3. Resend bir nechta DNS yozuvi (TXT, MX) ko'rsatadi — ularni domeningiz
   DNS sozlamalariga **aynan shunday** qo'shing. Qo'shimcha ravishda bitta
   TXT yozuv qo'shing (xatlar spamga tushmasligi uchun):

   | Turi | Nomi | Qiymati |
   |---|---|---|
   | TXT | `_dmarc` | `v=DMARC1; p=none;` |

4. Resend'da **Verify** — hammasi yashil bo'lguncha kuting (daqiqalar–soatlar).
5. **API Keys → Create API key** (Sending access) → kalitni nusxalang (`re_…`).
6. Serverda `/opt/legion/server/.env`:

   ```env
   SMTP_PASSWORD=re_…sizning_kalitingiz
   SMTP_FROM=Legion <no-reply@sizningdomen.uz>
   ```

   `SMTP_FROM` dagi domen 4-bandda tasdiqlangan domen bo'lishi shart.
   Qolgan SMTP qatorlari (`smtp.resend.com`, `465`, `resend`) allaqachon yozilgan.

---

## 3-qadam. Sayt ma'lumotlari

`/opt/legion/frontend/.env.local`:

```env
NEXT_PUBLIC_OPERATOR_NAME=Ism Familiya        # pasportdagidek, lotincha — tashkilot yo'q, shuning uchun o'z nomingiz
NEXT_PUBLIC_SUPPORT_EMAIL=support@sizningdomen.uz
NEXT_PUBLIC_DATA_LOCATION=Germany (Hetzner)   # serveringiz qaysi davlatda — maxfiylik siyosatida yoziladi
NEXT_PUBLIC_PRICE_LABEL=49 USD                # ixtiyoriy; "$" belgisini ishlatmang
```

Paddle domen tekshiruvida shartlarda **sotuvchining haqiqiy ismi** bo'lishini
talab qiladi — shu sabab `NEXT_PUBLIC_OPERATOR_NAME` muhim.
`support@…` manzilini qabul qila olishingiz kerak (Resend faqat yuboradi;
qabul uchun domeningizda pochta yoki email forwarding sozlang).

---

## 4-qadam. To'lov — Paddle (avval sinov, keyin haqiqiy)

Paddle'ning ikkita alohida muhiti bor: **sandbox** (soxta kartalar, pul
yo'q) va **live** (haqiqiy pul). Avval sandbox'da hammasini sinaysiz.

### 4a. Sandbox

1. <https://sandbox-login.paddle.com/signup> da ro'yxatdan o'ting.
2. **Catalog → Products → New product**: nomi `Legion`. Ichida
   **New price**: masalan 49 USD, **recurring, monthly**. Saqlang va narx
   ID sini nusxalang (`pri_…`).
3. **Developer tools → Authentication**:
   - **API key** yarating → `PADDLE_API_KEY` (server uchun, maxfiy);
   - **Client-side token** yarating → `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` (sahifa uchun).
4. **Developer tools → Notifications → New destination**:
   - URL: `https://legion.sizningdomen.uz/api/billing/webhook`
   - Hodisalar: barcha `subscription.*` (created, updated, activated,
     canceled, past_due, paused, resumed);
   - saqlang va **secret key** ni nusxalang → `PADDLE_WEBHOOK_SECRET`.
5. **Checkout → Checkout settings → Default payment link**:
   `https://legion.sizningdomen.uz/billing`
6. Qiymatlarni yozing:

   `server/.env`:
   ```env
   PADDLE_ENVIRONMENT=sandbox
   PADDLE_API_KEY=…
   PADDLE_WEBHOOK_SECRET=…
   ```

   `frontend/.env.local`:
   ```env
   NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
   NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=…
   NEXT_PUBLIC_PADDLE_PRICE_ID=pri_…
   ```

7. Qurib, qayta ishga tushiring:

   ```bash
   cd /opt/legion && sudo -u legion npm run build && systemctl restart legion
   journalctl -u legion -n 20     # "Paddle is in SANDBOX mode" — bu normal
   ```

### 4b. Sinov (to'liq aylanish)

1. `https://legion.sizningdomen.uz` → **Start free trial** → ro'yxatdan o'ting.
2. Emaildagi **Confirm email** tugmasini bosing → kiring. Dashboard ochiladi.
3. **Billing → Subscribe now** → Paddle oynasi. Sinov kartasi:
   `4242 4242 4242 4242`, istalgan kelajakdagi sana, istalgan CVC.
4. Bir necha soniyadan keyin Billing sahifasi **Active** ko'rsatadi.
5. **Manage subscription** → obunani bekor qiling → davr oxirida ish maydoni
   qulflanadi, Billing esa ochiq qoladi.

Shu besh qadam ishlasa — hammasi to'g'ri ulangan.

### 4c. Haqiqiy pul (live)

1. <https://login.paddle.com/signup> da **live** hisob oching (sandbox'dan alohida).
2. Tekshiruvlarni o'ting:
   - **Identity verification** — pasport (tashkilot shart emas: Paddle
     yakka tartibdagi sotuvchilar bilan ham ishlaydi);
   - **Checkout → Website approval** — `https://legion.sizningdomen.uz`.
     Paddle saytda mahsulot tavsifi, narx, shartlar, maxfiylik va qaytarish
     siyosati bo'lishini tekshiradi — bularning hammasi tayyor
     (`/`, `/pricing`, `/terms`, `/privacy`, `/refunds`);
   - pul olish uchun bank hisobi yoki Payoneer.
3. Tasdiqlangach, 4a dagi 2–5-bandlarni **live** hisobda qaytadan bajaring
   (mahsulot, narx, kalitlar, webhook, default payment link — hammasi yangi).
4. Ikkala faylda `sandbox` → `production` va yangi kalitlarni yozing,
   qurib qayta ishga tushiring.
5. O'zingiz haqiqiy karta bilan bir marta sotib olib, keyin **Refund**
   qilib ko'ring.

---

## Qanday ishlaydi (qisqacha)

| Holat | Mijoz nima ko'radi |
|---|---|
| Ro'yxatdan o'tdi, email tasdiqlanmagan | Kira olmaydi; "linkni qayta yuborish" tugmasi bor |
| Sinov muddati (14 kun) | Hammasi ishlaydi |
| Sinov tugadi, obuna yo'q | Ish maydoni qulflangan, ma'lumot saqlanadi, Billing ochiq |
| Obuna faol | Hammasi ishlaydi |
| To'lov o'tmadi (past due) | Faqat o'qish mumkin, o'zgartirib bo'lmaydi |
| Obuna bekor qilindi | Davr oxirigacha ishlaydi, keyin qulflanadi |

- Har bir mijozning ma'lumoti alohida ish maydonida — boshqalar ko'ra olmaydi.
- To'lov faqat Paddle imzolagan webhook orqali faollashadi; brauzer "men
  to'ladim" deb aldab o'ta olmaydi.
- Server o'chib qolsa ham, Paddle soatlab qayta urinadi — to'lov yo'qolmaydi.

## Hali qo'lda qilinadigan ishlar

- **Hisobni o'chirish so'rovi** — mijoz yozadi, siz bazadan o'chirasiz
  (shartlarda "30 kun ichida" deb yozilgan).
- **Barcha mijozlar ro'yxati** — alohida admin paneli yo'q; Paddle
  dashboard'ida (to'lovlar) yoki bazada ko'rinadi.
- **Email limiti** — Resend bepul tarifida kuniga 100 ta xat. Mijozlar
  ko'paysa, pullik tarifga o'ting.
- **Backup** — [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md) 10-qadam; endi bu
  mijozlaringizning ma'lumoti, shuning uchun serverdan tashqariga ham ko'chiring.

## Nimadir ishlamasa

| Belgi | Sabab |
|---|---|
| Server ishga tushmaydi: `SMTP_PASSWORD is empty` | 2-qadam bajarilmagan |
| Tasdiqlash xati kelmaydi | Resend'da domen tasdiqlanmagan yoki `SMTP_FROM` boshqa domen; Resend → Emails bo'limida xatolik ko'rinadi |
| Xat spamga tushadi | `_dmarc` TXT yozuvi va Resend'ning barcha DNS yozuvlari qo'shilganini tekshiring |
| Billing'da "Paddle isn't configured" | `frontend/.env.local` dagi Paddle qiymatlari bo'sh yoki build qilinmagan |
| To'ladi, lekin "Active" bo'lmadi | Paddle → Notifications → destination → loglarda javobni ko'ring; URL `/api/billing/webhook` va secret to'g'riligini tekshiring. Server logi: `journalctl -u legion \| grep Paddle` |
| Narx "—" ko'rinadi | `NEXT_PUBLIC_PADDLE_PRICE_ID` yoki client token yo'q; yoki `PRICE_LABEL` da `$` ishlatilgan |
