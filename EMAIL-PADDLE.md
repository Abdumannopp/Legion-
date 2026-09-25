# Email (SMTP) va Paddle Billing sozlash

Ikkalasi ham **ixtiyoriy**. Sozlanmasa Legion normal ishlaydi — email jo'natilmaydi,
billing sahifasi esa "sozlanmagan" deb javob beradi.

---

# 1. Email (SMTP)

## Nima uchun kerak

| Funksiya | SMTP'siz | SMTP bilan |
|---|---|---|
| Parolni tiklash | Havola faqat server logida | Foydalanuvchiga xat ketadi |
| Alert bildirishnomasi | Yo'q | Muhim alertlar emailga ketadi |
| `/notifications/test` | "skipped" | Haqiqiy test xati |

## Sozlash

`server/.env` fayliga:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=sizning@gmail.com
SMTP_PASSWORD=app-parolingiz
SMTP_SECURE=false
SMTP_FROM=Legion <sizning@gmail.com>
ALERT_EMAIL_MIN_SEVERITY=high
```

| Kalit | Izoh |
|---|---|
| `SMTP_HOST` | **Bo'sh bo'lsa email butunlay o'chiq** |
| `SMTP_PORT` | `587` (STARTTLS) yoki `465` (SSL) |
| `SMTP_SECURE` | `465` uchun `true`, `587` uchun `false` |
| `SMTP_USER` / `SMTP_PASSWORD` | Bo'sh qoldirilsa autentifikatsiyasiz ulanadi |
| `ALERT_EMAIL_MIN_SEVERITY` | `critical` \| `high` \| `medium` \| `low` \| `off` |

### Gmail uchun

Oddiy parol ishlamaydi. Google hisobingizda 2FA yoqing, so'ng
**App Password** yarating va uni `SMTP_PASSWORD` ga qo'ying.

### Boshqa xizmatlar

| Xizmat | Host | Port |
|---|---|---|
| SendGrid | `smtp.sendgrid.net` | 587 |
| Mailgun | `smtp.mailgun.org` | 587 |
| Resend | `smtp.resend.com` | 587 |
| Yandex | `smtp.yandex.ru` | 465 (`SMTP_SECURE=true`) |

## Alert emaili qayerga ketadi

Dashboard → **Settings** → notification email. Bo'sh bo'lsa hech narsa yuborilmaydi.

Legion'ni qayta ishga tushiring, so'ng **Settings → Send test** tugmasini bosing.

## Tekshirish

```bash
curl -X POST http://localhost:8000/notifications/test -b cookie.txt
```

| Javob | Ma'nosi |
|---|---|
| `{"status":"sent to ..."}` | Ishladi |
| `skipped: SMTP is not configured` | `SMTP_HOST` bo'sh |
| `Set a notification email address first` | Settings'da manzil yo'q |
| `SMTP connection failed: ...` | Host/port/parol xato |

---

# 2. Paddle Billing

## Muhim

To'lov **faqat webhook orqali** faollashadi. Webhook sozlanmasa mijoz pul
to'laydi, lekin obuna faol bo'lmaydi.

## 2.1 Paddle'da kalitlar olish

Paddle Dashboard → **Developer Tools**:

| Kerak | Qayerdan |
|---|---|
| API key (`pdl_...`) | Authentication → API keys |
| Client token | Authentication → Client-side tokens |
| Price ID (`pri_...`) | Catalog → Prices |
| Webhook secret (`pdl_ntfset_...`) | Notifications → yangi destination yaratganda |

## 2.2 Server sozlamasi

`server/.env`:

```env
PADDLE_API_KEY=pdl_sdbx_...
PADDLE_WEBHOOK_SECRET=pdl_ntfset_...
PADDLE_ENVIRONMENT=sandbox
```

## 2.3 Frontend sozlamasi

`frontend/.env.local`:

```env
NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=test_...
NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
NEXT_PUBLIC_PADDLE_PRICE_ID=pri_...
```

`PADDLE_ENVIRONMENT` va `NEXT_PUBLIC_PADDLE_ENVIRONMENT` **bir xil** bo'lishi shart.
Sandbox kaliti production webhook bilan hech qachon mos kelmaydi.

## 2.4 Webhook manzilini ro'yxatdan o'tkazish

Paddle → Notifications → **New destination**:

- URL: `https://sizning-domeningiz.com/billing/webhook`
- Quyidagi hodisalarni tanlang:
  - `subscription.created`
  - `subscription.updated`
  - `subscription.activated`
  - `subscription.canceled`
  - `subscription.paused`
  - `subscription.resumed`

> Paddle internetdan kirish imkoni bo'lgan HTTPS manzilni talab qiladi.
> Lokal sinov uchun `ngrok http 8000` ishlatib, chiqqan manzilni qo'ying.

## 2.5 Tenant qanday aniqlanadi

```
Foydalanuvchi "Upgrade" bosadi
  → Legion checkout_token yaratadi (imzolangan JWT, ichida tenant_id)
  → Paddle.js uni custom_data ichida checkout'ga uzatadi
  → Paddle webhookda uni qaytaradi
  → Legion tokenni tekshirib, obunani to'g'ri tenantga bog'laydi
```

Shu sababli brauzer boshqa tenantning obunasini o'g'irlay olmaydi —
tenant ID brauzerdan emas, imzolangan tokendan olinadi.

## 2.6 Webhook javoblari

| Javob | Ma'nosi |
|---|---|
| `202 processed` | Obuna yangilandi |
| `202 ignored` | Obunaga aloqasi yo'q hodisa (masalan `transaction.completed`) |
| `202 skipped, stale event` | Eskiroq hodisa keyin keldi — e'tiborsiz qoldirildi |
| `202 skipped, no valid checkout_token` | `custom_data` da token yo'q yoki yaroqsiz |
| `401 Invalid signature` | `PADDLE_WEBHOOK_SECRET` xato |
| `401 Signature timestamp outside tolerance` | Server soati noto'g'ri (NTP sozlang) |
| `503 Paddle webhook secret is not configured` | `.env` da sir yo'q |

---

## Xavfsizlik

- Paddle imzosi **xom baytlar** ustidan tekshiriladi. JSON qayta
  serializatsiya qilinsa imzo hech qachon mos kelmaydi.
- Taqqoslash `timingSafeEqual` bilan — vaqt bo'yicha hujumdan himoyalangan.
- 5 daqiqadan eski imzolar rad etiladi (replay hujumiga qarshi).
- SMTP xatoliklari hech qachon foydalanuvchiga qaytarilmaydi va alert
  qabul qilishni to'xtatmaydi.
- Parol tiklash havolasi production'da **hech qachon** logga yozilmaydi.
