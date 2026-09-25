# Legion — AI Cybersecurity SaaS

🇬🇧 [English](README.md) | 🇺🇿 O'zbekcha

AI-native platformasi: tahdidlarni aniqlaydi (Sentinel, Hunter), xavf darajasini
baholaydi (Guardian), tushuntiradi (Oracle), va bildirishnoma yuboradi.

Bu papkada butun loyiha bor:

```
legion/
├── backend/    — FastAPI API (login, alertlar, Oracle AI, Gmail)
├── frontend/   — Next.js dashboard
└── docker-compose.yml   — hammasini bitta buyruq bilan ishga tushiradi
```

## Eng oson ishga tushirish yo'li: Docker

Bu — **hech qanday Python yoki Node o'rnatmasdan** butun loyihani ishga
tushiradigan yo'l.

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) o'rnating
   va oching (u ishga tushib turishi kerak)
2. Terminalda ushbu papkaga o'ting va:

```
cp .env.example .env
docker compose up --build
```

3. Bir necha daqiqadan so'ng:
   - Dashboard: `http://localhost:3000`
   - API hujjatlari: `http://localhost:8000/docs`
   - Kirish: `admin@legion.demo` / `legion123`

4. To'xtatish uchun: `Ctrl+C`, keyin `docker compose down`
   (ma'lumotlarni butunlay o'chirish uchun: `docker compose down -v`)

**Eslatma:** `.env` faylida `HF_API_TOKEN` va `GMAIL_APP_PASSWORD`ni bo'sh
qoldirsangiz ham bo'ladi — loyiha baribir ishga tushadi, faqat Oracle
tushuntirishi va Gmail xabarlari o'chirilgan bo'ladi. Ularni keyinroq
qo'shishingiz mumkin (`backend/README.md`da batafsil yozilgan).

## Docker'siz ishga tushirish

Agar Docker o'rnatishni xohlamasangiz, `backend/README.md` va
`frontend/README.md` fayllarida Python/Node orqali alohida ishga tushirish
yo'riqnomasi bor.

## GitHub'ga yuklash

Kodni GitHub'da saqlash uchun eng oson yo'l — **GitHub Desktop** (buyruqlar
yozish shart emas):

1. [github.com](https://github.com)da bepul hisob oching (agar hali yo'q bo'lsa)
2. [desktop.github.com](https://desktop.github.com)dan GitHub Desktop'ni
   o'rnating va o'z hisobingiz bilan kiring
3. GitHub Desktop'da: **File → Add Local Repository** → ushbu `legion` papkasini
   tanlang
4. Agar "This directory does not appear to be a Git repository" desa,
   **"create a repository"** havolasini bosing
5. Pastda "Summary" qatoriga masalan "Legion loyihasi" deb yozib,
   **"Commit to main"** tugmasini bosing
6. Yuqorida **"Publish repository"** tugmasini bosing — nomini tanlang
   (masalan `legion`) va **Private** yoki **Public**ni tanlang
7. Tayyor — kodingiz endi GitHub'da

Keyingi safar o'zgartirish kiritganingizda: GitHub Desktop'ni oching, o'zgargan
fayllarni ko'rasiz, "Commit" va "Push origin" tugmalarini bosasiz.

### Buyruqlar orqali (agar tanlasangiz)

```
cd legion
git init
git add .
git commit -m "Legion loyihasi"
git branch -M main
git remote add origin https://github.com/SIZNING_USERNAME/legion.git
git push -u origin main
```

## Avtomatik tekshiruv (CI)

`.github/workflows/docker-build.yml` fayli — GitHub'ga har safar kod
yuklanganda backend va frontend Docker image'lari muvaffaqiyatli
build bo'lishini avtomatik tekshiradi. Agar kimdir loyihani buzadigan
o'zgarish kiritsa, GitHub sizga "❌ qizil belgi" bilan xabar beradi.

## Arxitektura

```
User → Next.js Dashboard → FastAPI → PostgreSQL
                              │
                              ├── Oracle agent → Hugging Face API
                              └── Notifications → Gmail (SMTP)
```

## Litsenziya

Proprietary — barcha huquqlar himoyalangan. Ushbu kod loyiha egasidan
tashqari hech kim tomonidan qayta ishlatilishi, tarqatilishi yoki
o'zgartirilishi uchun litsenziyalanmagan.
