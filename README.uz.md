# Legion — AI xavfsizlik konsoli

🇬🇧 [English](README.md) | 🇺🇿 O'zbekcha

> Asosiy, doim yangilanadigan hujjat aslida shu papkadagi
> [README.md](README.md) — u ham o'zbek tilida yozilgan. Ushbu fayl qisqacha
> kirish va GitHub'ga yuklash bo'yicha yo'riqnoma uchun saqlanmoqda.

Wazuh xavfsizlik hodisalarini qabul qiladi, tartiblaydi, tushuntiradi va
keyingi qadamni taklif qiladi. Bu papkada butun loyiha bor:

```
legion/
├── server/       — Express + TypeScript API
├── frontend/     — Next.js dashboard
├── ops/          — backup, restore, verify skriptlari
└── integrations/ — Wazuh integratsiyasi
```

## Ishga tushirish

Docker shart emas — Legion to'g'ridan-to'g'ri Node.js'da ishlaydi. Kerak:
Node.js 20.9+ va PostgreSQL 14+.

```bash
npm install
npm run setup      # bazani yaratadi, sirlarni yozadi, sxemani qo'llaydi
npm run build && npm start
```

Keyin http://localhost:3000 ni oching va birinchi administrator hisobingizni
yarating. Batafsil: [README.md](README.md) va [SINOV.md](SINOV.md).

**Windows:** `.\start-legion.ps1` — yuqoridagi hamma narsani o'zi bajaradi.

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

`.github/workflows/ci.yml` — GitHub'ga har safar kod yuklanganda testlarni,
xavfsizlik tekshiruvlarini va 56 ta hujum ssenariysini avtomatik ishga
tushiradi. Agar kimdir loyihani buzadigan yoki xavfsizlikni pasaytiradigan
o'zgarish kiritsa, reliz bloklanadi. Batafsil: [.github/CI.md](.github/CI.md).

## Arxitektura

```
Foydalanuvchi → Next.js Dashboard → Express API → PostgreSQL
                                        │
                                        ├── Oracle/Copilot → OpenRouter yoki Groq (ixtiyoriy)
                                        └── Bildirishnomalar → SMTP
```

## Litsenziya

Proprietary — barcha huquqlar himoyalangan. Ushbu kod loyiha egasidan
tashqari hech kim tomonidan qayta ishlatilishi, tarqatilishi yoki
o'zgartirilishi uchun litsenziyalanmagan.
