# Legion Dashboard

Legion loyihasining Alert Triage boshqaruv paneli — Next.js + Tailwind CSS asosida,
FastAPI backend'ga ulangan.

## Ishga tushirish

**1. Avval backend'ni ishga tushiring** (`legion-backend` papkasida, uning o'z
README'siga qarang). Backend odatda `http://localhost:8000` manzilida ishlaydi.

**2. Shu papkada:**

```
npm install
cp .env.local.example .env.local
npm run dev
```

3. Brauzerda `http://localhost:3000` manzilini oching — login sahifasiga
   yo'naltiriladi
4. Kirish uchun: `admin@legion.demo` / `legion123` (agar backend `python -m app.seed`
   bilan to'ldirilgan bo'lsa)

## Internetga chiqarish (deploy)

Eng oson yo'l — [vercel.com](https://vercel.com):

1. Ushbu papkani GitHub'ga yuklang (repo yarating)
2. Vercel'da "New Project" bosing va o'sha repo'ni tanlang
3. Environment Variables bo'limida `NEXT_PUBLIC_API_URL`ni backend'ingiz haqiqiy
   manziliga o'rnating (masalan, Railway yoki Render'da joylashtirilgan backend URL'i)
4. "Deploy" tugmasini bosing

## Fayl tuzilishi

- `app/page.tsx` — asosiy sahifa (dashboard)
- `app/login/page.tsx` — kirish sahifasi
- `components/LegionDashboard.tsx` — dashboard'ning barcha mantig'i va dizayni
- `lib/api.ts` — backend bilan gaplashadigan barcha funksiyalar (login, alertlar,
  Oracle tushuntirishi)
- `app/layout.tsx` — sahifa sarlavhasi va umumiy o'rash (wrapper)

## Qanday ishlaydi

- Token brauzerning `localStorage`'ida saqlanadi
- Har bir sahifa ochilganda token borligini tekshiradi; yo'q bo'lsa `/login`ga
  yo'naltiradi
- Alert ustiga bosilganda kengayadi — u yerda "Ask Oracle to explain" tugmasi
  bor, bu backend'dagi AI agentni chaqiradi va javobni saqlaydi
- "Investigate" / "Resolve" tugmalari real vaqtda backend'dagi holatni yangilaydi

