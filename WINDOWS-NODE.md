# Legion — Windows PowerShell + Node.js

Bu versiya Python, PostgreSQL yoki Docker talab qilmaydi. Node.js 20.9+ kerak.

## Bir buyruqda ishga tushirish

Arxivni oching, loyiha ichida PowerShell oching va bajaring:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start-legion.ps1
```

Yoki qo'lda:

```powershell
npm install
Copy-Item server\.env.example server\.env
npm run dev
```

- Dashboard: http://localhost:3000
- API health: http://localhost:8000/health
- Demo login: `admin@legion.demo` / `legion123`

Ma'lumotlar `server/data/legion.json` faylida saqlanadi. Uni zaxiralash uchun
Legion'ni to'xtating va shu fayldan nusxa oling.

## Production build

```powershell
npm run build
npm start
```

Production'da `server/.env` ichidagi `JWT_SECRET` uzun, tasodifiy qiymat bo'lishi shart.
