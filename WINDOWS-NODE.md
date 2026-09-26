# Legion — Windows

> **Bu fayl yangilandi (2026-09).** Oldingi versiyasi eskirgan edi: u
> `admin@legion.demo` / `legion123` demo hisobini va `server/data/legion.json`
> faylini tilga olardi. Ikkalasi ham Legion 2.0 da olib tashlangan — demo
> hisob mijoz serverida yaratilmaydi, ma'lumot PostgreSQL'da saqlanadi.
> Hech qachon hammaga ma'lum parol bilan hisob yaratmang.

Node.js 20.9+ va PostgreSQL 14+ kerak. Docker shart emas.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start-legion.ps1
```

Skript Node.js va PostgreSQL'ni tekshiradi, paketlarni o'rnatadi, birinchi
marta `npm run setup` ni ishga tushiradi (sirlar va baza), quradi va Legion'ni
ishga tushiradi.

- Dashboard: http://localhost:3000 — birinchi ochganingizda **o'zingizning**
  administrator hisobingizni yaratasiz; shundan keyin ro'yxatdan o'tish yopiladi.
- API holati: http://localhost:8000/health — `"database":"up"` bo'lishi kerak.

Batafsil, qadamma-qadam: [SINOV.md](SINOV.md). Mijoz uchun to'liq qo'llanma:
[INSTALL.md](INSTALL.md).

**Eslatma:** Windows — faqat sinov va baholash uchun. Odamlar tayanadigan
server uchun Linux + Docker (`./install.sh`) ishlating.
