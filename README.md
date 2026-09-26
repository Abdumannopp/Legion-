# Legion

**Wazuh alertlarini tushunarli qaroriga aylantiradigan xavfsizlik konsoli.**

Legion sizning serveringizda ishlaydi. Ma'lumotingiz sizning tarmog'ingizdan
chiqmaydi.

- Wazuh hodisalarini real vaqtda qabul qiladi va tartiblaydi
- Har bir alertni tushuntiradi va keyingi qadamni taklif qiladi
- Aktivlar inventarizatsiyasini sensorlardan avtomatik to'ldiradi
- Jamoa, rollar (admin / analitik / kuzatuvchi) va to'liq audit jurnali
- Ikki bosqichli autentifikatsiya (TOTP)

---

## O'rnatish

**Kerak:** Linux server, Docker va Docker Compose. 2 GB RAM yetarli.

```bash
git clone <repo> legion && cd legion
./install.sh
```

Skript sirlarni yaratadi, `.env` yozadi va hamma narsani ishga tushiradi.
Tugagach http://localhost:3000 ni oching va **darhol birinchi administrator
hisobini yarating** — u yaratilmaguncha sahifaga birinchi yetgan odam admin
bo'lib oladi. Dashboard va API standart holatda faqat `127.0.0.1` da tinglaydi
(`.env` → `LEGION_BIND_ADDRESS`); tashqaridan kirish uchun HTTPS proxy qo'ying.

> Birinchi hisob yaratilgach ro'yxatdan o'tish avtomatik **yopiladi**. Qolgan
> xodimlar Settings → Team orqali taklif bilan qo'shiladi. Ya'ni serveringiz
> internetda ochiq bo'lsa ham, begona odam hisob ocha olmaydi.

Boshqa manzilda ishlatish uchun `.env` da `FRONTEND_URL` va
`NEXT_PUBLIC_API_URL` ni o'zgartiring va `./install.sh` ni qayta ishga
tushiring.

### Docker'siz — faqat Node.js bilan

Node.js 20.9+ va PostgreSQL 14+ o'rnatilgan bo'lsa, Docker kerak emas:

```bash
npm install
npm run setup      # bazani yaratadi, sirlarni yozadi, sxemani qo'llaydi
npm run build && npm start
```

`npm run setup` PostgreSQL'ni o'zi topadi. Topa olmasa, host va superuser
parolini so'raydi — boshqa hech narsa qilish kerak emas.

**Windows:** `.\start-legion.ps1` — yuqoridagi hamma narsani o'zi bajaradi.

Batafsil qadamma-qadam: [SINOV.md](SINOV.md)

---

## Keyingi qadamlar

| Vazifa | Hujjat |
|---|---|
| **Mijozga beriladigan to'liq qo'llanma** (ingliz tilida) | [INSTALL.md](INSTALL.md) |
| Wazuh'ni ulash | [WAZUH.md](WAZUH.md) |
| Backup sozlash | [BACKUP.md](BACKUP.md) |
| HTTPS orqasiga qo'yish | [deploy/nginx.conf](deploy/nginx.conf) |
| Email (parol tiklash, taklif) | `.env` dagi `SMTP_*` |

### HTTPS haqida

Legion standart holatda HTTP'da ishlaydi, chunki ko'p o'rnatmalar ichki
tarmoqda bo'ladi. Agar server internetdan ochiq bo'lsa:

1. `deploy/nginx.conf` ni sertifikatingiz bilan sozlang
2. `.env` da `COOKIE_SECURE=true` qiling
3. `./install.sh` ni qayta ishga tushiring

`COOKIE_SECURE=true` ni HTTPS'siz qo'ymang — sessiya cookie'si yuborilmay
qoladi va hech kim kira olmaydi.

---

## AI haqida (muhim)

Oracle va Copilot **ixtiyoriy**. Hech qanday kalit qo'yilmasa:

- Ikkalasi ham ishlaydi, lekin lokal, deterministik tahlil bilan
- **Hech qanday ma'lumot serveringizdan chiqmaydi**

Ikkita variant bor, bittasini tanlang:

```env
OPENROUTER_API_KEY=sk-or-…     # bitta kalit — ko'p sotuvchi, bepul modellar ham bor
OPENROUTER_MODEL=              # bo'sh = OpenRouter hisobingizdagi standart model

GROQ_API_KEY=gsk-…             # muqobil
```

Model tanlash: <https://openrouter.ai/models>

Kalit qo'shsangiz, alert sarlavhasi, tavsifi, hostname va IP manzillari tahlil
uchun o'sha xizmatga yuboriladi. Bu sizning qaroringiz — mijozlaringiz oldidagi
majburiyatlaringizni hisobga oling.

Ikkala kalit ham qo'yilsa OpenRouter tanlanadi; `AI_PROVIDER=groq` buni
o'zgartiradi. Kalitsiz provayder nomlansa, AI **o'chadi** — ma'lumot siz
tanlamagan kompaniyaga ketmaydi.

Hozir nima ishlayotganini tekshirish: `curl http://localhost:8000/health` →
`ai_provider` maydoni.

---

## Kundalik ish

```bash
docker compose logs -f backend   # loglarni kuzatish
docker compose ps                # nima ishlayapti
docker compose down              # to'xtatish
docker compose up -d             # qayta ishga tushirish
```

### Yangilash

```bash
git pull
./install.sh
```

Sxema o'zgarishlari avtomatik va ma'lumotni saqlagan holda qo'llanadi.
`.env` dagi sirlaringiz o'zgarmaydi.

> `./install.sh` yangilashdan oldin bazaning backup'ini o'zi oladi
> (`ops/docker-backup.sh`) va backup muvaffaqiyatsiz bo'lsa yangilashni
> to'xtatadi. Backup'larni muntazam serverdan tashqariga ko'chiring —
> [BACKUP.md](BACKUP.md).

### Nimadir ishlamayapti

```bash
curl http://localhost:8000/health
```

`{"status":"ok","database":"up"}` qaytishi kerak. Aks holda:

| Belgi | Sabab |
|---|---|
| `database: down` | Postgres ko'tarilmagan — `docker compose logs postgres` |
| Server ishga tushmaydi, "JWT_SECRET" xatosi | `.env` yo'q yoki buzilgan — `./install.sh` |
| Kira olmayapman, parol to'g'ri | `COOKIE_SECURE=true` bo'lsa HTTPS kerak |
| Parol tiklash xati kelmadi | SMTP sozlanmagan — link log'da: `docker compose logs backend` |
| Wazuh alertlari kelmayapti | [WAZUH.md](WAZUH.md) dagi tekshiruv bo'limi |

---

## Xavfsizlik

- Parollar bcrypt (cost 12) bilan hash qilinadi
- Sessiya tokeni HttpOnly cookie'da; 15 daqiqada yangilanadi, 30 kun amal qiladi
- MFA: TOTP + bir martalik tiklash kodlari (faqat hash saqlanadi)
- Har bir tenant ma'lumoti alohida; barcha so'rovlar tenant bo'yicha cheklangan
- Barcha muhim amallar audit jurnaliga yoziladi
- Docker image'lari root bo'lmagan foydalanuvchida ishlaydi

Zaiflik topsangiz — ommaviy issue ochmasdan to'g'ridan-to'g'ri xabar bering.

---

## Tuzilma

```text
legion/
├── install.sh          o'rnatish (sir yaratadi, ishga tushiradi)
├── ops/                backup, restore, verify
├── server/             Express + TypeScript API
│   ├── src/db/         Postgres sxemasi va migratsiya
│   └── tests/          119 ta test
├── frontend/           Next.js dashboard
├── integrations/       Wazuh integratsiyasi
├── deploy/nginx.conf   HTTPS reverse proxy namunasi
├── LICENSE             litsenziya — HALI QORALAMA, yuristsiz mijozga bermang
└── NOTICE              327 ta ochiq kodli paketning litsenziyalari
```

## Mijozga berishdan oldin

1. `LICENSE` faylining boshidagi ogohlantirish blokini o'qing. U yerda
   `[BRACKETED]` maydonlar bor — kompaniya ro'yxatdan o'tgach to'ldiriladi va
   yurist ko'rib chiqishi kerak.
2. `.env` dagi `NEXT_PUBLIC_OPERATOR_NAME` va `NEXT_PUBLIC_SUPPORT_EMAIL` —
   bularni **mijoz** o'zi to'ldiradi, siz emas. Bo'sh qolsa, maxfiylik
   sahifasi buni ochiq ko'rsatadi.
3. Bog'liqliklar o'zgargandan keyin `NOTICE` ni qayta yarating:
   `npx license-checker-rseidelsohn --excludePrivatePackages --csv`

## Ishlab chiquvchilar uchun

```bash
npm run dev      # frontend + API
npm test         # test to'plami (Postgres talab qiladi)
npm run check    # TypeScript tekshiruvi
```

Testlar `TEST_DATABASE_URL` bazasiga ulanadi va har test oldidan jadvallarni
tozalaydi — **alohida baza** ishlating.
