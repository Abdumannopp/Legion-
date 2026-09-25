# Legion'ni o'zingizda sinash

Bu qo'llanma texnik bilim talab qilmaydi. Har qadamda **nima ko'rinishi kerakligi**
yozilgan — agar boshqacha ko'rinsa, o'sha yerda to'xtang.

Avval o'z kompyuteringizda sinang. Server keyin.

---

## Eng tez yo'l — bitta buyruq

Faqat **Node.js** o'rnatilgan bo'lsa yetarli. Baza dasturning o'zi bilan keladi.

```
npm install
npm run try
```

Birinchi marta 2–3 daqiqa (bazani tayyorlaydi va Legion'ni quradi), keyingi
safar bir necha soniya.

**Ko'rinishi kerak:**

```
OK  Database running on port 54329
OK  Schema applied
OK  Configuration written

Legion is starting.
  Dashboard:  http://localhost:3000
```

Oxirgi qatordagi **manzilni brauzerda oching** va **5-qadamga** o'ting.

> **Diqqat:** 3000-port boshqa dastur tomonidan band bo'lsa, Legion o'zi bo'sh
> port topadi va shunday yozadi:
> ```
> Dashboard port 3000 is busy — using 3001 instead.
>   Dashboard:  http://localhost:3001
> ```
> Bunday holda **o'sha ko'rsatilgan manzilni** oching, `3000` ni emas.

> ⚠️ **Bu faqat sinov uchun.** Baza dastur papkasi ichida yotadi
> (`.legion-testdb`), backup qilinmaydi va u ishlatadigan paketning
> barqaror versiyasi hali yo'q. Haqiqiy foydalanish uchun pastdagi
> **A yo'l** yoki **B yo'l** ni ishlating.
>
> Noldan boshlash: `.legion-testdb` papkasini o'chiring.

Node.js yo'q bo'lsa: https://nodejs.org — "LTS" tugmasi.

### Agar npm o'rnatish skriptini bloklasa

Yangi npm versiyalari xavfsizlik uchun ba'zi paketlarning o'rnatish
qadamini bloklaydi va `npm install` chiqishida shunday ogohlantiradi:

```
npm warn allow-scripts  @embedded-postgres/windows-x64 (install scripts present)
```

Bunday bo'lsa PostgreSQL fayllari to'liq o'rnatilmaydi. Ruxsat bering:

```
npm approve-scripts --allow-scripts-pending
npm install
npm run try
```

Ruxsat bermoqchi bo'lmasangiz — **A yo'l** dan boring (PostgreSQL'ni
o'zingiz o'rnatasiz, hech qanday skript ishga tushmaydi).

---

## Haqiqiy o'rnatish uchun ikkita yo'l

| | **A yo'l — Node.js** | **B yo'l — Docker** |
|---|---|---|
| Nima o'rnatiladi | Node.js + PostgreSQL | Docker Desktop |
| Buyruq | `npm run setup` → `npm start` | `./install.sh` |
| Ma'lumot qayerda | O'rnatgan PostgreSQL'ingizda | Docker volume'ida |

---

# A yo'l — Node.js bilan

## A1. Node.js o'rnating

https://nodejs.org — "LTS" tugmasini bosing, o'rnating.

**Tekshiruv:** terminalda `node --version` → `v20.` yoki `v22.` bilan boshlanishi kerak.

## A2. PostgreSQL o'rnating

Bu Legion ma'lumot saqlaydigan baza. Bir marta o'rnatiladi, keyin unutasiz.

**Windows uchun qadamma-qadam:**

1. https://www.postgresql.org/download/windows/ → "Download the installer"
2. Eng yuqoridagi versiyani (masalan 17.x) yuklab oling va ishga tushiring
3. Sehrgar oynalarida:

| Oyna | Nima qilish |
|---|---|
| Installation Directory | **Next** (o'zgartirmang) |
| Select Components | **Next** (hammasi belgilangan holda qoldiring) |
| Data Directory | **Next** |
| **Password** | ⚠️ **Parol o'ylab toping va YOZIB QO'YING** |
| Port | **5432** — o'zgartirmang, **Next** |
| Advanced Options / Locale | **Next** |
| Ready to Install | **Next** → kuting |
| Stack Builder (oxirida) | Belgini **olib tashlang**, **Finish** |

> Eng muhimi — **Password** oynasi. O'sha parolni keyingi qadamda so'rayman.
> Yozib qo'ying yoki eslab qoladiganini tanlang.

**Mac:** https://postgresapp.com — yuklab oling, oching, "Initialize" bosing.

**Linux:** `sudo apt install postgresql` (yoki distributivingizga mos buyruq)

**Tekshiruv (Windows, PowerShell'da):**

```powershell
Get-Service -Name "*postgres*"
```

`Running` yozuvi ko'rinishi kerak. `Stopped` bo'lsa:

```powershell
Start-Service -Name "postgresql*"
```

## A3. Fayllarni oching va sozlang

Zip'ni oching, terminalda o'sha papkaga o'ting va:

```
npm install
npm run setup
```

> `npm install` ni **albatta birinchi** bajaring. Busiz `npm run setup`
> ishlamaydi (u kerakli paketlarni topa olmaydi).

`npm run setup` PostgreSQL'ni topadi, Legion uchun baza yaratadi va sirlarni
o'ylab topadi.

**Parol so'rasa** — A2 dagi Password oynasida yozib qo'ygan parolingizni
kiriting. Boshqa savollarni (Host, Port, Superuser name) Enter bilan
o'tkazib yuboring.

**Ko'rinishi kerak:**

```
✓ Node.js v22.x.x
✓ Connected to PostgreSQL
✓ Created database "legion"
✓ Wrote server/.env with new secrets
✓ Database schema applied

Setup complete.
```

## A4. Ishga tushiring

```
npm run build
npm start
```

**Ko'rinishi kerak:** `Legion Node API: http://localhost:8000`

Windows'da buning o'rniga bitta fayl ham yetadi:
```
.\start-legion.ps1
```

Endi **5-qadamga** o'ting (brauzerda ochish).

---

# B yo'l — Docker bilan

## B1. Docker o'rnating

- **Windows / Mac:** https://docker.com/products/docker-desktop — yuklab oling,
  o'rnating va **ishga tushiring**.
- **Linux:** https://docs.docker.com/engine/install/

**Ko'rinishi kerak:** Docker Desktop oynasida yashil "Engine running".

## B2. Fayllarni oching va ishga tushiring

Zip'ni oching, terminalda o'sha papkaga o'ting va:

```
./install.sh
```

Birinchi marta 5–10 daqiqa ketadi.

**Ko'rinishi kerak:**

```
✓ Legion is running
  Legion is ready:  http://localhost:3000
```

**Agar xato chiqsa:**

| Xato | Nima qilish |
|---|---|
| `Docker is not installed` | B1 ga qayting |
| `Cannot talk to the Docker daemon` | Docker Desktop ochiq emas — oching |
| `permission denied` | Oldiga qo'shing: `bash install.sh` |

---

## 5-qadam. Oching va admin yarating

Brauzerda: **http://localhost:3000**

**Ko'rinishi kerak:** Legion logotipi va kirish oynasi.

Ro'yxatdan o'ting — email va parol o'ylab toping (haqiqiy email shart emas,
sinov uchun `admin@sinov.uz` bo'lsa ham bo'ladi).

Bu **birinchi administrator** hisobi. Shundan keyin ro'yxatdan o'tish yopiladi.

---

## 6-qadam. Ishlayotganini tekshiring

Beshta oddiy tekshiruv. Har biri bir daqiqa.

### 6.1 Kirish ishlaydimi
Chiqing va qayta kiring. Kirishi kerak.

### 6.2 Ro'yxatdan o'tish yopilganmi
Brauzerda yangi yashirin oyna (incognito) oching va yana
http://localhost:3000 ga kiring, ro'yxatdan o'tmoqchi bo'ling.

**Ko'rinishi kerak:** *"This Legion installation is already set up"* —
ya'ni begona odam hisob ocha olmaydi. Bu to'g'ri xatti-harakat.

### 6.3 Hamkasbni taklif qilish
Settings → Team → email yozib, rol tanlab, taklif yuboring.

SMTP sozlanmagani uchun xat ketmaydi — o'rniga ekranda **havola** chiqadi.
O'sha havolani yashirin oynada oching, parol o'rnating va kiring.

**Ko'rinishi kerak:** yangi foydalanuvchi kira oldi va uning huquqi cheklangan
(masalan analitik audit jurnalini ko'ra olmaydi).

### 6.4 Ikki bosqichli kirish
Settings → Two-factor authentication → Set up.

Telefoningizdagi authenticator ilovasiga (Google Authenticator, Authy)
ko'rsatilgan kalitni qo'shing va kodni kiriting.

**Ko'rinishi kerak:** 10 ta tiklash kodi. Ularni saqlang. Keyin chiqib, qayta
kiring — endi paroldan keyin kod so'raydi.

### 6.5 Server sog'lommi
Brauzerda oching: **http://localhost:8000/health**

**Ko'rinishi kerak:**
```
{"status":"ok","runtime":"node","database":"up","ai":false}
```

`database: up` — eng muhimi. `ai: false` normal: AI kaliti qo'yilmagan,
demak hech qanday ma'lumot tashqariga chiqmaydi.

---

## 7-qadam. To'xtatish va qayta ishga tushirish

**Node.js yo'lida:** terminalda `Ctrl+C` — to'xtaydi.
Qayta ishga tushirish: `npm start`

**Docker yo'lida:**
```
docker compose down      # to'xtatish
docker compose up -d     # qayta ishga tushirish
```

**Muhim tekshiruv:** to'xtatib, qayta ishga tushiring va **kirib ko'ring**.
Hisobingiz va ma'lumotingiz joyida qolishi kerak. Agar yo'qolsa — menga ayting,
bu jiddiy muammo.

---

## Keyin nima

Shu yettita qadam ishlagan bo'lsa, Legion sizning kompyuteringizda ishlayapti.

Keyingi ikkita ish — **birinchi mijozdan oldin**:

1. **Serverda takrorlang.** Xuddi shu qadamlar, lekin haqiqiy serverda.
   Farqi: `localhost` o'rniga server manzilini ishlatasiz —
   `server/.env` (Node yo'li) yoki `.env` (Docker yo'li) faylida
   `FRONTEND_URL` ni o'zgartirib, qaytadan ishga tushirasiz.

2. **Haqiqiy Wazuh ulang.** [WAZUH.md](WAZUH.md) da yozilgan. Bu eng muhim
   sinov — men uni o'tkaza olmadim, chunki menda Wazuh yo'q edi.

---

## Nimadir noto'g'ri bo'lsa

Xato xabarini toping:

- **Node.js yo'lida:** xato to'g'ridan-to'g'ri terminalda ko'rinadi
- **Docker yo'lida:** `docker compose logs backend | tail -30`

Chiqqan matnni menga yuboring — kodni tushunish shart emas, sabab o'sha matnda
yozilgan bo'ladi.

### Tez-tez uchraydigan xatolar

| Xato | Sabab va yechim |
|---|---|
| `'tsx' is not recognized` yoki `Dependencies are not installed` | `npm install` bajarilmagan — avval shuni ishga tushiring |
| `The bundled PostgreSQL is installed but incomplete` | npm o'rnatish skriptini bloklagan — pastdagi izohga qarang |
| `Could not start the database` | Xabar ostida **"What the database reported"** bo'limi bor — sabab o'sha yerda. Windows'da ko'pincha Visual C++ runtime yetishmaydi: https://aka.ms/vs/17/release/vc_redist.x64.exe |
| `Refusing to start: JWT_SECRET…` | Sozlash bajarilmagan — `npm run setup` |
| `ECONNREFUSED …:5432` | PostgreSQL ishlamayapti — A2 dagi tekshiruvni bajaring |
| `password authentication failed` | Parol mos emas — `npm run setup` ni qayta ishga tushiring |
| `EADDRINUSE` | 8000 yoki 3000 port band — boshqa dastur ishlatayapti |

### Noldan boshlash

Hech narsani buzib qo'yishdan qo'rqmang: bu sizning kompyuteringizda, sinov
uchun.

**Node.js yo'lida** — bazani tozalash:
```
npm run setup
```
(bazani o'chirish uchun PostgreSQL'da `DROP DATABASE legion;`)

**Docker yo'lida** — hammasini o'chirish:
```
docker compose down -v
./install.sh
```
