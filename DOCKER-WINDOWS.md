# Legion'ni Docker Desktop bilan ishga tushirish (Windows)

Bu usulda Legion, uning bazasi va dashboard'i Docker Desktop ichida ishlaydi.
Kompyuteringizga PostgreSQL yoki Node.js o'rnatish shart emas. Hammasi o'zi
tayyorlanadi. Bu **sinov va namoyish** uchun. Internetga chiqarish uchun
[DEPLOY-ONLINE.md](DEPLOY-ONLINE.md) ishlatiladi.

---

## 1-qadam. Docker Desktop o'rnating (bir marta)

1. Brauzerda oching: **https://www.docker.com/products/docker-desktop/**
2. **Download for Windows** ni bosing va faylni o'rnating.
3. Kompyuterni **qayta yoqing**.
4. **Docker Desktop** dasturini oching. Agar WSL 2 o'rnatishni taklif qilsa, **ha** deb javob bering.
5. Pastki chapda yashil yozuv **"Engine running"** chiqquncha kuting (1–3 daqiqa).

## 2-qadam. Zip faylni oching

1. Yuklangan **`legion-….zip`** ustiga o'ng tugma → **Extract All…** → **Extract**.
2. Ichida **`legion`** papkasi paydo bo'ladi.

## 3-qadam. Legion'ni ishga tushiring

1. **`legion`** papkasini oching.
2. Yuqoridagi manzil satriga bosing, `powershell` deb yozing va **Enter** bosing.
3. Ochilgan oynaga bitta qatorni yozing va **Enter** bosing:

   ```
   powershell -ExecutionPolicy Bypass -File .\start-docker.ps1
   ```

4. Birinchi marta **5–15 daqiqa** ketadi (fayllar yuklanadi va yig'iladi). Ekranda yozuvlar o'tadi, bu normal.
5. Oxirida shunday yozuv chiqadi:

   ```
   Legion is ready:  http://localhost:3000
   ```

## 4-qadam. Birinchi administrator hisobini yarating

1. Brauzerda **http://localhost:3000/setup** ni oching.
2. **Setup token** so'raladi. Uni PowerShell oynasida oling:

   ```
   docker compose exec backend cat /app/server/.legion-setup-token
   ```

   Chiqqan uzun matnni (`lst_…` bilan boshlanadi) nusxalab, sahifaga qo'ying.
3. Email, parol va tashkilot nomini kiriting. Siz administrator bo'lasiz.

Keyin **http://localhost:3000** da oddiy kirish qiling.

---

## Har kuni

| Nima qilish | Qanday |
|---|---|
| Ishga tushirish | Docker Desktop'ni oching (Engine running bo'lsin), keyin 3-qadamdagi buyruqni yozing |
| Ishlayotganini ko'rish | `docker compose ps` (hamma qator `running` yoki `healthy` bo'lsin) |
| Loglarni ko'rish | `docker compose logs -f backend` (to'xtatish: **Ctrl+C**) |
| To'xtatish | `docker compose down` (ma'lumot saqlanadi) |

**Ma'lumot qayerda:** baza Docker'ning ichki xotirasida (`legion-pgdata`) saqlanadi.
`docker compose down` uni o'chirmaydi. Hamma narsani butunlay o'chirish
(**ma'lumot yo'qoladi**): `docker compose down -v`.

**Maxfiy fayl:** `.env` ichida parollar va kalitlar bor. Uni hech kimga yubormang
va zip'ga qo'shmang. Yo'qolsa, Legion'dagi ma'lumotni qayta ochib bo'lmaydi.

---

## Nimadir noto'g'ri bo'lsa

| Xabar | Sabab va yechim |
|---|---|
| `Docker Desktop is installed but not running` | Docker Desktop'ni oching, "Engine running" chiqquncha kuting |
| `Docker Desktop is not installed` | 1-qadamni bajaring |
| `running scripts is disabled on this system` | Buyruqni aynan shunday yozing: `powershell -ExecutionPolicy Bypass -File .\start-docker.ps1` |
| `port is already allocated` (3000 yoki 8000) | Boshqa dastur o'sha portni band qilgan. Docker Desktop'ni qayta ishga tushiring yoki kompyuterni qayta yoqing |
| `Legion did not report ready within three minutes` | `docker compose logs --tail=50 backend` ni yozing va chiqqan matnni menga yuboring |
| Brauzerda sahifa ochilmaydi | `docker compose ps` ni yozing. `backend` `Restarting` bo'lsa, `docker compose logs --tail=50 backend` |
| Sahifa ochiladi, lekin kirish ishlamaydi | Manzil aynan `http://localhost:3000` bo'lsin (`127.0.0.1` emas) |
| Parol tiklash xati kelmaydi | Bu sinovda pochta sozlanmagan. Havola loglarda chiqadi: `docker compose logs backend` |

Hech narsani o'zgartirmasdan, xato matnini (yoki ekran rasmini) menga yuboring.

---

## Eslatma: bu nima uchun sinov rejimi

- Sayt faqat shu kompyuterda (`localhost`) ochiladi.
- Pochta (SMTP) sozlanmagan: parol tiklash va taklif havolalari loglarga yoziladi.
- Baza bitta umumiy foydalanuvchi bilan ulanadi (lokal sinov uchun qulay, lekin serverdagi
  tartibdan kam himoyali). Serverda DEPLOY-ONLINE.md dagi sozlama ishlatiladi.
