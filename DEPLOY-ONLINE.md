# Legion'ni internetga chiqarish (onlayn)

Bu qo'llanma oxirida Legion `https://legion.sizningdomen.uz` kabi manzilda,
HTTPS bilan, server qayta yoqilganda ham o'zi ishga tushadigan holatda
ishlaydi. Taxminan 30–60 daqiqa ketadi. Buyruqlarni ko'chirib qo'yish
kifoya.

> **Nega Vercel yoki Netlify emas?** Legion'ga doim ishlab turadigan server,
> PostgreSQL bazasi va jonli ulanish (WebSocket) kerak. Bunday "serverless"
> xizmatlar buni bermaydi. Oddiy virtual server (VPS) — to'g'ri yo'l.

---

## 0. Nima kerak

| | |
|---|---|
| **Server (VPS)** | Ubuntu 24.04, kamida 2 CPU, 4 GB RAM, 40 GB disk. Istalgan provayder: Hetzner, DigitalOcean, Contabo, mahalliy hosting — farqi yo'q. Sotib olgach sizga **IP manzil** va **root paroli** (yoki SSH kalit) beriladi. |
| **Domen** | Masalan `sizningdomen.uz`. Legion uchun alohida subdomen ishlatamiz: `legion.sizningdomen.uz`. |
| **Loyiha fayli** | `Legion-….zip` (yoki Git repozitoriy). |

Pastda hamma joyda `legion.sizningdomen.uz` ni **o'z domeningiz** bilan,
`SERVER_IP` ni serveringiz IP manzili bilan almashtiring.

---

## 1. Domenni serverga yo'naltiring

Domen sotib olgan joyingizning DNS sozlamalarida yangi yozuv qo'shing:

| Turi | Nomi | Qiymati |
|---|---|---|
| `A` | `legion` | `SERVER_IP` |

Tekshirish (o'z kompyuteringizda): `ping legion.sizningdomen.uz` — javob
`SERVER_IP` dan kelishi kerak. Ba'zan 5–30 daqiqa kutish kerak bo'ladi.
**Bu ishlamaguncha 7-qadamdagi HTTPS ham ishlamaydi.**

---

## 2. Serverga ulaning

Windows'da PowerShell, Mac/Linux'da Terminal:

```bash
ssh root@SERVER_IP
```

Qolgan barcha buyruqlar **serverda** bajariladi.

---

## 3. Kerakli dasturlarni o'rnating

```bash
apt update && apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt install -y nodejs postgresql nginx certbot python3-certbot-nginx unzip git

# Firewall: faqat SSH va veb (80/443) ochiq
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable
```

Tekshirish: `node --version` → `v22…`.

PostgreSQL uchun administrator parolini o'rnating (o'ylab toping va
**yozib qo'ying** — 5-qadamda so'raladi, backup tekshiruvi uchun ham kerak):

```bash
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'BU-YERGA-KUCHLI-PAROL'"
```

---

## 4. Legion fayllarini joylang

Legion alohida, imtiyozsiz `legion` foydalanuvchisi nomidan ishlaydi.

**Zip fayl bo'lsa** — o'z kompyuteringizdan (serverda emas!) yuklang:

```bash
scp Legion-2026-09-28-dizayn.zip root@SERVER_IP:/opt/
```

So'ng serverda:

```bash
cd /opt && unzip -q Legion-*.zip && rm Legion-*.zip   # /opt/legion papkasi paydo bo'ladi
```

**Git bo'lsa**: `git clone <repo-manzili> /opt/legion`

Keyin (ikkala holatda ham):

```bash
adduser --system --group --home /opt/legion --no-create-home legion
chown -R legion:legion /opt/legion
```

---

## 5. Sozlash va qurish

```bash
cd /opt/legion
sudo -u legion npm install
sudo -u legion npm run setup -- --domain legion.sizningdomen.uz
sudo -u legion npm run build
```

`npm run setup` PostgreSQL parolini so'raydi — 3-qadamdagi parolni kiriting
(Host, Port, Superuser name savollariga shunchaki Enter). U bazani, Legion'ning
alohida (superuser bo'lmagan) rolini va barcha sirlarni yaratadi.
`--domain` tufayli manzillar darhol `https://…` qilib yoziladi.

Tashkilotingiz nomi maxfiylik va shartlar sahifalarida chiqadi —
`/opt/legion/frontend/.env.local` dagi `NEXT_PUBLIC_OPERATOR_NAME` va
`NEXT_PUBLIC_SUPPORT_EMAIL` ni to'ldiring, so'ng `sudo -u legion npm run build`
ni qayta ishga tushiring.

> `npm run setup` ni keyin qayta ishga tushirish xavfsiz: siz qo'shgan
> sozlamalar (SMTP, AI kaliti, domen) o'chmaydi.

---

## 6. Doimiy ishlashi uchun (systemd)

```bash
cp /opt/legion/deploy/legion.service /etc/systemd/system/legion.service
systemctl daemon-reload
systemctl enable --now legion
systemctl status legion        # "active (running)" bo'lishi kerak
```

Endi Legion server qayta yoqilganda ham, qulasa ham o'zi ishga tushadi.

---

## 7. nginx va HTTPS

```bash
cp /opt/legion/deploy/nginx.conf /etc/nginx/sites-available/legion
sed -i 's/legion.example.com/legion.sizningdomen.uz/' /etc/nginx/sites-available/legion
ln -s /etc/nginx/sites-available/legion /etc/nginx/sites-enabled/legion
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

certbot --nginx -d legion.sizningdomen.uz
```

Certbot email so'raydi va shartlarga rozilik so'raydi. U bepul SSL
sertifikatini oladi, nginx'ga HTTPS'ni qo'shadi, `http://` ni `https://` ga
yo'naltiradi va sertifikatni o'zi avtomatik yangilab turadi.

---

## 8. Birinchi administrator

Brauzerda oching: **https://legion.sizningdomen.uz/setup**

Bir martalik **setup token** so'raladi. Uni serverda oling:

```bash
cat /opt/legion/server/.legion-setup-token
```

Email, parol va tashkilot nomini kiriting — siz administrator bo'lasiz va
ro'yxatdan o'tish yopiladi. Qolganlar Settings → Team orqali taklif bilan
qo'shiladi.

**Buni darhol qiling:** administrator yaratilmaguncha tokenni bilgan har
kim sahifani egallashi mumkin (token faqat serverda, shuning uchun xavf past,
lekin kechiktirmang).

---

## 9. Wazuh'ni ulash

[WAZUH.md](WAZUH.md) dagi qadamlar, faqat `hook_url` endi:

```xml
<hook_url>https://legion.sizningdomen.uz/api/security-events/webhook</hook_url>
```

`api_key` uchun `KEY_ID:SECRET` kerak (`whk_…:whs_…`) — har tashkilotning o'z
tasodifiy kaliti. Uni administrator yaratadi (sir faqat bir marta ko'rsatiladi):

```bash
cd /opt/legion && npm run webhook:credential -w server -- create --tenant TENANT_ID --label "wazuh-1"
```

Tenant ID: Settings sahifasida. `SECURITY_EVENT_WEBHOOK_SECRET` endi autentifikatsiya
uchun ishlatilmaydi. `.env` dagi `WEBHOOK_ENCRYPTION_KEY` ni zaxira nusxalarda
bazadan **alohida** saqlang.

---

## 10. Backup (majburiy)

```bash
mkdir -p /var/log/legion && chown legion:legion /var/log/legion
crontab -u legion -e
```

Ochilgan faylning oxiriga qo'shing (har kecha soat 03:00):

```cron
0 3 * * * cd /opt/legion && DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' server/.env)" ./ops/backup.sh >> /var/log/legion/backup.log 2>&1
```

Backup'lar `/opt/legion/backups/` ga tushadi. **Ularni serverdan
tashqariga ham ko'chiring** — server yo'qolsa, uning ichidagi backup ham
yo'qoladi. Oyiga bir marta backup haqiqatan tiklanishini tekshiring
([BACKUP.md](BACKUP.md)):

```bash
cd /opt/legion && DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' server/.env)" \
  DATABASE_ADMIN_URL="postgresql://postgres:3-QADAMDAGI-PAROL@localhost/postgres" \
  ./ops/verify-backup.sh
```

---

## 11. Yangilash

```bash
cd /opt/legion
sudo -u legion env DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' server/.env)" ./ops/backup.sh
# yangi fayllarni joylang (git pull, yoki yangi zip'ni ustidan oching)
chown -R legion:legion /opt/legion
sudo -u legion npm install
sudo -u legion npm run build
systemctl restart legion
```

Baza sxemasi o'zi yangilanadi, ma'lumot va sirlar saqlanadi.

---

## 12. DDoS hujumdan himoya (Cloudflare, tavsiya etiladi)

Serverning o'zi hamma narsani to'xtata olmaydi: hujumchi kanalingizni (Gbit/s)
to'ldirib qo'ysa, so'rov Legion'ga yetmasdan ham sayt ochilmay qoladi. Buni
faqat serverdan **oldinda** turuvchi xizmat (CDN) hal qiladi. Eng oddiy yo'l —
Cloudflare'ning bepul tarifi. Legion va nginx tomoni esa ana shu xizmatning
ortida to'g'ri ishlashga tayyorlangan (tayyor skriptlar `ops/` va `deploy/`
papkalarida).

**Nima uchun bu qadam kerak.** Cloudflare ortida nginx har bir tashrif
buyuruvchini Cloudflare'ning manzili sifatida ko'radi. Natijada "bir manzildan
ko'p urinish" cheklovlari hamma uchun **bitta** hisoblagich bo'lib qoladi:
bitta hujumchi hammani kirishdan to'sib qo'yadi. Haqiqiy manzil
`CF-Connecting-IP` sarlavhasida keladi, lekin sarlavhaga faqat Cloudflare'dan
kelganda ishonish mumkin. Quyidagi qadamlar aynan shuni sozlaydi.

### 12.1. Domenni Cloudflare'ga o'tkazing

1. cloudflare.com'da bepul hisob oching, domeningizni qo'shing va domen
   sotib olgan joyingizda nameserver'larni Cloudflare bergan qiymatlarga
   almashtiring.
2. DNS bo'limida `legion` yozuvi **proxied** (to'q sariq bulut) bo'lsin.
3. **SSL/TLS → Overview** da rejim: **Full (strict)**. (Buning uchun serverda
   haqiqiy sertifikat bo'lishi kerak — 7-qadamdagi `certbot` buni beradi.
   Sertifikatni **12.4 dan oldin** oling.)

### 12.2. nginx haqiqiy manzilni Cloudflare'dan olsin

```bash
cd /opt/legion
sudo ops/update-cloudflare-ips.sh --reload
```

Skript Cloudflare'ning rasmiy manzillar ro'yxatini yuklaydi, tekshiradi
(noto'g'ri yoki juda keng diapazonni rad etadi — nginx'ni butun internetga
ishontirib qo'ymaslik uchun), `/etc/nginx/legion-cloudflare.conf` ni yozadi,
`nginx -t` bilan sinaydi va qayta yuklaydi. Biror narsa noto'g'ri bo'lsa,
eski fayl joyida qoladi.

Keyin `/etc/nginx/sites-available/legion` ichida quyidagi qatordan `#` ni
olib tashlang va nginx'ni qayta yuklang:

```
    include /etc/nginx/legion-cloudflare.conf;
```

```bash
nginx -t && systemctl reload nginx
```

Cloudflare manzillari o'zgarib turadi, shuning uchun ro'yxatni haftada bir
yangilab turadigan taymerni yoqing:

```bash
cp /opt/legion/deploy/legion-cloudflare-ips.service /etc/systemd/system/
cp /opt/legion/deploy/legion-cloudflare-ips.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now legion-cloudflare-ips.timer
```

> Legion'ga (`server/.env`) hech narsa qo'shish shart emas: u faqat shu
> serverdagi nginx'ga ishonadi va mijoz manzilini nginx qo'ygan sarlavhadan
> oladi. `TRUSTED_PROXIES` ni o'zgartirmang.

### 12.3. Tekshirib ko'ring

Brauzerda saytni oching va kiring. Keyin serverdan:

```bash
curl -s https://legion.sizningdomen.uz/api/health
journalctl -u legion -n 20      # xatolar yo'qligini ko'ring
```

### 12.4. Serverni to'g'ridan-to'g'ri hujumdan yoping (origin lockdown)

Hujumchi Cloudflare'ni chetlab, server IP manziliga to'g'ridan-to'g'ri
yuborishi mumkin. Buni oldini olish uchun 80/443 portlarni faqat
Cloudflare'ga oching:

```bash
sudo ops/update-cloudflare-ips.sh --ufw            # avval faqat ko'rsatadi (hech narsa o'zgarmaydi)
sudo ops/update-cloudflare-ips.sh --ufw --apply    # qoidalarni qo'shadi
ufw status numbered
ufw delete allow 'Nginx Full'                      # hammaga ochiq qoidani olib tashlang
```

SSH qoidasiga tegilmaydi. Tekshiruv: `curl -m 5 http://SERVER_IP/` **javob
bermasligi** kerak, `https://legion.sizningdomen.uz` esa ishlashi kerak.

Diqqat: shundan keyin Wazuh menejeri Legion'ga **IP orqali emas, domen orqali**
(`https://legion.sizningdomen.uz/api/security-events/webhook`) yuborishi
kerak, aks holda to'siqqa uchraydi. Yangi Cloudflare diapazoni paydo bo'lsa,
taymer nginx ro'yxatini yangilaydi, lekin `ufw` qoidalarini **qo'lda**
qayta ishga tushirishingiz kerak (`--ufw --apply` — ortiqcha qoidalar
qo'shilmaydi, faqat yetishmaganlari).

### 12.5. Cloudflare panelidagi qoidalar

(Menyu nomlari vaqt o'tishi bilan o'zgarishi mumkin; bepul tarifda qoidalar
soni cheklangan.)

- **Security → WAF → Rate limiting rules**: `/api/auth/` yo'li uchun
  bir manzildan daqiqasiga ~30 so'rov, oshsa — blok. (Legion va nginx o'z
  cheklovlariga ega; Cloudflare'dagisi so'rovni serverga umuman yetkazmaydi.)
- **Security → Settings**: *Bot Fight Mode* ni yoqish mumkin. Hujum paytida
  vaqtincha **"I'm Under Attack"** rejimini yoqing.
- **Wazuh webhook'i.** Cloudflare brauzer bo'lmagan mijozlarni (Wazuh
  skripti) bot deb tekshiruvga yo'naltirishi mumkin. Agar sensor
  hodisalari kelmay qolsa, `/api/security-events/webhook` yo'li uchun
  *Custom rule → Skip (Bot Fight / Rate limiting)* qoidasini qo'shing.
  Bu qoida Legion'da **sinab ko'rilmagan** — Cloudflare hisobi kerak va
  panelning joriy ko'rinishiga bog'liq. Webhook baribir o'z imzosi bilan
  himoyalangan: noto'g'ri imzoli so'rovlar rad etiladi va cheklanadi.
- WebSocket (jonli ogohlantirishlar) Cloudflare'ning barcha tariflarida ishlaydi.

### 12.6. Quvvat oshirish (agar hujum katta bo'lsa)

Legion bir nechta nusxada ishlashi mumkin: umumiy PostgreSQL va Redis
(`server/.env` da `REDIS_URL`; tafsilot — [GLOBAL-SAAS-ARCHITECTURE.md](GLOBAL-SAAS-ARCHITECTURE.md))
va nginx'dagi `upstream legion_api` ga yana bir `server` qatori.
Sozlanadigan qiymatlar (`server/.env`):

| O'zgaruvchi | Ma'nosi |
|---|---|
| `PASSWORD_HASH_WORKERS` | parol tekshiruvchi oqimlar soni (standart: avtomatik; o'lchovda 1–3 oqim o'rtasida sezilarli farq chiqmadi) |
| `HTTP_FIRST_REQUEST_TIMEOUT_SECONDS` | birinchi so'rovni yubormagan ulanishni yopish (standart 15 s, `0` — o'chirish) |

### 12.7. Halol cheklovlar

- **Katta (hajmiy) hujum** — kanalni to'ldiruvchi L3/L4 hujum — faqat
  Cloudflare kabi tarmoq oldidan to'xtatiladi. Ularsiz, hosting provayderning
  o'z himoyasiga tayanasiz.
- Minglab har xil manzildan kelgan **sekin, "odamga o'xshash"** so'rovlar
  (L7 botnet) manzil bo'yicha cheklovlarni chetlab o'tadi. Legion buni
  yumshatadi (hisoblagich xotirasi cheklangan, tizim ishdan chiqmaydi,
  sensor hodisalari yo'qolmaydi, o'qish ishlaydi), lekin parol bilan
  kirish — eng qimmat amal — hujum davomida band bo'lib `503` qaytarishi
  mumkin. Cloudflare qoidalari va Bot Fight Mode aynan shu holat uchun.
- O'lchovlar bir mashinada olingan (`ops/tests/ddos-resilience.mjs`);
  ular tizimning **xatti-harakatini** ko'rsatadi, sizning serveringiz
  quvvatini emas. Natijalar: [PRODUCTION-VALIDATION-2026-10-01.md](PRODUCTION-VALIDATION-2026-10-01.md).
- Kelajak uchun: kirish/ro'yxatdan o'tish formalariga Cloudflare Turnstile
  (CAPTCHA) qo'shish — hozircha qo'shilmagan.

---

## Nimadir ishlamasa

| Belgi | Sabab va yechim |
|---|---|
| `502 Bad Gateway` | Legion ishlamayapti: `systemctl status legion`, loglar: `journalctl -u legion -n 50` |
| Certbot xato beradi | DNS hali serverga yo'naltirilmagan (1-qadam) yoki 80-port yopiq (`ufw status`) |
| Kira olmayapman, parol to'g'ri | Sayt `http://` orqali ochilgan — `https://` dan kiring |
| Sahifa ochiladi, lekin ma'lumot yo'q | `frontend/.env.local` dagi `NEXT_PUBLIC_API_URL` `https://DOMEN/api` emas — tuzating va `npm run build` |
| Server ishga tushmaydi, `JWT_SECRET` haqida | `server/.env` yo'q — `sudo -u legion npm run setup -- --domain …` |
| Holat | `curl https://legion.sizningdomen.uz/api/health` → `"database":"up"` |

---

## Bitta qaror: kim uchun?

Standart holatda Legion **bitta tashkilot** uchun (`DEPLOYMENT_MODE=self-hosted`):
birinchi administratordan keyin ro'yxatdan o'tish yopiladi. Bu — har bir
mijozga o'z serverida alohida Legion o'rnatish modeli.

Agar bitta saytda **ko'p mijoz o'zi ro'yxatdan o'tib**, obuna sotib oladigan
xizmat (SaaS) qilmoqchi bo'lsangiz: 5-qadamda `npm run setup -- --saas --domain …`
ni ishlating va [SAAS.md](SAAS.md) dagi qadamlarni bajaring (email — Resend,
to'lov — Paddle).
