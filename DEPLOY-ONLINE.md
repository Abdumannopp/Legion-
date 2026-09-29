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
