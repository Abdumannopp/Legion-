# Legion — Backup va falokatdan tiklash

> Hech qachon tiklanmagan backup — bu backup emas, bu taxmin.

## Nima himoyalanadi

Postgres 2.0 dan beri **yagona** haqiqat manbai. Unda mijozning barcha xavfsizlik
telemetriyasi, hisoblari va audit jurnali bor. Boshqa hech qayerda nusxa yo'q.
Bazani yo'qotish = mijozni yo'qotish.

## Maqsadlar (RPO / RTO)

| Ko'rsatkich | Maqsad | Izoh |
|---|---|---|
| **RPO** (qancha ma'lumot yo'qolishi mumkin) | ≤ 24 soat | Kunlik dump bilan. PITR yoqilsa — daqiqalar |
| **RTO** (qancha vaqtda tiklash) | ≤ 1 soat | `-Fc` format + `pg_restore -j` bilan |

Bu maqsadlarni mijozga va'da qilishdan oldin **o'lchang** — mashq vaqtini yozib boring.

## Tavsiya: boshqariladigan Postgres

Eng ishonchli yo'l — avtomatik backup'i bor boshqariladigan Postgres (RDS,
Neon, Supabase, Cloud SQL). Ularda point-in-time recovery bor, ya'ni RPO
daqiqalarga tushadi.

Yoqish kerak bo'lgan narsalar:

- Avtomatik kunlik backup, kamida 14 kun saqlash
- Point-in-time recovery (PITR)
- Backup'larni **boshqa regionga** nusxalash
- Baza o'chirilishidan himoya (deletion protection)

**Muhim:** provayder backup olayotgani — uni tiklay olishingiz demak emas.
Pastdagi mashqni baribir bajaring.

## Docker bilan o'rnatilgan bo'lsa — shu skriptlardan foydalaning

Docker o'rnatmasida Postgres port tashqariga ochilmagan (ataylab), shuning
uchun serverdan `DATABASE_URL` orqali ishlaydigan `ops/backup.sh` bazaga
yeta olmaydi. Buning o'rniga:

```bash
./ops/docker-backup.sh                         # dump + VAQTINCHALIK bazaga tiklab tekshirish + eskisini tozalash
./ops/docker-restore.sh backups/legion-….dump --yes   # tiklash (pastga qarang)
```

- `docker-backup.sh` har safar dump'ni vaqtinchalik bazaga **tiklab ko'radi**
  va jadvallarni jonli baza bilan solishtiradi. Xato bo'lsa — nol bo'lmagan
  kod bilan chiqadi va "yaxshi backup"ga o'xshash fayl qoldirmaydi.
- Har dump yonida `.sha256` fayli bo'ladi; `docker-restore.sh` uni tekshiradi.
- `docker-restore.sh` jonli bazaga **tegmaydi**: dump yangi bazaga tiklanadi,
  muvaffaqiyatli bo'lsagina nomini almashtirib joyiga qo'yiladi. Eski baza
  `legion_before_restore_…` nomi bilan saqlanib qoladi — noto'g'ri tiklashni
  ikki buyruq bilan orqaga qaytarish mumkin (skript buyruqlarni chiqaradi).
- `./install.sh` yangilashdan **oldin** avtomatik backup oladi; backup
  muvaffaqiyatsiz bo'lsa, yangilash to'xtaydi.

Kunlik cron (Docker):

```cron
0 3 * * * cd /opt/legion && BACKUP_DIR=/var/backups/legion ./ops/docker-backup.sh >> /var/log/legion-backup.log 2>&1 || echo "Legion backup FAILED" | mail -s "Legion backup FAILED" admin@example.com
```

Oxirgi qism muhim: jimgina ishlamay qolgan backup — eng xavfli holat.
Xato haqida xabar kelishini bir marta ataylab tekshirib ko'ring.

Sinov: `bash ops/tests/test-backup-restore.sh` — haqiqiy Postgres 16
konteynerida backup → jadvalni o'chirish → tiklash, buzilgan va o'zgartirilgan
dump'ni rad etish, baza o'chiq bo'lganda backup xatosi.

## Skriptlar (Node.js yo'li)

```bash
./ops/backup.sh              # dump olish + o'qilishini tekshirish + eskisini tozalash
./ops/verify-backup.sh       # vaqtinchalik bazaga tiklab, ma'lumotni tekshirish
./ops/restore.sh <dump>      # MAVJUD baza ustiga tiklash (buzuvchi)
```

O'zgaruvchilar: `DATABASE_URL`, `BACKUP_DIR` (standart `./backups`),
`RETENTION_DAYS` (standart 14).

### Kunlik backup (cron)

```cron
0 3 * * * cd /opt/legion && DATABASE_URL=... BACKUP_DIR=/var/backups/legion ./ops/backup.sh >> /var/log/legion-backup.log 2>&1
```

### Oylik tekshiruv (majburiy)

```cron
0 4 1 * * cd /opt/legion && DATABASE_URL=... BACKUP_DIR=/var/backups/legion ./ops/verify-backup.sh >> /var/log/legion-verify.log 2>&1
```

`verify-backup.sh` ishlab turgan bazaga **tegmaydi** — vaqtinchalik baza
yaratadi, tiklaydi, tekshiradi va o'chiradi.

## Backup'ni serverdan tashqariga chiqaring

Serverdagi backup server bilan birga yo'qoladi. `backup.sh` dan keyin:

```bash
aws s3 cp "$TARGET" "s3://legion-backups/$(date -u +%Y/%m)/" --storage-class STANDARD_IA
```

S3'da **versioning** va **object lock** yoqing — ransomware backup'larni ham
o'chirishga urinadi.

## Falokat holatida tiklash

```bash
# 1. Yozuvni to'xtating (API ni o'chiring) — tiklash paytida yangi yozuv kelmasin
docker compose stop backend

# 2. Eng yangi backup'ni toping va TEKSHIRING (tiklashdan oldin!)
./ops/verify-backup.sh /var/backups/legion/legion-20260820T030000Z.dump

# 3. Tiklang
./ops/restore.sh /var/backups/legion/legion-20260820T030000Z.dump

# 4. API ni qaytaring
docker compose start backend

# 5. Tekshiring
curl -s https://api.legion.example/health
```

`restore.sh` `--single-transaction` bilan ishlaydi: xato bo'lsa **hech narsa**
qo'llanmaydi va baza avvalgi holatida qoladi. Yarim tiklangan baza — eng yomon
holat, chunki u ishlayotgandek ko'rinadi.

## Sinalgan mashq natijasi

Bu protsedura sinovdan o'tkazilgan (2026-08-21):

| Qadam | Natija |
|---|---|
| 40 ta alert + 2 tenant + 2 user yaratildi | ✅ |
| `backup.sh` — dump olindi va o'qilishi tasdiqlandi | ✅ 20K |
| `DROP SCHEMA public CASCADE` — **hamma narsa yo'q qilindi** | ✅ |
| `restore.sh` — backupdan tiklandi | ✅ 43 alert, 2 tenant, 2 user |
| Login + alert o'qish (serverni qayta ishga tushirmasdan) | ✅ ishladi |
| `verify-backup.sh` sxema nomuvofiqligini aniqladi | ✅ jadval yo'qligini tutdi |

Oxirgi qator muhim: skript shunchaki "tiklandi" demaydi, kutilgan jadvallar va
ma'lumot borligini tekshiradi va nomuvofiqlikda **xato qaytaradi**.

## Nima hali yo'q

- **PITR** — kunlik dump'da RPO 24 soat. Boshqariladigan Postgres'da yoqing.
- **Avtomatik offsite nusxa** — S3 buyrug'i hujjatlashtirilgan, lekin skriptga
  kiritilmagan (kalitlar sizning muhitingizga bog'liq).
- **Backup shifrlash** — mijoz xavfsizlik ma'lumoti saqlanadi. S3 SSE yoki
  `gpg` bilan shifrlang; GDPR bo'yicha bu talab bo'lishi mumkin.
