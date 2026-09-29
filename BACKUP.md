# Legion — Backup va falokatdan tiklash

> **Yangilanish:** backup endi **shifrlanadi** (age, ochiq kalit bilan), serverdan tashqariga
> nusxalanadi, har safar haqiqiy tiklab sinaladi, monitoring va ogohlantirishlarga ega.
> To'liq, joriy qo'llanma: **[RECOVERY.md](RECOVERY.md)**. Quyidagi matn eski (shifrsiz)
> tavsif bo'lib, `RECOVERY.md` bilan ziddiyat bo'lsa — `RECOVERY.md` to'g'ri.

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

## Skriptlar

```bash
DATABASE_URL=... ./ops/backup.sh                  # dump olish + o'qilishini tekshirish + eskisini tozalash
DATABASE_URL=... ./ops/verify-backup.sh           # vaqtinchalik bazaga tiklab, ma'lumotni tekshirish
DATABASE_URL=... ./ops/restore.sh <dump> --yes    # MAVJUD baza ustiga tiklash (buzuvchi)
```

- `backup.sh` dump'ni tekshiradi (o'qilishi mumkinmi), lekin uni tiklamaydi —
  bu tezkor, kunlik ish uchun.
- `verify-backup.sh` dump'ni **haqiqatan vaqtinchalik bazaga tiklaydi** va har
  jadvalning qatorlar sonini chiqaradi — buni oyiga bir marta ishga
  tushiring, chunki tiklanmagan backup — bu shunchaki taxmin. Buning uchun
  baza yarata oladigan (`CREATEDB`) ulanish kerak; `npm run setup` yaratgan
  rolda ataylab yo'q (pastga qarang), shuning uchun faqat shu skript uchun
  `DATABASE_ADMIN_URL` (superuser ulanishi) bering.
- `restore.sh` jonli bazani **o'zgartiradi**: bitta tranzaksiya ichida
  (`--single-transaction`) ishlaydi — xato bo'lsa **hech narsa** qo'llanmaydi
  va baza avvalgi holatida qoladi. Har dump yonida `.sha256` fayli bo'ladi;
  `restore.sh` uni tekshiradi va mos kelmasa rad etadi.

O'zgaruvchilar: `DATABASE_URL` (majburiy — serveringiz ishlatadigan xuddi
o'sha qiymat), `DATABASE_ADMIN_URL` (ixtiyoriy, faqat `verify-backup.sh`
uchun), `BACKUP_DIR` (standart `./backups`), `RETENTION_DAYS` (standart 14).

Sinov: `DATABASE_URL=... bash ops/tests/test-backup-restore.sh` — haqiqiy
Postgres'da backup → jadvalni o'chirish → tiklash, buzilgan va o'zgartirilgan
dump'ni rad etish, baza o'chiq bo'lganda backup xatosi.

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
# 1. Yozuvni to'xtating — tiklash paytida yangi yozuv kelmasin
sudo systemctl stop legion        # yoki API jarayonini boshqa usulda to'xtating

# 2. Eng yangi backup'ni toping va TEKSHIRING (tiklashdan oldin!)
DATABASE_ADMIN_URL=... ./ops/verify-backup.sh /var/backups/legion/legion-20260820T030000Z.dump

# 3. Tiklang
DATABASE_URL=... ./ops/restore.sh /var/backups/legion/legion-20260820T030000Z.dump --yes

# 4. API ni qaytaring
sudo systemctl start legion

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
