# Legion — Windows launcher (no Docker required).
#
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\start-legion.ps1
#
# Checks Node.js, installs dependencies, runs setup the first time, and starts
# Legion. Safe to run again — setup keeps existing secrets and data.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Say  ($m) { Write-Host $m -ForegroundColor Cyan }
function Ok   ($m) { Write-Host "OK  $m" -ForegroundColor Green }
function Fail ($m) { Write-Host "ERR $m" -ForegroundColor Red; exit 1 }

# --- Node.js -----------------------------------------------------------------

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Fail "Node.js topilmadi. Node.js 20.9+ yoki 22 LTS o'rnating: https://nodejs.org"
}

$nodeMajor = [int]((node --version).TrimStart('v').Split('.')[0])
if ($nodeMajor -lt 20) {
    Fail "Node.js 20.9+ kerak. Hozirgi versiya: $(node --version)"
}
Ok "Node.js $(node --version)"

# --- PostgreSQL --------------------------------------------------------------
# Legion PostgreSQL'da ishlaydi. Windows uchun o'rnatuvchi:
#   https://www.postgresql.org/download/windows/
# O'rnatishda so'ralgan superuser parolini eslab qoling — setup uni so'raydi.

$pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue |
             Where-Object { $_.Status -eq "Running" } | Select-Object -First 1

if ($pgService) {
    Ok "PostgreSQL ishlayapti ($($pgService.Name))"
} else {
    Write-Host ""
    Write-Host "PostgreSQL xizmati topilmadi yoki ishlamayapti." -ForegroundColor Yellow
    Write-Host "  O'rnatilmagan bo'lsa: https://www.postgresql.org/download/windows/"
    Write-Host "  O'rnatilgan bo'lsa:   Services oynasida postgresql-... ni ishga tushiring"
    Write-Host ""
    Write-Host "Setup baribir urinib ko'radi (masofadagi server bo'lishi mumkin)." -ForegroundColor DarkGray
    Write-Host ""
}

# --- Dependencies ------------------------------------------------------------

if (-not (Test-Path "node_modules")) {
    Say "Paketlar o'rnatilmoqda (bir necha daqiqa)..."
    npm install
    if ($LASTEXITCODE -ne 0) { Fail "npm install muvaffaqiyatsiz tugadi." }
    Ok "Paketlar o'rnatildi"
}

# --- First-run setup ---------------------------------------------------------

if (-not (Test-Path "server\.env")) {
    Say "Birinchi ishga tushirish — sozlash boshlandi."
    npm run setup
    if ($LASTEXITCODE -ne 0) {
        Fail "Sozlash tugallanmadi. Yuqoridagi xabarni o'qing — odatda PostgreSQL ishlamayotgan bo'ladi."
    }
} else {
    Ok "server\.env mavjud — sozlash o'tkazib yuborildi"
}

# --- Build and run -----------------------------------------------------------

Say "Legion quriladi..."
npm run build
if ($LASTEXITCODE -ne 0) { Fail "Qurish muvaffaqiyatsiz tugadi." }

Write-Host ""
Write-Host "────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Legion:  http://localhost:3000" -ForegroundColor Magenta
Write-Host "  API:     http://localhost:8000" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Brauzerda oching va birinchi administrator" -ForegroundColor Gray
Write-Host "  hisobini yarating. Shundan keyin ro'yxatdan" -ForegroundColor Gray
Write-Host "  o'tish yopiladi — qolganlar taklif bilan." -ForegroundColor Gray
Write-Host ""
Write-Host "  To'xtatish: Ctrl+C" -ForegroundColor DarkGray
Write-Host "────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

npm start
