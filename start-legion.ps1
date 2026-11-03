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
    Fail "Node.js not found. Install Node.js 20.9+ or 22 LTS: https://nodejs.org"
}

$nodeMajor = [int]((node --version).TrimStart('v').Split('.')[0])
if ($nodeMajor -lt 20) {
    Fail "Node.js 20.9+ is required. Current version: $(node --version)"
}
Ok "Node.js $(node --version)"

# --- PostgreSQL --------------------------------------------------------------
# Legion runs on PostgreSQL. Windows installer:
#   https://www.postgresql.org/download/windows/
# Remember the superuser password the installer asks for — setup will ask for it.

$pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue |
             Where-Object { $_.Status -eq "Running" } | Select-Object -First 1

if ($pgService) {
    Ok "PostgreSQL is running ($($pgService.Name))"
} else {
    Write-Host ""
    Write-Host "PostgreSQL service not found or not running." -ForegroundColor Yellow
    Write-Host "  Not installed:     https://www.postgresql.org/download/windows/"
    Write-Host "  Installed:         start postgresql-... in the Services window"
    Write-Host ""
    Write-Host "Setup will try anyway (the database may be on a remote server)." -ForegroundColor DarkGray
    Write-Host ""
}

# --- Dependencies ------------------------------------------------------------

if (-not (Test-Path "node_modules")) {
    Say "Installing packages (a few minutes)..."
    npm install
    if ($LASTEXITCODE -ne 0) { Fail "npm install failed." }
    Ok "Packages installed"
}

# --- First-run setup ---------------------------------------------------------

if (-not (Test-Path "server\.env")) {
    Say "First run — starting setup."
    npm run setup
    if ($LASTEXITCODE -ne 0) {
        Fail "Setup did not finish. Read the message above — usually PostgreSQL is not running."
    }
} else {
    Ok "server\.env exists — skipping setup"
}

# --- Build and run -----------------------------------------------------------

Say "Building Legion..."
npm run build
if ($LASTEXITCODE -ne 0) { Fail "Build failed." }

Write-Host ""
Write-Host "────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Legion:  http://localhost:3000" -ForegroundColor Magenta
Write-Host "  API:     http://localhost:8000" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Open it in a browser and create the first" -ForegroundColor Gray
Write-Host "  administrator account. You need the one-time" -ForegroundColor Gray
Write-Host "  setup token (lst_...) the server prints below." -ForegroundColor Gray
Write-Host "  After that, sign-up closes — others join" -ForegroundColor Gray
Write-Host "  by invitation." -ForegroundColor Gray
Write-Host ""
Write-Host "  Stop: Ctrl+C" -ForegroundColor DarkGray
Write-Host "────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

npm start
