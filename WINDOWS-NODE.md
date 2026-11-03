# Legion — Windows

> **Updated (2026-09).** The previous version was out of date: it mentioned a
> demo account `admin@legion.demo` / `legion123` and a `server/data/legion.json`
> file. Both were removed in Legion 2.0 — no demo account is created on a
> customer's server, and data is stored in PostgreSQL.
> Never create an account with a publicly known password.

You need Node.js 20.9+ and PostgreSQL 14+. Docker is not required.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start-legion.ps1
```

The script checks Node.js and PostgreSQL, installs the packages, runs
`npm run setup` the first time (secrets and database), builds and starts Legion.

- Dashboard: http://localhost:3000 — the first time you open it, you create
  **your own** administrator account; after that, sign-up closes.
- API status: http://localhost:8000/health — should show `"database":"up"`.

Step by step: [TRY-LOCALLY.md](TRY-LOCALLY.md). Full guide for customers:
[INSTALL.md](INSTALL.md).

**Note:** Windows is for testing and evaluation only. For a server people rely
on, use Linux (`npm run setup`, then a process supervisor such as
[deploy/legion.service](deploy/legion.service) to keep it running).
