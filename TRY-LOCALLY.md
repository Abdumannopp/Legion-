# Trying Legion on your own computer

This guide needs no technical knowledge. Each step says **what you should see** —
if you see something different, stop there.

Try it on your own computer first. The server comes later.

> **If you have Docker Desktop**, follow [DOCKER-WINDOWS.md](DOCKER-WINDOWS.md) instead.

---

## The fastest way — one command

Only **Node.js** is needed. The database comes with the program.

```
npm install
npm run try
```

The first time takes 2–3 minutes (it prepares the database and builds Legion);
after that, a few seconds.

**You should see:**

```
OK  Database running on port 54329
OK  Schema applied
OK  Configuration written

Legion is starting.
  Dashboard:  http://localhost:3000
```

**Open the address on the last line in a browser** and go to **step 5**.

> **Note:** if port 3000 is used by another program, Legion finds a free port
> itself and says so:
> ```
> Dashboard port 3000 is busy — using 3001 instead.
>   Dashboard:  http://localhost:3001
> ```
> In that case open **the address it shows**, not `3000`.

> ⚠️ **This is for testing only.** The database lives inside the program folder
> (`.legion-testdb`), is not backed up, and the package it uses has no stable
> release yet. For real use, follow the steps below (with a PostgreSQL you
> install yourself).
>
> To start from scratch: delete the `.legion-testdb` folder.

No Node.js? https://nodejs.org — the "LTS" button.

### If npm blocks the install script

Newer npm versions block some packages' install steps for security, and warn
like this at the end of `npm install`:

```
npm warn allow-scripts  @embedded-postgres/windows-x64 (install scripts present)
```

Then the PostgreSQL files are not fully installed. Allow it:

```
npm approve-scripts --allow-scripts-pending
npm install
npm run try
```

If you prefer not to allow it, follow the steps below (you install PostgreSQL
yourself and no script runs).

---

## A real installation

You need Node.js and PostgreSQL. Docker is not required — Legion runs directly
on Node.js and stores data in the PostgreSQL you install.

---

## Step 1. Install Node.js

https://nodejs.org — click "LTS" and install.

**Check:** in a terminal, `node --version` → should start with `v20.` or `v22.`

## Step 2. Install PostgreSQL

This is the database where Legion keeps its data. You install it once and forget it.

**Windows, step by step:**

1. https://www.postgresql.org/download/windows/ → "Download the installer"
2. Download the newest version (e.g. 17.x) and run it
3. In the wizard:

| Window | What to do |
|---|---|
| Installation Directory | **Next** (do not change) |
| Select Components | **Next** (leave everything ticked) |
| Data Directory | **Next** |
| **Password** | ⚠️ **Choose a password and WRITE IT DOWN** |
| Port | **5432** — do not change, **Next** |
| Advanced Options / Locale | **Next** |
| Ready to Install | **Next** → wait |
| Stack Builder (at the end) | **Untick** it, **Finish** |

> The **Password** window matters most. The next step asks for that password.
> Write it down or choose one you will remember.

**Mac:** https://postgresapp.com — download, open, click "Initialize".

**Linux:** `sudo apt install postgresql` (or your distribution's equivalent)

**Check (Windows, in PowerShell):**

```powershell
Get-Service -Name "*postgres*"
```

You should see `Running`. If it says `Stopped`:

```powershell
Start-Service -Name "postgresql*"
```

## Step 3. Unzip and configure

Unzip the archive, go to that folder in a terminal, and run:

```
npm install
npm run setup
```

> Always run `npm install` **first**. Without it `npm run setup` does not work
> (it cannot find the packages it needs).

`npm run setup` finds PostgreSQL, creates a database for Legion and generates
the secrets.

**If it asks for a password** — enter the one you wrote down in the Password
window in step 2. Skip the other questions (Host, Port, Superuser name) with Enter.

**You should see:**

```
✓ Node.js v22.x.x
✓ Connected to PostgreSQL
✓ Created database "legion"
✓ Wrote server/.env with new secrets
✓ Database schema applied

Setup complete.
```

## Step 4. Start it

```
npm run build
npm start
```

**You should see:** `Legion Node API: http://localhost:8000`

On Windows, one file does it all instead:
```
.\start-legion.ps1
```

Now go to **step 5** (open it in a browser).

---

## Step 5. Open it and create the admin

In a browser: **http://localhost:3000**

**You should see:** the Legion logo and a sign-in window.

Sign up — choose an email and password (a real email is not needed; for a test,
`admin@test.example` is fine).

This is the **first administrator** account. After it, sign-up closes.

---

## Step 6. Check that it works

Five simple checks, a minute each.

### 6.1 Does sign-in work
Sign out and sign in again. It should work.

### 6.2 Is sign-up closed
Open a new private (incognito) window, go to http://localhost:3000 again and
try to sign up.

**You should see:** *"This Legion installation is already set up"* — a stranger
cannot open an account. That is correct.

### 6.3 Invite a colleague
Settings → Team → enter an email, choose a role, send the invitation.

Since SMTP is not configured, no email is sent — instead a **link** appears on
screen. Open it in a private window, set a password and sign in.

**You should see:** the new user can sign in, with limited rights (for example,
an analyst cannot see the audit log).

### 6.4 Two-factor sign-in
Settings → Two-factor authentication → Set up.

Add the key shown to the authenticator app on your phone (Google Authenticator,
Authy) and enter the code.

**You should see:** 10 recovery codes. Keep them. Then sign out and back in —
after the password it now asks for a code.

### 6.5 Is the server healthy
Open in a browser: **http://localhost:8000/health**

**You should see:**
```
{"status":"ok","runtime":"node","database":"up","ai":false}
```

`database: up` matters most. `ai: false` is normal: no AI key is set, so no data
leaves your computer.

---

## Step 7. Stopping and restarting

`Ctrl+C` in the terminal stops it. To start again: `npm start`
(for a permanent server — `sudo systemctl restart legion`, if you installed
[deploy/legion.service](deploy/legion.service)).

**Important check:** stop it, start it again and **sign in**. Your account and
data must still be there. If they are gone, report it — that is a serious problem.

---

## What next

If these seven steps worked, Legion is running on your computer.

The next two tasks — **before your first customer**:

1. **Repeat on a server.** The same steps, on a real server, following
   [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md).

2. **Connect a real Wazuh.** See [WAZUH.md](WAZUH.md). This is the most
   important test.

---

## When something goes wrong

Find the error message — it appears directly in the terminal (or in
`journalctl -u legion -f` if you started it through systemd).

Send the text to support — you do not need to understand the code; the reason
is written in that text.

### Common errors

| Error | Cause and fix |
|---|---|
| `'tsx' is not recognized` or `Dependencies are not installed` | `npm install` was not run — run it first |
| `The bundled PostgreSQL is installed but incomplete` | npm blocked the install script — see the note above |
| `Could not start the database` | Below the message there is a **"What the database reported"** section with the reason. On Windows the Visual C++ runtime is often missing: https://aka.ms/vs/17/release/vc_redist.x64.exe |
| `Execution of PostgreSQL by a user with administrative permissions is not permitted` | The terminal was opened **as administrator**. Close it; open a normal window by typing `powershell` in the `legion` folder's address bar; run `Remove-Item -Recurse -Force .legion-testdb`, then `npm run try`. If the same error appears (the computer opens everything as administrator): `runas /trustlevel:0x20000 "cmd /k cd /d C:\legion && npm run try"` — a new window opens; do not close it. |
| `Refusing to start: JWT_SECRET…` | Setup was not run — `npm run setup` |
| `ECONNREFUSED …:5432` | PostgreSQL is not running — do the check in step 2 |
| `password authentication failed` | Wrong password — run `npm run setup` again |
| `EADDRINUSE` | Port 8000 or 3000 is busy — another program uses it |
| `12 vulnerabilities (… high, … critical)` at the end of `npm install` | A warning, not an error: the number of known issues in the public package database. **Do nothing, carry on** (do **not** run `npm audit fix --force` — it can break the program). The ones used while the server runs are up to date; the rest are build-time tools that never touch your data. |

### Starting from scratch

Do not worry about breaking anything: this is your computer, for testing.

To reset: in PostgreSQL run `DROP DATABASE legion;`, then run `npm run setup` again.
