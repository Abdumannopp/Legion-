# Running Legion with Docker Desktop (Windows)

With this method Legion, its database and its dashboard all run inside Docker
Desktop. You do not need to install PostgreSQL or Node.js on your computer;
everything is prepared automatically. This is for **testing and demos**. To put
Legion online, use [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md).

---

## Step 1. Install Docker Desktop (once)

1. Open in a browser: **https://www.docker.com/products/docker-desktop/**
2. Click **Download for Windows** and install the file.
3. **Restart** the computer.
4. Open **Docker Desktop**. If it offers to install WSL 2, answer **yes**.
5. Wait until the green **"Engine running"** label appears in the bottom left (1–3 minutes).

## Step 2. Unzip the project

1. Right-click the downloaded **`legion-….zip`** → **Extract All…** → **Extract**.
2. A **`legion`** folder appears inside.

## Step 3. Start Legion

1. Open the **`legion`** folder.
2. Click the address bar at the top, type `powershell` and press **Enter**.
3. In the window that opens, type this one line and press **Enter**:

   ```
   powershell -ExecutionPolicy Bypass -File .\start-docker.ps1
   ```

4. The first time takes **5–15 minutes** (files are downloaded and built). Text scrolls past; that is normal.
5. At the end you see:

   ```
   Legion is ready:  http://localhost:3000
   ```

## Step 4. Create the first administrator account

1. Open **http://localhost:3000/setup** in a browser.
2. It asks for a **setup token**. Get it in the PowerShell window:

   ```
   docker compose exec backend cat /app/server/.legion-setup-token
   ```

   Copy the long text it prints (starting with `lst_…`) and paste it into the page.
3. Enter your email, password and organisation name. You become the administrator.

After that, sign in normally at **http://localhost:3000**.

---

## Every day

| What | How |
|---|---|
| Start | Open Docker Desktop (wait for Engine running), then type the command from step 3 |
| Check it is running | `docker compose ps` (every line should be `running` or `healthy`) |
| View logs | `docker compose logs -f backend` (stop with **Ctrl+C**) |
| Stop | `docker compose down` (data is kept) |

**Where the data lives:** the database is kept in Docker's internal storage
(`legion-pgdata`). `docker compose down` does not delete it. To remove everything
for good (**data is lost**): `docker compose down -v`.

**Secret file:** `.env` contains passwords and keys. Never send it to anyone
and do not put it in a zip. If it is lost, Legion's data cannot be decrypted again.

---

## When something goes wrong

| Message | Cause and fix |
|---|---|
| `Docker Desktop is installed but not running` | Open Docker Desktop and wait for "Engine running" |
| `Docker Desktop is not installed` | Do step 1 |
| `running scripts is disabled on this system` | Type the command exactly: `powershell -ExecutionPolicy Bypass -File .\start-docker.ps1` |
| `port is already allocated` (3000 or 8000) | Another program uses that port. Restart Docker Desktop or the computer |
| `Legion did not report ready within three minutes` | Run `docker compose logs --tail=50 backend` and send the output to support |
| The page does not open in the browser | Run `docker compose ps`. If `backend` shows `Restarting`, run `docker compose logs --tail=50 backend` |
| The page opens but sign-in does not work | The address must be exactly `http://localhost:3000` (not `127.0.0.1`) |
| No password-reset email arrives | Email is not configured in this test setup. The link appears in the logs: `docker compose logs backend` |

Without changing anything, send the error text (or a screenshot) to support.

---

## Why this is a test setup

- The site opens only on this computer (`localhost`).
- Email (SMTP) is not configured: password-reset and invitation links are written to the logs.
- The database uses a single shared user (convenient for local testing, but less
  protected than the server setup). On a server, use the setup in DEPLOY-ONLINE.md.
