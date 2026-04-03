# GradeVault — Vercel Deployment Guide

> FUTO GPA & CGPA Calculator · 5-Point Scale · Free Hosting

---

## File Structure

```
gradevault/
├── api/
│   └── index.py      ← Python serverless API (Flask)
├── index.html        ← Frontend (served as static)
├── vercel.json       ← Routing config
├── requirements.txt  ← Python dependencies
└── README.md
```

---

## Step 1 — Create a Free PostgreSQL Database (Neon)

1. Go to **https://neon.tech** and sign up for free
2. Create a new project (e.g. `gradevault`)
3. Copy the **Connection String** — it looks like:
   ```
   postgresql://username:password@ep-xxx.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
   Keep this, you'll need it in Step 3.

---

## Step 2 — Push to GitHub

```bash
# One-time setup
git init
git add .
git commit -m "Initial GradeVault"

# Create a repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/gradevault.git
git push -u origin main
```

---

## Step 3 — Deploy on Vercel

1. Go to **https://vercel.com** and sign up free (use GitHub login)
2. Click **"Add New Project"** → Import your `gradevault` repo
3. Leave build settings as defaults (Vercel auto-detects)
4. Before clicking Deploy, go to **Environment Variables** and add:

   | Name               | Value                                |
   |--------------------|--------------------------------------|
   | `DATABASE_URL`     | your Neon connection string          |
   | `SESSION_SECRET`   | any random string (e.g. 32 chars)    |
   | `ALLOWED_ORIGIN`   | your Vercel URL (after first deploy) |

5. Click **Deploy** — takes ~60 seconds

---

## Step 4 — Set ALLOWED_ORIGIN (after first deploy)

After your first deploy, Vercel will give you a URL like:
`https://gradevault-abc123.vercel.app`

Go to **Settings → Environment Variables** and set:
```
ALLOWED_ORIGIN = https://gradevault-abc123.vercel.app
```

Then redeploy (Deployments → Redeploy latest).

---

## Updating the App

```bash
git add .
git commit -m "Update: ..."
git push
```
Vercel auto-deploys every push to `main`.

---

## Local Development (optional)

```bash
pip install flask flask-cors psycopg2-binary

# Set env vars
export DATABASE_URL="your-neon-connection-string"
export SESSION_SECRET="dev-secret"

python api/index.py     # → http://localhost:5000
```

---

## Free Tier Limits (both services are free)

| Service | Free Limit                        |
|---------|-----------------------------------|
| Vercel  | 100 GB bandwidth/month, unlimited deploys |
| Neon    | 0.5 GB storage, 190 compute hours/month |

Both are more than enough for a student GPA calculator.
