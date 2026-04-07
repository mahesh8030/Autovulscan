# AutoVulnScan 🔐

Web Application Security Testing Platform

## Deploy to Render (Free)

### Step 1 — Push to GitHub
1. Create a new GitHub repo named `autovulnscan`
2. Upload all files from this folder
3. Commit and push

### Step 2 — Deploy on Render
1. Go to render.com → New → Web Service
2. Connect your GitHub repo
3. Settings:
   - Build Command: `npm install && npm run build`
   - Start Command: `npm start`
   - Environment: Node

### Step 3 — Add PostgreSQL Database
1. In Render → New → PostgreSQL (free plan)
2. Name it: `autovulnscan-db`
3. Copy the "Internal Database URL"
4. In your Web Service → Environment → Add:
   - `DATABASE_URL` = paste the URL
   - `SESSION_SECRET` = any random 32-char string
   - `NODE_ENV` = production

### Step 4 — Deploy
Click "Deploy" — your app will be live at `https://autovulnscan.onrender.com`

## Local Development

```bash
npm install
# Set DATABASE_URL in .env file
npm run build
npm start
```

## Tech Stack
- Backend: Node.js + Express + TypeScript
- Database: PostgreSQL (Drizzle ORM)
- Frontend: Vanilla JS + TailwindCSS (CDN)
- Auth: Express Sessions

## ⚠️ Legal Notice
For educational and authorised security assessment only.
