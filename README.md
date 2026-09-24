# ConnectID — GitHub + Render

This is the flat-file version. **No folders are required.**

Files:
- `index.html` — frontend
- `server.js` — backend/API
- `package.json` — dependencies
- `render.yaml` — Render deployment
- `.env.example` — environment template
- `.gitignore` — ignores secrets/runtime data
- `API.md` — API reference
- `README.md` — setup

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:10000`.

Health check: `http://localhost:10000/api/health`

## Demo organization

Code: `HOSP001`
Password: `hospital123`

`EMAIL_MODE=demo` returns OTPs in API responses for the demo.

## GitHub

Upload all files directly into the root of your GitHub repository.

```bash
git init
git add .
git commit -m "ConnectID backend and frontend"
git branch -M main
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main
```

Never commit `.env`, API keys, database files, or passwords.

## Render

Connect the GitHub repository to Render. `render.yaml` configures the Node service automatically.

## Real Gmail OTP

Later set:
- `EMAIL_MODE=resend`
- `RESEND_API_KEY`
- `RESEND_FROM_EMAIL`

The current demo does not require an email provider.
