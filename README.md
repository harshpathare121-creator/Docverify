# ConnectID Demo — Multi-user + Backend + Admin Portal

Flat-file demo project for GitHub + Render.

## What changed

- Frontend now uses the backend API instead of storing user data in localStorage.
- Every registered person gets a unique permanent Person ID (`PID-100245`, `PID-100246`, ...).
- Multiple people can register independently.
- Documents, access requests, notifications, and audit events are stored in SQLite.
- New top-right menu contains About, Organization Portal, and Admin Portal.
- Demo Admin Portal can view all user records, including profile data, document OCR metadata, access requests, notifications, and activity.
- Demo Organization Portal supports requesting data, OTP authorization, and viewing granted fields.
- Node is pinned to 20.19.0 for Render compatibility.

## Demo credentials

### Organization
- Code: `HOSP001`
- Password: `hospital123`

### Admin
- Code: `ADMIN001`
- Password: `admin12345`

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:10000`.

## Important

This is a prototype. OCR is simulated. Gmail OTP is in demo mode unless Resend is configured. The Admin Portal intentionally has full access because this is a judge/demo environment.

## Render

The included `render.yaml` uses a persistent disk at `/var/data` and pins Node 20.19.0.
If you are using an existing Render Web Service rather than a Blueprint-managed service, manually add:

`NODE_VERSION=20.19.0`

Then use **Clear build cache & deploy** if the service still shows Node 26.
