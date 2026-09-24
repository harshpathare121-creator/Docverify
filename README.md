# ConnectID Demo — stable Render build

This version keeps the same ConnectID demo flow but removes the native SQLite dependency. Data is stored in a JSON file on the Render persistent disk, so the service does not need `better-sqlite3`/node-gyp during deployment.

## Demo credentials
- Organization: `HOSP001` / `hospital123`
- Admin: `ADMIN001` / `admin12345`
- Registration: Gmail only; demo OTP is shown on screen.

## Features
- Unique permanent Person IDs (`PID-100245`, `PID-100246`, ...)
- Document upload + simulated OCR metadata
- Organization access requests
- Person approve/deny
- OTP authorization
- Granted access + revoke
- Notifications + audit trail
- Demo Admin Portal with full user records and uploaded files

## Render
Deploy the flat project with `npm install` and `npm start`. `NODE_VERSION=20.19.0` is pinned. Persistent data is stored under `/var/data` when the included Blueprint is used.
