# ConnectID API quick reference

## Person
POST /api/auth/register
POST /api/auth/verify-email
POST /api/auth/login
GET  /api/me
GET  /api/documents
POST /api/documents
GET  /api/access-requests
POST /api/access-requests/:id/decision
POST /api/access-requests/:id/revoke
GET  /api/notifications
POST /api/notifications/:id/read
GET  /api/audit

## Organization
POST /api/org/login
POST /api/access-requests
GET  /api/org/access-requests
POST /api/access-requests/:id/authorize
GET  /api/granted-data/:requestId

## System
GET /api/health
