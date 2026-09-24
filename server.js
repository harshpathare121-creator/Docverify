import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import Database from "better-sqlite3";
import { Resend } from "resend";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || "change-this-in-render";
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 10);
const EMAIL_MODE = process.env.EMAIL_MODE || "demo";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");

fs.mkdirSync(DATA_DIR, { recursive: true });
const uploadDir = path.join(DATA_DIR, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(DATA_DIR, "connectid.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  mobile TEXT,
  password_hash TEXT NOT NULL,
  email_verified INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  original_name TEXT NOT NULL,
  stored_name TEXT,
  document_type TEXT,
  extracted_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS access_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id TEXT NOT NULL,
  organization_id INTEGER NOT NULL,
  requested_data TEXT NOT NULL,
  purpose TEXT NOT NULL,
  duration TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  otp_hash TEXT,
  otp_expires_at TEXT,
  created_at TEXT NOT NULL,
  approved_at TEXT,
  granted_at TEXT,
  revoked_at TEXT,
  FOREIGN KEY(organization_id) REFERENCES organizations(id)
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  read INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id TEXT,
  organization_id INTEGER,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  purpose TEXT NOT NULL
);
`);

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 10 * 1024 * 1024 }
});

function now() { return new Date().toISOString(); }
function makePersonId() {
  const row = db.prepare(`
    SELECT COALESCE(MAX(CAST(SUBSTR(person_id, 5) AS INTEGER)), 100244) AS n
    FROM users
  `).get();
  return `PID-${Number(row.n) + 1}`;
}
function makeOtp() { return String(crypto.randomInt(100000, 1000000)); }
function hashOtp(otp) { return crypto.createHash("sha256").update(otp).digest("hex"); }

function tokenFor(user) {
  return jwt.sign(
    { sub: user.id, personId: user.person_id, email: user.email, role: "person" },
    JWT_SECRET, { expiresIn: "2h" }
  );
}
function orgTokenFor(org) {
  return jwt.sign(
    { sub: org.id, orgCode: org.org_code, role: "organization" },
    JWT_SECRET, { expiresIn: "2h" }
  );
}
function adminTokenFor(admin) {
  return jwt.sign(
    { sub: admin.id, adminCode: admin.admin_code, role: "admin" },
    JWT_SECRET, { expiresIn: "2h" }
  );
}
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
function personAuth(req, res, next) {
  auth(req, res, () => req.auth.role === "person"
    ? next() : res.status(403).json({ error: "Person access required" }));
}
function orgAuth(req, res, next) {
  auth(req, res, () => req.auth.role === "organization"
    ? next() : res.status(403).json({ error: "Organization access required" }));
}
function adminAuth(req, res, next) {
  auth(req, res, () => req.auth.role === "admin"
    ? next() : res.status(403).json({ error: "Admin access required" }));
}

async function sendOtpEmail(email, otp) {
  if (EMAIL_MODE === "resend") {
    if (!RESEND_API_KEY || !RESEND_FROM_EMAIL) throw new Error("Resend is not configured");
    const resend = new Resend(RESEND_API_KEY);
    await resend.emails.send({
      from: RESEND_FROM_EMAIL,
      to: email,
      subject: "ConnectID verification code",
      html: `<p>Your ConnectID verification code is <strong>${otp}</strong>.</p><p>This code expires in ${OTP_TTL_MINUTES} minutes.</p>`
    });
    return { delivered: true };
  }
  return { delivered: false, demoOtp: otp };
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "ConnectID API", time: now() }));

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body || {};
    const cleanEmail = String(email || "").trim().toLowerCase();
    if (!String(name || "").trim() || !cleanEmail.endsWith("@gmail.com") || String(password || "").length < 6) {
      return res.status(400).json({ error: "Name, Gmail address, and password (6+ chars) are required" });
    }
    if (db.prepare("SELECT id FROM users WHERE email=?").get(cleanEmail)) {
      return res.status(409).json({ error: "Gmail address is already registered" });
    }

    const otp = makeOtp();
    const expires = new Date(Date.now() + OTP_TTL_MINUTES * 60000).toISOString();
    const passwordHash = await bcrypt.hash(String(password), 12);
    const personId = makePersonId();

    db.prepare(`
      INSERT INTO users(person_id,name,email,mobile,password_hash,email_verified,created_at)
      VALUES(?,?,?,?,?,0,?)
    `).run(personId, String(name).trim(), cleanEmail, String(mobile || "").trim(), passwordHash, now());

    db.prepare("DELETE FROM pending_otps WHERE email=? AND purpose='register'").run(cleanEmail);
    db.prepare("INSERT INTO pending_otps(email,otp_hash,expires_at,purpose) VALUES(?,?,?,'register')")
      .run(cleanEmail, hashOtp(otp), expires);

    const mail = await sendOtpEmail(cleanEmail, otp);
    res.status(201).json({
      message: "Registration created. Verify Gmail to activate the account.",
      personId,
      email: cleanEmail,
      ...(mail.demoOtp ? { demoOtp: mail.demoOtp } : {})
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Registration failed" });
  }
});

app.post("/api/auth/verify-email", (req, res) => {
  const { email, otp } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const row = db.prepare("SELECT * FROM pending_otps WHERE email=? AND purpose='register' ORDER BY id DESC LIMIT 1").get(cleanEmail);
  if (!row) return res.status(400).json({ error: "No verification code found" });
  if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: "Verification code expired" });
  if (hashOtp(String(otp || "")) !== row.otp_hash) return res.status(400).json({ error: "Invalid verification code" });

  db.prepare("UPDATE users SET email_verified=1 WHERE email=?").run(cleanEmail);
  db.prepare("DELETE FROM pending_otps WHERE email=? AND purpose='register'").run(cleanEmail);
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(cleanEmail);
  res.json({ message: "Gmail verified", token: tokenFor(user), personId: user.person_id });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(cleanEmail);
  if (!user || !(await bcrypt.compare(String(password || ""), user.password_hash))) {
    return res.status(401).json({ error: "Invalid Gmail or password" });
  }
  if (!user.email_verified) return res.status(403).json({ error: "Verify Gmail before logging in" });
  res.json({
    token: tokenFor(user),
    user: { id: user.id, personId: user.person_id, name: user.name, email: user.email, mobile: user.mobile }
  });
});

app.post("/api/org/login", async (req, res) => {
  const { orgCode, password } = req.body || {};
  const org = db.prepare("SELECT * FROM organizations WHERE org_code=?").get(String(orgCode || "").trim());
  if (!org || !(await bcrypt.compare(String(password || ""), org.password_hash))) {
    return res.status(401).json({ error: "Invalid organization credentials" });
  }
  res.json({ token: orgTokenFor(org), organization: { id: org.id, code: org.org_code, name: org.name, type: org.type } });
});

app.post("/api/admin/login", async (req, res) => {
  const { adminCode, password } = req.body || {};
  const admin = db.prepare("SELECT * FROM admins WHERE admin_code=?").get(String(adminCode || "").trim());
  if (!admin || !(await bcrypt.compare(String(password || ""), admin.password_hash))) {
    return res.status(401).json({ error: "Invalid admin credentials" });
  }
  res.json({ token: adminTokenFor(admin), admin: { id: admin.id, code: admin.admin_code, name: admin.name } });
});

app.get("/api/me", personAuth, (req, res) => {
  const user = db.prepare(`
    SELECT id,person_id,name,email,mobile,email_verified,created_at
    FROM users WHERE id=?
  `).get(req.auth.sub);
  res.json(user);
});

app.get("/api/documents", personAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id,original_name,document_type,extracted_json,created_at
    FROM documents WHERE user_id=? ORDER BY id DESC
  `).all(req.auth.sub);
  res.json(rows.map(r => ({ ...r, extracted: r.extracted_json ? JSON.parse(r.extracted_json) : null })));
});

app.post("/api/documents", personAuth, upload.single("document"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Document file is required" });
  const extracted = {
    FullName: req.body.fullName || "",
    PersonID: req.body.personId || req.auth.personId,
    DocumentType: req.body.documentType || "Uploaded Document",
    ocrStatus: "demo"
  };
  const result = db.prepare(`
    INSERT INTO documents(user_id,original_name,stored_name,document_type,extracted_json,created_at)
    VALUES(?,?,?,?,?,?)
  `).run(
    req.auth.sub, req.file.originalname, req.file.filename,
    extracted.DocumentType, JSON.stringify(extracted), now()
  );
  db.prepare("INSERT INTO audit_logs(person_id,action,details,created_at) VALUES(?,?,?,?)")
    .run(req.auth.personId, "DOCUMENT_UPLOADED", JSON.stringify({ documentId: result.lastInsertRowid, fileName: req.file.originalname }), now());

  res.status(201).json({
    id: result.lastInsertRowid,
    fileName: req.file.originalname,
    extracted,
    message: "Document stored. OCR adapter is currently in demo mode."
  });
});

app.post("/api/access-requests", orgAuth, (req, res) => {
  const { personId, requestedData, purpose, duration } = req.body || {};
  const person = db.prepare("SELECT id,person_id FROM users WHERE person_id=? AND email_verified=1").get(String(personId || "").trim());
  if (!person) return res.status(404).json({ error: "Verified person not found" });
  if (!Array.isArray(requestedData) || requestedData.length === 0 || !purpose || !duration) {
    return res.status(400).json({ error: "Requested data, purpose, and duration are required" });
  }

  const result = db.prepare(`
    INSERT INTO access_requests(person_id,organization_id,requested_data,purpose,duration,status,created_at)
    VALUES(?,?,?,?,?,'Pending',?)
  `).run(person.person_id, req.auth.sub, JSON.stringify(requestedData), String(purpose), String(duration), now());

  const org = db.prepare("SELECT name FROM organizations WHERE id=?").get(req.auth.sub);
  db.prepare("INSERT INTO notifications(person_id,title,message,created_at) VALUES(?,?,?,?)")
    .run(person.person_id, "New data access request", `${org.name} requested ${requestedData.join(", ")} for ${purpose}.`, now());

  db.prepare("INSERT INTO audit_logs(person_id,organization_id,action,details,created_at) VALUES(?,?,?,?,?)")
    .run(person.person_id, req.auth.sub, "ACCESS_REQUEST_CREATED", JSON.stringify({ requestId: result.lastInsertRowid }), now());

  res.status(201).json({ id: result.lastInsertRowid, status: "Pending" });
});

app.get("/api/access-requests", personAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT ar.*, o.name AS organization_name, o.type AS organization_type
    FROM access_requests ar JOIN organizations o ON o.id=ar.organization_id
    WHERE ar.person_id=? ORDER BY ar.id DESC
  `).all(req.auth.personId);
  res.json(rows.map(r => ({ ...r, requestedData: JSON.parse(r.requested_data) })));
});

app.get("/api/org/access-requests", orgAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT ar.*, u.name AS person_name, o.name AS organization_name
    FROM access_requests ar
    JOIN users u ON u.person_id=ar.person_id
    JOIN organizations o ON o.id=ar.organization_id
    WHERE ar.organization_id=? ORDER BY ar.id DESC
  `).all(req.auth.sub);
  res.json(rows.map(r => ({ ...r, requestedData: JSON.parse(r.requested_data) })));
});

app.post("/api/access-requests/:id/decision", personAuth, (req, res) => {
  const { decision } = req.body || {};
  const request = db.prepare("SELECT * FROM access_requests WHERE id=? AND person_id=?").get(req.params.id, req.auth.personId);
  if (!request) return res.status(404).json({ error: "Request not found" });
  if (!["approve", "deny"].includes(decision)) return res.status(400).json({ error: "Decision must be approve or deny" });
  if (request.status !== "Pending") return res.status(400).json({ error: "Request is no longer pending" });

  if (decision === "deny") {
    db.prepare("UPDATE access_requests SET status='Denied' WHERE id=?").run(request.id);
    db.prepare("INSERT INTO audit_logs(person_id,organization_id,action,details,created_at) VALUES(?,?,?,?,?)")
      .run(request.person_id, request.organization_id, "ACCESS_REQUEST_DENIED", JSON.stringify({ requestId: request.id }), now());
    return res.json({ status: "Denied" });
  }

  const otp = makeOtp();
  const expires = new Date(Date.now() + OTP_TTL_MINUTES * 60000).toISOString();
  db.prepare("UPDATE access_requests SET status='Awaiting OTP',otp_hash=?,otp_expires_at=?,approved_at=? WHERE id=?")
    .run(hashOtp(otp), expires, now(), request.id);
  db.prepare("INSERT INTO notifications(person_id,title,message,created_at) VALUES(?,?,?,?)")
    .run(req.auth.personId, "Access approved", "Your approval is waiting for authorization by the requesting organization.", now());
  res.json({ status: "Awaiting OTP", ...(EMAIL_MODE === "demo" ? { demoOtp: otp } : {}) });
});

app.post("/api/access-requests/:id/authorize", orgAuth, (req, res) => {
  const { otp } = req.body || {};
  const request = db.prepare("SELECT * FROM access_requests WHERE id=? AND organization_id=?").get(req.params.id, req.auth.sub);
  if (!request) return res.status(404).json({ error: "Request not found" });
  if (request.status !== "Awaiting OTP") return res.status(400).json({ error: "Request is not awaiting OTP" });
  if (!request.otp_expires_at || new Date(request.otp_expires_at) < new Date()) return res.status(400).json({ error: "Authorization OTP expired" });
  if (hashOtp(String(otp || "")) !== request.otp_hash) return res.status(400).json({ error: "Invalid authorization OTP" });

  db.prepare("UPDATE access_requests SET status='Granted',granted_at=? WHERE id=?").run(now(), request.id);
  db.prepare("INSERT INTO notifications(person_id,title,message,created_at) VALUES(?,?,?,?)")
    .run(request.person_id, "Data access granted", "Your approved request has been authorized by the organization.", now());
  db.prepare("INSERT INTO audit_logs(person_id,organization_id,action,details,created_at) VALUES(?,?,?,?,?)")
    .run(request.person_id, request.organization_id, "ACCESS_GRANTED", JSON.stringify({ requestId: request.id }), now());

  res.json({ status: "Granted", message: "Access granted for the approved request." });
});

app.post("/api/access-requests/:id/revoke", personAuth, (req, res) => {
  const request = db.prepare("SELECT * FROM access_requests WHERE id=? AND person_id=?").get(req.params.id, req.auth.personId);
  if (!request) return res.status(404).json({ error: "Request not found" });
  if (request.status !== "Granted") return res.status(400).json({ error: "Only granted access can be revoked" });
  db.prepare("UPDATE access_requests SET status='Revoked',revoked_at=? WHERE id=?").run(now(), request.id);
  db.prepare("INSERT INTO audit_logs(person_id,organization_id,action,details,created_at) VALUES(?,?,?,?,?)")
    .run(request.person_id, request.organization_id, "ACCESS_REVOKED", JSON.stringify({ requestId: request.id }), now());
  res.json({ status: "Revoked" });
});

app.get("/api/notifications", personAuth, (req, res) => {
  res.json(db.prepare("SELECT * FROM notifications WHERE person_id=? ORDER BY id DESC").all(req.auth.personId));
});
app.post("/api/notifications/:id/read", personAuth, (req, res) => {
  db.prepare("UPDATE notifications SET read=1 WHERE id=? AND person_id=?").run(req.params.id, req.auth.personId);
  res.json({ ok: true });
});
app.get("/api/audit", personAuth, (req, res) => {
  res.json(db.prepare(`
    SELECT a.*, o.name AS organization_name
    FROM audit_logs a LEFT JOIN organizations o ON o.id=a.organization_id
    WHERE a.person_id=? ORDER BY a.id DESC
  `).all(req.auth.personId));
});

app.get("/api/granted-data/:requestId", orgAuth, (req, res) => {
  const request = db.prepare(`
    SELECT ar.*, u.name, u.email, u.mobile
    FROM access_requests ar JOIN users u ON u.person_id=ar.person_id
    WHERE ar.id=? AND ar.organization_id=? AND ar.status='Granted'
  `).get(req.params.requestId, req.auth.sub);
  if (!request) return res.status(403).json({ error: "No active authorization for this request" });
  const wanted = JSON.parse(request.requested_data);
  const data = { personId: request.person_id, name: request.name };
  if (wanted.includes("Email")) data.email = request.email;
  if (wanted.includes("Mobile")) data.mobile = request.mobile;
  res.json({ requestId: request.id, access: data, purpose: request.purpose, duration: request.duration });
});

/* ---------------- Demo Admin Portal ---------------- */
app.get("/api/admin/overview", adminAuth, (req, res) => {
  const users = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  const verifiedUsers = db.prepare("SELECT COUNT(*) AS n FROM users WHERE email_verified=1").get().n;
  const organizations = db.prepare("SELECT COUNT(*) AS n FROM organizations").get().n;
  const documents = db.prepare("SELECT COUNT(*) AS n FROM documents").get().n;
  const requests = db.prepare("SELECT COUNT(*) AS n FROM access_requests").get().n;
  const pending = db.prepare("SELECT COUNT(*) AS n FROM access_requests WHERE status='Pending'").get().n;
  const granted = db.prepare("SELECT COUNT(*) AS n FROM access_requests WHERE status='Granted'").get().n;
  res.json({ users, verifiedUsers, organizations, documents, requests, pending, granted });
});

app.get("/api/admin/users", adminAuth, (req, res) => {
  const users = db.prepare(`
    SELECT id,person_id,name,email,mobile,email_verified,created_at
    FROM users ORDER BY id DESC
  `).all();

  const docStmt = db.prepare(`
    SELECT id,original_name,document_type,extracted_json,created_at
    FROM documents WHERE user_id=? ORDER BY id DESC
  `);
  const requestStmt = db.prepare(`
    SELECT ar.*, o.name AS organization_name, o.type AS organization_type
    FROM access_requests ar JOIN organizations o ON o.id=ar.organization_id
    WHERE ar.person_id=? ORDER BY ar.id DESC
  `);
  const notificationStmt = db.prepare(`
    SELECT id,title,message,read,created_at FROM notifications
    WHERE person_id=? ORDER BY id DESC
  `);
  const auditStmt = db.prepare(`
    SELECT a.*, o.name AS organization_name
    FROM audit_logs a LEFT JOIN organizations o ON o.id=a.organization_id
    WHERE a.person_id=? ORDER BY a.id DESC
  `);

  res.json(users.map(u => ({
    ...u,
    documents: docStmt.all(u.id).map(d => ({
      ...d,
      extracted: d.extracted_json ? JSON.parse(d.extracted_json) : null
    })),
    accessRequests: requestStmt.all(u.person_id).map(r => ({
      ...r, requestedData: JSON.parse(r.requested_data)
    })),
    notifications: notificationStmt.all(u.person_id),
    audit: auditStmt.all(u.person_id)
  })));
});

app.get("/api/admin/documents/:id/download", adminAuth, (req, res) => {
  const doc = db.prepare("SELECT original_name, stored_name FROM documents WHERE id=?").get(req.params.id);
  if (!doc || !doc.stored_name) return res.status(404).json({ error: "Document file not found" });
  const filePath = path.join(uploadDir, doc.stored_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Stored document file is missing" });
  res.download(filePath, doc.original_name);
});

app.get("/api/admin/organizations", adminAuth, (req, res) => {
  res.json(db.prepare(`
    SELECT id,org_code,name,type,created_at FROM organizations ORDER BY id DESC
  `).all());
});

app.get("/api/admin/audit", adminAuth, (req, res) => {
  res.json(db.prepare(`
    SELECT a.*, u.name AS person_name, o.name AS organization_name
    FROM audit_logs a
    LEFT JOIN users u ON u.person_id=a.person_id
    LEFT JOIN organizations o ON o.id=a.organization_id
    ORDER BY a.id DESC LIMIT 500
  `).all());
});

/* Seed demo organization and admin. */
const orgCount = db.prepare("SELECT COUNT(*) AS n FROM organizations").get().n;
if (orgCount === 0) {
  const passwordHash = await bcrypt.hash("hospital123", 12);
  db.prepare("INSERT INTO organizations(org_code,name,type,password_hash,created_at) VALUES(?,?,?,?,?)")
    .run("HOSP001", "CityCare Hospital", "Hospital", passwordHash, now());
}
const adminCount = db.prepare("SELECT COUNT(*) AS n FROM admins").get().n;
if (adminCount === 0) {
  const passwordHash = await bcrypt.hash("admin12345", 12);
  db.prepare("INSERT INTO admins(admin_code,name,password_hash,created_at) VALUES(?,?,?,?)")
    .run("ADMIN001", "ConnectID Demo Admin", passwordHash, now());
}

app.use(express.static(__dirname));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ConnectID API listening on port ${PORT}`);
});
