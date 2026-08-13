require("dotenv").config();

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_MB = Number(process.env.MAX_FILE_SIZE_MB || 25);

const DATA_DIR = path.join(__dirname, "data");
const STORAGE_DIR = path.join(__dirname, "storage");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(STORAGE_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "documents.db"));
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','employee')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  parent_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  current_version INTEGER NOT NULL DEFAULT 1,
  size INTEGER NOT NULL DEFAULT 0,
  mime_type TEXT,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS document_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  stored_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  mime_type TEXT,
  uploaded_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(document_id, version)
);
CREATE TABLE IF NOT EXISTS folder_permissions (
  folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  can_read INTEGER NOT NULL DEFAULT 1,
  can_write INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(folder_id, user_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id INTEGER,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const adminExists = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (!adminExists) {
  const hash = bcrypt.hashSync("ChangeMe123!", 12);
  const info = db.prepare("INSERT INTO users(email,name,password_hash,role) VALUES(?,?,?,?)")
    .run("admin@example.com", "System Administrator", hash, "admin");
  db.prepare("INSERT INTO folders(name,parent_id,created_by) VALUES('Shared Documents',NULL,?)").run(info.lastInsertRowid);
}

app.use(helmet({ crossOriginResourcePolicy: { policy: "same-site" } }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 8 * 60 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

function auth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Authentication required" });
  const user = db.prepare("SELECT id,email,name,role,active FROM users WHERE id=?").get(req.session.userId);
  if (!user || !user.active) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: "Session invalid" });
  }
  req.user = user;
  next();
}
function adminOnly(req,res,next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Administrator access required" });
  next();
}
function logAction(userId, action, entityType, entityId, details) {
  db.prepare("INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details) VALUES(?,?,?,?,?)")
    .run(userId, action, entityType, entityId || null, details ? JSON.stringify(details) : null);
}
function hasFolderAccess(user, folderId, write=false) {
  if (user.role === "admin") return true;
  let cur = db.prepare("SELECT id,parent_id FROM folders WHERE id=?").get(folderId);
  while (cur) {
    const p = db.prepare("SELECT can_read,can_write FROM folder_permissions WHERE folder_id=? AND user_id=?")
      .get(cur.id, user.id);
    if (p && (write ? p.can_write : p.can_read)) return true;
    cur = cur.parent_id ? db.prepare("SELECT id,parent_id FROM folders WHERE id=?").get(cur.parent_id) : null;
  }
  return false;
}
function sanitizeFilename(name) {
  return path.basename(name).replace(/[^a-zA-Z0-9._() -]/g, "_").slice(0, 180) || "file";
}

const storage = multer.diskStorage({
  destination: (req,file,cb) => cb(null, STORAGE_DIR),
  filename: (req,file,cb) => cb(null, crypto.randomUUID())
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter: (req,file,cb) => {
    if (!file.originalname || file.originalname.length > 255) return cb(new Error("Invalid filename"));
    cb(null,true);
  }
});

let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE) === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}
async function sendNotification(to, subject, text) {
  if (!to) return;
  if (!transporter) {
    console.log(`[EMAIL NOT CONFIGURED] To: ${to} | ${subject} | ${text}`);
    return;
  }
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to, subject, text
  });
}

app.post("/api/login", loginLimiter, async (req,res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE lower(email)=lower(?) AND active=1").get(String(email||"").trim());
  if (!user || !bcrypt.compareSync(String(password||""), user.password_hash))
    return res.status(401).json({ error: "Invalid email or password" });
  req.session.userId = user.id;
  logAction(user.id, "LOGIN", "user", user.id);
  res.json({ user: { id:user.id,email:user.email,name:user.name,role:user.role } });
});
app.post("/api/logout", auth, (req,res) => {
  logAction(req.user.id,"LOGOUT","user",req.user.id);
  req.session.destroy(()=>res.json({ok:true}));
});
app.get("/api/me", auth, (req,res)=>res.json({user:req.user}));

app.get("/api/folders", auth, (req,res) => {
  const rows = db.prepare("SELECT f.*, u.name AS creator FROM folders f JOIN users u ON u.id=f.created_by ORDER BY f.name").all();
  const visible = rows.filter(f => req.user.role==="admin" || hasFolderAccess(req.user,f.id));
  res.json({folders: visible});
});
app.post("/api/folders", auth, (req,res) => {
  const { name, parent_id=null } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({error:"Folder name required"});
  if (parent_id && !hasFolderAccess(req.user, Number(parent_id), true)) return res.status(403).json({error:"No write permission"});
  const info = db.prepare("INSERT INTO folders(name,parent_id,created_by) VALUES(?,?,?)")
    .run(String(name).trim().slice(0,120), parent_id || null, req.user.id);
  logAction(req.user.id,"CREATE","folder",info.lastInsertRowid,{name});
  res.json({id:info.lastInsertRowid});
});
app.delete("/api/folders/:id", auth, (req,res) => {
  const id=Number(req.params.id);
  const folder=db.prepare("SELECT * FROM folders WHERE id=?").get(id);
  if (!folder) return res.status(404).json({error:"Folder not found"});
  if (req.user.role!=="admin" && !hasFolderAccess(req.user,id,true)) return res.status(403).json({error:"No permission"});
  if (folder.name==="Shared Documents" && req.user.role!=="admin") return res.status(403).json({error:"Protected folder"});
  const docs=db.prepare("SELECT id FROM documents WHERE folder_id=?").all(id);
  for (const d of docs) {
    const versions=db.prepare("SELECT stored_name FROM document_versions WHERE document_id=?").all(d.id);
    versions.forEach(v=>{ try{fs.unlinkSync(path.join(STORAGE_DIR,v.stored_name));}catch{} });
  }
  db.prepare("DELETE FROM folders WHERE id=?").run(id);
  logAction(req.user.id,"DELETE","folder",id,{name:folder.name});
  res.json({ok:true});
});

app.get("/api/documents", auth, (req,res) => {
  const folderId=req.query.folder_id ? Number(req.query.folder_id) : null;
  const q=String(req.query.q||"").trim();
  let rows;
  if (folderId) {
    if (!hasFolderAccess(req.user,folderId)) return res.status(403).json({error:"No access"});
    rows=db.prepare(`
      SELECT d.*, u.name AS creator FROM documents d JOIN users u ON u.id=d.created_by
      WHERE d.folder_id=? AND d.original_name LIKE ? ORDER BY d.updated_at DESC`).all(folderId, `%${q}%`);
  } else {
    rows=db.prepare(`
      SELECT d.*, u.name AS creator FROM documents d JOIN users u ON u.id=d.created_by
      WHERE d.original_name LIKE ? ORDER BY d.updated_at DESC`).all(`%${q}%`)
      .filter(d=>req.user.role==="admin" || hasFolderAccess(req.user,d.folder_id));
  }
  res.json({documents:rows});
});

app.post("/api/documents/upload", auth, upload.single("file"), async (req,res) => {
  try {
    if (!req.file) return res.status(400).json({error:"File required"});
    const folderId=Number(req.body.folder_id);
    if (!folderId || !hasFolderAccess(req.user,folderId,true)) {
      fs.unlinkSync(req.file.path);
      return res.status(403).json({error:"No write permission for this folder"});
    }
    const name=sanitizeFilename(req.file.originalname);
    const doc=db.prepare("INSERT INTO documents(folder_id,original_name,current_version,size,mime_type,created_by) VALUES(?,?,1,?,?,?)")
      .run(folderId,name,req.file.size,req.file.mimetype,req.user.id);
    db.prepare("INSERT INTO document_versions(document_id,version,stored_name,size,mime_type,uploaded_by) VALUES(?,?,?,?,?,?)")
      .run(doc.lastInsertRowid,1,path.basename(req.file.filename),req.file.size,req.file.mimetype,req.user.id);
    logAction(req.user.id,"UPLOAD","document",doc.lastInsertRowid,{name,version:1});
    const admins=db.prepare("SELECT email FROM users WHERE role='admin' AND active=1").all();
    await Promise.all(admins.map(a=>sendNotification(a.email,"New document uploaded",`${req.user.name} uploaded ${name}.`)));
    res.json({id:doc.lastInsertRowid});
  } catch(e) {
    if(req.file?.path) try{fs.unlinkSync(req.file.path)}catch{}
    res.status(500).json({error:"Upload failed"});
  }
});

app.post("/api/documents/:id/version", auth, upload.single("file"), async (req,res) => {
  try {
    const id=Number(req.params.id);
    const doc=db.prepare("SELECT * FROM documents WHERE id=?").get(id);
    if(!doc) return res.status(404).json({error:"Document not found"});
    if(!hasFolderAccess(req.user,doc.folder_id,true)) return res.status(403).json({error:"No write permission"});
    if(!req.file) return res.status(400).json({error:"File required"});
    const version=doc.current_version+1;
    db.prepare("INSERT INTO document_versions(document_id,version,stored_name,size,mime_type,uploaded_by) VALUES(?,?,?,?,?,?)")
      .run(id,version,path.basename(req.file.filename),req.file.size,req.file.mimetype,req.user.id);
    db.prepare("UPDATE documents SET current_version=?,size=?,mime_type=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(version,req.file.size,req.file.mimetype,id);
    logAction(req.user.id,"NEW_VERSION","document",id,{version});
    res.json({ok:true,version});
  } catch(e) {
    if(req.file?.path) try{fs.unlinkSync(req.file.path)}catch{}
    res.status(500).json({error:"Version upload failed"});
  }
});

app.get("/api/documents/:id/versions", auth, (req,res) => {
  const id=Number(req.params.id);
  const doc=db.prepare("SELECT * FROM documents WHERE id=?").get(id);
  if(!doc) return res.status(404).json({error:"Document not found"});
  if(!hasFolderAccess(req.user,doc.folder_id)) return res.status(403).json({error:"No access"});
  const versions=db.prepare(`
    SELECT v.*,u.name AS uploader FROM document_versions v JOIN users u ON u.id=v.uploaded_by
    WHERE v.document_id=? ORDER BY v.version DESC`).all(id);
  res.json({versions});
});

app.get("/api/documents/:id/download", auth, (req,res) => {
  const id=Number(req.params.id), version=Number(req.query.version||0);
  const doc=db.prepare("SELECT * FROM documents WHERE id=?").get(id);
  if(!doc) return res.status(404).json({error:"Document not found"});
  if(!hasFolderAccess(req.user,doc.folder_id)) return res.status(403).json({error:"No access"});
  const v=version ? db.prepare("SELECT * FROM document_versions WHERE document_id=? AND version=?").get(id,version)
                  : db.prepare("SELECT * FROM document_versions WHERE document_id=? AND version=?").get(id,doc.current_version);
  if(!v) return res.status(404).json({error:"Version not found"});
  const full=path.join(STORAGE_DIR,v.stored_name);
  if(!fs.existsSync(full)) return res.status(404).json({error:"Stored file missing"});
  logAction(req.user.id,"DOWNLOAD","document",id,{version:v.version});
  res.download(full,doc.original_name);
});

app.delete("/api/documents/:id", auth, (req,res) => {
  const id=Number(req.params.id);
  const doc=db.prepare("SELECT * FROM documents WHERE id=?").get(id);
  if(!doc) return res.status(404).json({error:"Document not found"});
  if(req.user.role!=="admin" && !hasFolderAccess(req.user,doc.folder_id,true)) return res.status(403).json({error:"No permission"});
  const versions=db.prepare("SELECT stored_name FROM document_versions WHERE document_id=?").all(id);
  versions.forEach(v=>{try{fs.unlinkSync(path.join(STORAGE_DIR,v.stored_name));}catch{}});
  db.prepare("DELETE FROM documents WHERE id=?").run(id);
  logAction(req.user.id,"DELETE","document",id,{name:doc.original_name});
  res.json({ok:true});
});

app.get("/api/users", auth, adminOnly, (req,res)=>{
  res.json({users:db.prepare("SELECT id,email,name,role,active,created_at FROM users ORDER BY name").all()});
});
app.post("/api/users", auth, adminOnly, (req,res)=>{
  const {email,name,password,role="employee"}=req.body||{};
  if(!email||!name||!password) return res.status(400).json({error:"Name, email and password required"});
  if(!["admin","employee"].includes(role)) return res.status(400).json({error:"Invalid role"});
  if(String(password).length<8) return res.status(400).json({error:"Password must be at least 8 characters"});
  try {
    const info=db.prepare("INSERT INTO users(email,name,password_hash,role) VALUES(?,?,?,?)")
      .run(String(email).trim().toLowerCase(),String(name).trim(),bcrypt.hashSync(password,12),role);
    logAction(req.user.id,"CREATE","user",info.lastInsertRowid,{email,role});
    res.json({id:info.lastInsertRowid});
  } catch(e) { res.status(409).json({error:"Email already exists"}); }
});
app.patch("/api/users/:id", auth, adminOnly, (req,res)=>{
  const id=Number(req.params.id);
  const target=db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if(!target) return res.status(404).json({error:"User not found"});
  const {name,role,active,password}=req.body||{};
  if(id===req.user.id && active===0) return res.status(400).json({error:"You cannot disable your own account"});
  if(role && !["admin","employee"].includes(role)) return res.status(400).json({error:"Invalid role"});
  const hash=password ? bcrypt.hashSync(String(password),12) : target.password_hash;
  db.prepare("UPDATE users SET name=?,role=?,active=?,password_hash=? WHERE id=?")
    .run(name ?? target.name, role ?? target.role, active ?? target.active, hash,id);
  logAction(req.user.id,"UPDATE","user",id,{name,role,active});
  res.json({ok:true});
});

app.get("/api/permissions/:folderId", auth, adminOnly, (req,res)=>{
  const folderId=Number(req.params.folderId);
  const users=db.prepare(`
    SELECT u.id,u.name,u.email,COALESCE(p.can_read,0) can_read,COALESCE(p.can_write,0) can_write
    FROM users u LEFT JOIN folder_permissions p ON p.user_id=u.id AND p.folder_id=?
    WHERE u.active=1 ORDER BY u.name`).all(folderId);
  res.json({users});
});
app.put("/api/permissions/:folderId/:userId", auth, adminOnly, (req,res)=>{
  const folderId=Number(req.params.folderId), userId=Number(req.params.userId);
  const {can_read=false,can_write=false}=req.body||{};
  db.prepare(`
    INSERT INTO folder_permissions(folder_id,user_id,can_read,can_write) VALUES(?,?,?,?)
    ON CONFLICT(folder_id,user_id) DO UPDATE SET can_read=excluded.can_read,can_write=excluded.can_write
  `).run(folderId,userId,can_read?1:0,can_write?1:0);
  logAction(req.user.id,"PERMISSION_UPDATE","folder",folderId,{userId,can_read,can_write});
  res.json({ok:true});
});

app.get("/api/dashboard", auth, adminOnly, (req,res)=>{
  const users=db.prepare("SELECT COUNT(*) c FROM users WHERE active=1").get().c;
  const folders=db.prepare("SELECT COUNT(*) c FROM folders").get().c;
  const documents=db.prepare("SELECT COUNT(*) c FROM documents").get().c;
  const bytes=db.prepare("SELECT COALESCE(SUM(size),0) s FROM documents").get().s;
  const logs=db.prepare(`
    SELECT a.*,COALESCE(u.name,'System') user_name FROM audit_logs a
    LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 20`).all();
  res.json({users,folders,documents,bytes,logs});
});
app.get("/api/audit", auth, adminOnly, (req,res)=>{
  res.json({logs:db.prepare(`
    SELECT a.*,COALESCE(u.name,'System') user_name,COALESCE(u.email,'') email
    FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
    ORDER BY a.created_at DESC LIMIT 200`).all()});
});

app.use(express.static(path.join(__dirname,"public")));
app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError || err?.message?.includes("Invalid filename")) return res.status(400).json({error:err.message});
  console.error(err);
  res.status(500).json({error:"Internal server error"});
});

app.listen(PORT,()=>console.log(`Document Management System running at http://localhost:${PORT}`));
