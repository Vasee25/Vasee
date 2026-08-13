const { Client } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;

async function getDB() {
  const c = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await c.connect();
  return c;
}

async function init(c) {
  await c.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','employee')),
      active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS folders (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, parent_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
      created_by INTEGER NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS documents (
      id SERIAL PRIMARY KEY, folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL, current_version INTEGER DEFAULT 1, size BIGINT DEFAULT 0,
      mime_type TEXT, created_by INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS document_versions (
      id SERIAL PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      version INTEGER NOT NULL, storage_key TEXT NOT NULL, size BIGINT DEFAULT 0,
      mime_type TEXT, uploaded_by INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(document_id,version)
    );
    CREATE TABLE IF NOT EXISTS folder_permissions (
      folder_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      can_read BOOLEAN DEFAULT TRUE, can_write BOOLEAN DEFAULT FALSE,
      PRIMARY KEY(folder_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id INTEGER,
      details JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  const a=await c.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if(!a.rows.length){
    const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD||"ChangeMe123!",12);
    const r=await c.query(
      "INSERT INTO users(email,name,password_hash,role) VALUES($1,$2,$3,'admin') RETURNING id",
      [process.env.ADMIN_EMAIL||"admin@example.com","System Administrator",hash]);
    await c.query("INSERT INTO folders(name,created_by) VALUES('Shared Documents',$1)",[r.rows[0].id]);
  }
}

function response(code,data){
  return {statusCode:code,headers:{
    "Content-Type":"application/json",
    "Access-Control-Allow-Origin":"*",
    "Access-Control-Allow-Headers":"Content-Type,Authorization",
    "Access-Control-Allow-Methods":"GET,POST,PATCH,PUT,DELETE,OPTIONS"
  },body:JSON.stringify(data)};
}
function body(e){try{return JSON.parse(e.body||"{}")}catch{return {}}}
function parts(e){
  const p=(e.path||"").replace(/^.*\/api\/?/,"").replace(/^\/|\/$/g,"");
  return p?p.split("/"):[];
}
function auth(e){
  const h=e.headers?.authorization||e.headers?.Authorization||"";
  if(!h.startsWith("Bearer ")||!SECRET) throw Object.assign(new Error("Authentication required"),{status:401});
  try{return jwt.verify(h.slice(7),SECRET)}catch{throw Object.assign(new Error("Invalid or expired session"),{status:401})}
}
function admin(u){if(u.role!=="admin")throw Object.assign(new Error("Administrator access required"),{status:403})}
async function access(c,u,fid,write=false){
  if(u.role==="admin")return true;
  let id=fid;
  while(id){
    const f=(await c.query("SELECT id,parent_id FROM folders WHERE id=$1",[id])).rows[0];
    if(!f)return false;
    const p=(await c.query("SELECT can_read,can_write FROM folder_permissions WHERE folder_id=$1 AND user_id=$2",[id,u.id])).rows[0];
    if(p&&(write?p.can_write:p.can_read))return true;
    id=f.parent_id;
  }
  return false;
}
async function audit(c,u,a,t,id,d={}){await c.query(
  "INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details) VALUES($1,$2,$3,$4,$5)",
  [u,a,t,id,d]);}

exports.handler=async(e)=>{
  if(e.httpMethod==="OPTIONS")return response(204,{});
  let c;
  try{
    c=await getDB(); await init(c);
    const p=parts(e),m=e.httpMethod;

    if(p[0]==="health")return response(200,{ok:true});

    if(p[0]==="login"&&m==="POST"){
      const b=body(e);
      const r=await c.query("SELECT * FROM users WHERE lower(email)=lower($1) AND active=TRUE",[String(b.email||"").trim()]);
      if(!r.rows.length||!(await bcrypt.compare(String(b.password||""),r.rows[0].password_hash)))
        return response(401,{error:"Invalid email or password"});
      const x=r.rows[0];
      const token=jwt.sign({id:x.id,email:x.email,name:x.name,role:x.role},SECRET,{expiresIn:"8h"});
      await audit(c,x.id,"LOGIN","user",x.id);
      return response(200,{user:{id:x.id,email:x.email,name:x.name,role:x.role},token});
    }

    const u=auth(e);

    if(p[0]==="me")return response(200,{user:u});

    if(p[0]==="folders"&&m==="GET"){
      const r=await c.query("SELECT f.*,u.name creator FROM folders f JOIN users u ON u.id=f.created_by ORDER BY f.name");
      const out=[];for(const f of r.rows)if(await access(c,u,f.id))out.push(f);
      return response(200,{folders:out});
    }

    if(p[0]==="folders"&&m==="POST"){
      const b=body(e);if(!b.name)return response(400,{error:"Folder name required"});
      if(b.parent_id&&!await access(c,u,Number(b.parent_id),true))return response(403,{error:"No write permission"});
      const r=await c.query("INSERT INTO folders(name,parent_id,created_by) VALUES($1,$2,$3) RETURNING id",
        [String(b.name).trim().slice(0,120),b.parent_id||null,u.id]);
      await audit(c,u.id,"CREATE","folder",r.rows[0].id,{name:b.name});
      return response(200,{id:r.rows[0].id});
    }

    if(p[0]==="documents"&&m==="GET"){
      const q=e.queryStringParameters||{},term=String(q.q||"").trim(),fid=q.folder_id?Number(q.folder_id):null;
      if(fid&&!await access(c,u,fid))return response(403,{error:"No access"});
      const sql=fid
        ?"SELECT d.*,u.name creator FROM documents d JOIN users u ON u.id=d.created_by WHERE d.folder_id=$1 AND d.original_name ILIKE $2 ORDER BY d.updated_at DESC"
        :"SELECT d.*,u.name creator FROM documents d JOIN users u ON u.id=d.created_by WHERE d.original_name ILIKE $1 ORDER BY d.updated_at DESC";
      const vals=fid?[fid,`%${term}%`]:[`%${term}%`];
      let rows=(await c.query(sql,vals)).rows;
      if(!fid){const ok=[];for(const d of rows)if(await access(c,u,d.folder_id))ok.push(d);rows=ok}
      return response(200,{documents:rows});
    }

    if(p[0]==="dashboard"&&m==="GET"){
      admin(u);
      const users=Number((await c.query("SELECT COUNT(*) n FROM users WHERE active")).rows[0].n);
      const folders=Number((await c.query("SELECT COUNT(*) n FROM folders")).rows[0].n);
      const documents=Number((await c.query("SELECT COUNT(*) n FROM documents")).rows[0].n);
      const bytes=Number((await c.query("SELECT COALESCE(SUM(size),0) n FROM documents")).rows[0].n);
      const logs=(await c.query("SELECT a.*,COALESCE(u.name,'System') user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 20")).rows;
      return response(200,{users,folders,documents,bytes,logs});
    }

    if(p[0]==="users"&&m==="GET"){
      admin(u);return response(200,{users:(await c.query("SELECT id,email,name,role,active,created_at FROM users ORDER BY name")).rows});
    }

    if(p[0]==="users"&&m==="POST"){
      admin(u);const b=body(e);
      if(!b.name||!b.email||!b.password||String(b.password).length<8)return response(400,{error:"Name, email and password (8+ characters) required"});
      try{
        const r=await c.query("INSERT INTO users(email,name,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id",
          [String(b.email).trim().toLowerCase(),String(b.name).trim(),await bcrypt.hash(b.password,12),b.role==="admin"?"admin":"employee"]);
        await audit(c,u.id,"CREATE","user",r.rows[0].id,{email:b.email});
        return response(200,{id:r.rows[0].id});
      }catch{return response(409,{error:"Email already exists"});}
    }

    if(p[0]==="users"&&p[1]&&m==="PATCH"){
      admin(u);const id=Number(p[1]),b=body(e);
      const old=(await c.query("SELECT * FROM users WHERE id=$1",[id])).rows[0];
      if(!old)return response(404,{error:"User not found"});
      const hash=b.password?await bcrypt.hash(b.password,12):old.password_hash;
      await c.query("UPDATE users SET name=$1,role=$2,active=$3,password_hash=$4 WHERE id=$5",
        [b.name??old.name,b.role??old.role,b.active??old.active,hash,id]);
      await audit(c,u.id,"UPDATE","user",id,{});
      return response(200,{ok:true});
    }

    if(p[0]==="audit"&&m==="GET"){
      admin(u);return response(200,{logs:(await c.query(
        "SELECT a.*,COALESCE(u.name,'System') user_name,COALESCE(u.email,'') email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 200")).rows});
    }

    return response(404,{error:"API route not found"});
  }catch(err){
    console.error(err);return response(err.status||500,{error:err.message||"Internal server error"});
  }finally{if(c)await c.end().catch(()=>{});}
};
