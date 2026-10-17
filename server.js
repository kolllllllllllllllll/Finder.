'use strict';
require('dotenv').config?.();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.SESSION_SECRET || '';
if (SECRET.length < 32 || /replace-with/i.test(SECRET)) {
  console.error('SECURITY ERROR: Set SESSION_SECRET in .env to a random secret of at least 32 characters.');
  process.exit(1);
}
const ROOT = __dirname;
const AVATAR_DIR = path.join(ROOT, 'uploads', 'avatars');
const REPORT_DIR = path.join(ROOT, 'uploads', 'reports');
for (const d of [AVATAR_DIR, REPORT_DIR, path.join(ROOT, 'data')]) fs.mkdirSync(d, {recursive:true});
const db = new Database(path.join(ROOT, 'data', 'finder.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, age_band TEXT NOT NULL DEFAULT '13-15', bio TEXT NOT NULL DEFAULT '',
 interests TEXT NOT NULL DEFAULT '', avatar TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS likes (
 from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(from_user,to_user), CHECK(from_user <> to_user)
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(from_user <> to_user)
);
CREATE TABLE IF NOT EXISTS blocks (
 blocker INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 blocked INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(blocker,blocked), CHECK(blocker <> blocked)
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, reporter INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 target_user INTEGER REFERENCES users(id) ON DELETE SET NULL, category TEXT NOT NULL,
 details TEXT NOT NULL, evidence_file TEXT, status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],scriptSrc:["'self'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],baseUri:["'self'"],frameAncestors:["'none'"]}}}));
app.use(express.json({limit:'80kb'}));
app.use(express.urlencoded({extended:false,limit:'80kb'}));
app.use('/api/', rateLimit({windowMs:15*60*1000, limit:250, standardHeaders:true, legacyHeaders:false}));
app.use(express.static(path.join(ROOT,'public')));

function hashToken(t){return crypto.createHmac('sha256',SECRET).update(t).digest('hex');}
function auth(req,res,next){
 const raw = (req.headers.authorization||'').startsWith('Bearer ') ? req.headers.authorization.slice(7) : (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('finder_session='))?.slice('finder_session='.length);
 if(!raw) return res.status(401).json({error:'Сначала войди в аккаунт.'});
 const row=db.prepare('SELECT u.id,u.username,u.age_band,u.bio,u.interests,u.avatar FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.disabled=0').get(hashToken(raw),Date.now());
 if(!row) return res.status(401).json({error:'Сессия закончилась. Войди ещё раз.'});
 req.user=row; req.sessionRaw=raw; next();
}
const avatarUpload=multer({storage:multer.memoryStorage(),limits:{fileSize:3*1024*1024,files:1},fileFilter:(req,file,cb)=>{
 const allowed={'image/jpeg':'jpg','image/png':'png','image/webp':'webp'};
 if(!allowed[file.mimetype]) return cb(new Error('Аватар должен быть JPG, PNG или WebP.'));
 cb(null,true);
}});
const evidenceUpload=multer({storage:multer.diskStorage({destination:(req,file,cb)=>cb(null,REPORT_DIR),filename:(req,file,cb)=>cb(null,crypto.randomUUID()+'.pdf')}),limits:{fileSize:5*1024*1024,files:1},fileFilter:(req,file,cb)=>{
 if(file.mimetype!=='application/pdf' || path.extname(file.originalname).toLowerCase()!=='.pdf') return cb(new Error('Для доказательства разрешён только PDF.'));
 cb(null,true);
}});
function noBlocked(a,b){return !db.prepare('SELECT 1 FROM blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)').get(a,b,b,a);}
function publicUser(u,meId){return {id:u.id,username:u.username,age_band:u.age_band,bio:u.bio,interests:u.interests,avatar:u.avatar?'/uploads/avatars/'+encodeURIComponent(u.avatar):null,likes_count:db.prepare('SELECT COUNT(*) n FROM likes WHERE to_user=?').get(u.id).n,liked_by_me:meId?!!db.prepare('SELECT 1 FROM likes WHERE from_user=? AND to_user=?').get(meId,u.id):false};}
// Avatars are public profile media only; report evidence is never served as static files.
app.get('/uploads/avatars/:file',(req,res)=>{const file=path.basename(req.params.file); if(!/^[a-f0-9-]+\.(jpg|png|webp)$/i.test(file)) return res.sendStatus(404); res.sendFile(path.join(AVATAR_DIR,file));});

app.post('/api/register',rateLimit({windowMs:60*60*1000,limit:10,standardHeaders:true,legacyHeaders:false}),async(req,res)=>{
 const username=String(req.body.username||'').trim(); const password=String(req.body.password||''); const age=String(req.body.age_band||'');
 if(!/^[\p{L}\p{N}_-]{3,20}$/u.test(username)) return res.status(400).json({error:'Ник: 3–20 букв, цифр, _ или -.'});
 if(password.length<10||password.length>100) return res.status(400).json({error:'Пароль должен быть длиной от 10 до 100 символов.'});
 if(!['10-12','13-15','16-17','18+'].includes(age)) return res.status(400).json({error:'Выбери возрастную группу.'});
 if(age==='18+') return res.status(403).json({error:'Эта версия Finder предназначена для подросткового сообщества. Взрослые аккаунты не принимаются.'});
 try {const hash=await bcrypt.hash(password,12); const info=db.prepare('INSERT INTO users(username,password_hash,age_band) VALUES(?,?,?)').run(username,hash,age); const token=crypto.randomBytes(48).toString('hex'); db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),info.lastInsertRowid,Date.now()+7*24*60*60*1000); res.json({token,user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid),info.lastInsertRowid)});} catch(e){if(String(e.code)==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'Этот ник уже занят.'}); console.error(e);res.status(500).json({error:'Не удалось создать аккаунт.'});}
});
app.post('/api/login',rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:true,legacyHeaders:false}),async(req,res)=>{
 const username=String(req.body.username||'').trim(); const password=String(req.body.password||''); const u=db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').get(username);
 if(!u||u.disabled||!await bcrypt.compare(password,u.password_hash)) return res.status(401).json({error:'Неверный ник или пароль.'});
 const token=crypto.randomBytes(48).toString('hex'); db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),u.id,Date.now()+7*24*60*60*1000); res.json({token,user:publicUser(u,u.id)});
});
app.post('/api/logout',auth,(req,res)=>{db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(req.sessionRaw));res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:publicUser(req.user,req.user.id)}));
app.get('/api/profiles',auth,(req,res)=>{const users=db.prepare('SELECT u.* FROM users u WHERE u.id<>? AND u.disabled=0 AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker=? AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=?)) ORDER BY u.created_at DESC LIMIT 100').all(req.user.id,req.user.id,req.user.id);res.json({profiles:users.map(u=>publicUser(u,req.user.id))});});
app.get('/api/profiles/:id',auth,(req,res)=>{const id=Number(req.params.id);const u=db.prepare('SELECT * FROM users WHERE id=? AND disabled=0').get(id);if(!u||id===req.user.id||!noBlocked(req.user.id,id))return res.sendStatus(404);res.json({profile:publicUser(u,req.user.id)});});
app.patch('/api/profile',auth,(req,res)=>{const bio=String(req.body.bio||'').trim().slice(0,400);const interests=String(req.body.interests||'').trim().slice(0,200);const age=String(req.body.age_band||req.user.age_band);if(!['10-12','13-15','16-17'].includes(age))return res.status(400).json({error:'Неверная возрастная группа.'});db.prepare('UPDATE users SET bio=?,interests=?,age_band=? WHERE id=?').run(bio,interests,age,req.user.id);res.json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id),req.user.id)});});
// Dedicated upload handler kept separate so only validated image bytes are written.
app.post('/api/avatar-upload',auth,(req,res)=>avatarUpload.single('avatar')(req,res,err=>{
 if(err)return res.status(400).json({error:err.message}); if(!req.file)return res.status(400).json({error:'Выбери изображение.'});
 const b=req.file.buffer; const isJpeg=b.length>3&&b[0]===0xff&&b[1]===0xd8&&b[2]===0xff; const isPng=b.length>8&&b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])); const isWebp=b.length>12&&b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WEBP';
 if(!isJpeg&&!isPng&&!isWebp)return res.status(400).json({error:'Файл не похож на корректное изображение.'});
 const ext=isJpeg?'jpg':isPng?'png':'webp';const name=crypto.randomUUID()+'.'+ext;fs.writeFileSync(path.join(AVATAR_DIR,name),b,{flag:'wx',mode:0o600});const old=db.prepare('SELECT avatar FROM users WHERE id=?').get(req.user.id).avatar;db.prepare('UPDATE users SET avatar=? WHERE id=?').run(name,req.user.id);if(old)try{fs.unlinkSync(path.join(AVATAR_DIR,path.basename(old)));}catch{}res.json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id),req.user.id)});
}));
app.post('/api/likes/:id',auth,(req,res)=>{const target=Number(req.params.id);if(!Number.isInteger(target)||target===req.user.id)return res.status(400).json({error:'Нельзя лайкнуть этот профиль.'});const u=db.prepare('SELECT id FROM users WHERE id=? AND disabled=0').get(target);if(!u||!noBlocked(req.user.id,target))return res.sendStatus(404);const exists=db.prepare('SELECT 1 FROM likes WHERE from_user=? AND to_user=?').get(req.user.id,target);if(exists)db.prepare('DELETE FROM likes WHERE from_user=? AND to_user=?').run(req.user.id,target);else db.prepare('INSERT INTO likes(from_user,to_user) VALUES(?,?)').run(req.user.id,target);res.json({liked:!exists,likes_count:db.prepare('SELECT COUNT(*) n FROM likes WHERE to_user=?').get(target).n});});
app.get('/api/messages/:id',auth,(req,res)=>{const other=Number(req.params.id);if(!Number.isInteger(other)||!noBlocked(req.user.id,other))return res.status(404).json({error:'Переписка недоступна.'});const msgs=db.prepare('SELECT id,from_user,to_user,body,created_at FROM messages WHERE ((from_user=? AND to_user=?) OR (from_user=? AND to_user=?)) ORDER BY id DESC LIMIT 100').all(req.user.id,other,other,req.user.id).reverse();res.json({messages:msgs});});
app.post('/api/messages/:id',auth,(req,res)=>{const to=Number(req.params.id),body=String(req.body.body||'').trim();if(!Number.isInteger(to)||to===req.user.id||body.length<1||body.length>1000)return res.status(400).json({error:'Сообщение должно содержать 1–1000 символов.'});const u=db.prepare('SELECT id FROM users WHERE id=? AND disabled=0').get(to);if(!u||!noBlocked(req.user.id,to))return res.status(403).json({error:'Нельзя отправить сообщение этому пользователю.'});const recent=db.prepare("SELECT COUNT(*) n FROM messages WHERE from_user=? AND created_at>datetime('now','-1 minute')").get(req.user.id).n;if(recent>=12)return res.status(429).json({error:'Слишком много сообщений. Подожди минуту.'});const info=db.prepare('INSERT INTO messages(from_user,to_user,body) VALUES(?,?,?)').run(req.user.id,to,body);res.json({message:db.prepare('SELECT id,from_user,to_user,body,created_at FROM messages WHERE id=?').get(info.lastInsertRowid)});});
app.post('/api/block/:id',auth,(req,res)=>{const id=Number(req.params.id);if(!Number.isInteger(id)||id===req.user.id)return res.status(400).json({error:'Нельзя заблокировать этот профиль.'});db.prepare('INSERT OR IGNORE INTO blocks(blocker,blocked) VALUES(?,?)').run(req.user.id,id);db.prepare('DELETE FROM likes WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)').run(req.user.id,id,id,req.user.id);res.json({ok:true});});
app.post('/api/reports',auth,(req,res)=>evidenceUpload.single('evidence')(req,res,err=>{
 if(err)return res.status(400).json({error:err.message});const target=req.body.target_user?Number(req.body.target_user):null;const category=String(req.body.category||'').slice(0,60);const details=String(req.body.details||'').trim().slice(0,1500);
 if(req.file){const head=Buffer.alloc(5);const fd=fs.openSync(req.file.path,'r');fs.readSync(fd,head,0,5,0);fs.closeSync(fd);if(head.toString('ascii')!=='%PDF-'){try{fs.unlinkSync(req.file.path)}catch{}return res.status(400).json({error:'Файл не похож на PDF.'});}}
 if(!['Подозрительное поведение','Домогательства','Угрозы','Спам или фейк','Другое'].includes(category)||details.length<8){if(req.file)try{fs.unlinkSync(req.file.path)}catch{}return res.status(400).json({error:'Выбери причину и добавь описание минимум из 8 символов.'});}
 if(target&&!db.prepare('SELECT id FROM users WHERE id=?').get(target)){if(req.file)try{fs.unlinkSync(req.file.path)}catch{}return res.status(400).json({error:'Профиль не найден.'});}
 const info=db.prepare('INSERT INTO reports(reporter,target_user,category,details,evidence_file) VALUES(?,?,?,?,?)').run(req.user.id,target,category,details,req.file?path.basename(req.file.path):null);res.json({ok:true,report_id:info.lastInsertRowid,message:'Жалоба отправлена модератору. Не публикуй обвинения и личные данные в профилях.'});
}));
// Moderation endpoints are private and require a separate secret. Never publish a suspect list.
function admin(req,res,next){const provided=String(req.headers['x-admin-token']||'');const expected=String(process.env.ADMIN_TOKEN||'');if(expected.length<32||/replace-with/i.test(expected)||!crypto.timingSafeEqual(Buffer.from(crypto.createHash('sha256').update(provided).digest('hex')),Buffer.from(crypto.createHash('sha256').update(expected).digest('hex'))))return res.status(403).json({error:'Доступ только для модератора.'});next();}
app.get('/api/mod/reports',admin,(req,res)=>{const rows=db.prepare('SELECT r.id,r.category,r.details,r.status,r.created_at,u.username AS reporter,t.username AS target_username, r.evidence_file FROM reports r JOIN users u ON u.id=r.reporter LEFT JOIN users t ON t.id=r.target_user WHERE r.status="pending" ORDER BY r.id ASC LIMIT 100').all();res.json({reports:rows.map(r=>({...r,evidence_file:r.evidence_file?'/api/mod/reports/'+r.id+'/evidence':null}))});});
app.get('/api/mod/reports/:id/evidence',admin,(req,res)=>{const r=db.prepare('SELECT evidence_file FROM reports WHERE id=?').get(Number(req.params.id));if(!r||!r.evidence_file)return res.sendStatus(404);res.type('application/pdf').sendFile(path.join(REPORT_DIR,path.basename(r.evidence_file)));});
app.patch('/api/mod/reports/:id',admin,(req,res)=>{const status=String(req.body.status||'');if(!['reviewed','dismissed','actioned'].includes(status))return res.status(400).json({error:'Неверный статус.'});const r=db.prepare('SELECT id,target_user FROM reports WHERE id=?').get(Number(req.params.id));if(!r)return res.sendStatus(404);db.prepare('UPDATE reports SET status=? WHERE id=?').run(status,r.id);if(status==='actioned'&&r.target_user)db.prepare('UPDATE users SET disabled=1 WHERE id=?').run(r.target_user);res.json({ok:true});});
app.delete('/api/profile',auth,(req,res)=>{db.prepare('DELETE FROM users WHERE id=?').run(req.user.id);res.json({ok:true});});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Внутренняя ошибка сервера.'});});
app.listen(PORT,()=>console.log(`Finder запущен: http://localhost:${PORT}`));
