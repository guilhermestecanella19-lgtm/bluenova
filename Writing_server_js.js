const express = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const multer   = require('multer');
const fs       = require('fs');
const path     = require('path');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'bluenova-secret-2024';
const DB_FILE = path.join(__dirname, 'db.json');

/* ─────────────────────────────── SETUP ─────────────────────────────── */
app.use(express.json({ limit: '150mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// File uploads
const storage = multer.diskStorage({
  destination(req, file, cb) {
    const dir = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename(req, file, cb) {
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, Date.now() + '-' + safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

/* ─────────────────────────────── DATABASE ─────────────────────────────── */
function getDB() {
  if (!fs.existsSync(DB_FILE)) return createDB();
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return createDB(); }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function gid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function createDB() {
  const now = new Date().toISOString();
  const db = {
    users: [
      {
        id: 'admin1',
        name: 'Administrador BlueNova',
        email: 'comercial@vertexdigital.art',
        password: bcrypt.hashSync('Guigui11', 10),
        role: 'admin',
        bio: 'Administrador da plataforma',
        active: true,
        createdAt: now
      },
      {
        id: 'teacher1',
        name: 'Guilherme Stecanella',
        email: 'guilhermestecanella19@gmail.com',
        password: bcrypt.hashSync('Guigui11', 10),
        role: 'teacher',
        bio: 'Especialista em tecnologia e educação online',
        studentLimit: 100,
        active: true,
        createdAt: now
      }
    ],
    courses: [],
    modules: [],
    lessons: [],
    enrollments: [],
    progress: []
  };
  saveDB(db);
  console.log('✅ Banco de dados criado.');
  return db;
}

/* ─────────────────────────────── MIDDLEWARES ─────────────────────────────── */
function auth(req, res, next) {
  const t = req.headers.authorization?.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'Token necessário' });
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido ou expirado' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Apenas administradores' });
  next();
}

function staffOnly(req, res, next) {
  if (!['admin', 'teacher'].includes(req.user.role)) return res.status(403).json({ error: 'Acesso negado' });
  next();
}

/* ─────────────────────────────── AUTH ─────────────────────────────── */
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-mail e senha obrigatórios' });
  const db = getDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.active !== false);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'E-mail ou senha incorretos' });
  const token = jwt.sign(
    { id: user.id, role: user.role, name: user.name, email: user.email },
    SECRET, { expiresIn: '30d' }
  );
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role, bio: user.bio, studentLimit: user.studentLimit }
  });
});

app.get('/api/auth/me', auth, (req, res) => {
  const db = getDB();
  const u = db.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Usuário não encontrado' });
  res.json({ id: u.id, name: u.name, email: u.email, role: u.role, bio: u.bio, studentLimit: u.studentLimit });
});

/* ─────────────────────────────── USERS ─────────────────────────────── */
app.get('/api/users', auth, (req, res) => {
  const db = getDB();
  let users = db.users;
  if (req.user.role === 'teacher')
    users = users.filter(u => u.role === 'student' && u.teacherId === req.user.id);
  else if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Acesso negado' });
  res.json(users.map(u => ({ ...u, password: undefined })));
});

app.post('/api/users', auth, (req, res) => {
  const { name, email, password, role, bio, studentLimit, teacherId } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Nome, e-mail e senha obrigatórios' });
  const db = getDB();

  if (req.user.role === 'teacher') {
    if (role && role !== 'student')
      return res.status(403).json({ error: 'Professores só podem criar alunos' });
    const me = db.users.find(u => u.id === req.user.id);
    const myStudents = db.users.filter(u => u.teacherId === req.user.id && u.active !== false);
    if (me?.studentLimit != null && myStudents.length >= me.studentLimit)
      return res.status(403).json({ error: `Limite de ${me.studentLimit} alunos atingido. Solicite mais vagas ao administrador.` });
  } else if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  if (db.users.some(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'E-mail já cadastrado' });

  const nu = {
    id: gid(),
    name,
    email,
    password: bcrypt.hashSync(password, 10),
    role: role || 'student',
    teacherId: req.user.role === 'teacher' ? req.user.id : (teacherId || null),
    bio: bio || '',
    studentLimit: role === 'teacher' ? (studentLimit ?? 20) : null,
    active: true,
    createdAt: new Date().toISOString()
  };
  db.users.push(nu);
  saveDB(db);
  res.status(201).json({ ...nu, password: undefined });
});

app.put('/api/users/:id', auth, (req, res) => {
  const db = getDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Usuário não encontrado' });
  const target = db.users[idx];

  if (req.user.role === 'student' && target.id !== req.user.id)
    return res.status(403).json({ error: 'Acesso negado' });
  if (req.user.role === 'teacher' && target.teacherId !== req.user.id && target.id !== req.user.id)
    return res.status(403).json({ error: 'Acesso negado' });

  const { password, ...rest } = req.body;
  // non-admins cannot change role
  if (req.user.role !== 'admin') delete rest.role;

  db.users[idx] = {
    ...target,
    ...rest,
    ...(password ? { password: bcrypt.hashSync(password, 10) } : {}),
    updatedAt: new Date().toISOString()
  };
  saveDB(db);
  res.json({ ...db.users[idx], password: undefined });
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (req.params.id === 'admin1') return res.status(400).json({ error: 'Não é possível excluir o admin principal' });
  const db = getDB();
  db.users = db.users.filter(u => u.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

/* ─────────────────────────────── FILE UPLOAD ─────────────────────────────── */
app.post('/api/upload', auth, staffOnly, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname, size: req.file.size });
});

/* ─────────────────────────────── COURSES ─────────────────────────────── */
app.get('/api/courses', (req, res) => {
  const db = getDB();
  let token = req.headers.authorization?.split(' ')[1];
  let user = null;
  if (token) try { user = jwt.verify(token, SECRET); } catch {}

  let courses = db.courses;
  if (user?.role === 'teacher')      courses = courses.filter(c => c.tid === user.id);
  else if (!user || user?.role === 'student') courses = courses.filter(c => c.status === 'published');

  const users = db.users;
  res.json(courses.map(c => ({
    ...c,
    teacherName: users.find(u => u.id === c.tid)?.name || '',
    moduleCount: db.modules.filter(m => m.cid === c.id).length,
    lessonCount: db.lessons.filter(l => l.cid === c.id).length
  })));
});

app.post('/api/courses', auth, staffOnly, (req, res) => {
  const db = getDB();
  const nc = { id: gid(), tid: req.user.id, students: 0, rating: 0, rcount: 0, status: 'draft', ...req.body, createdAt: new Date().toISOString() };
  db.courses.push(nc);
  saveDB(db);
  res.status(201).json(nc);
});

app.put('/api/courses/:id', auth, staffOnly, (req, res) => {
  const db = getDB();
  const idx = db.courses.findIndex(c => c.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Curso não encontrado' });
  if (req.user.role === 'teacher' && db.courses[idx].tid !== req.user.id)
    return res.status(403).json({ error: 'Acesso negado' });
  db.courses[idx] = { ...db.courses[idx], ...req.body, updatedAt: new Date().toISOString() };
  saveDB(db);
  res.json(db.courses[idx]);
});

app.delete('/api/courses/:id', auth, staffOnly, (req, res) => {
  const db = getDB();
  const course = db.courses.find(c => c.id === req.params.id);
  if (!course) return res.status(404).json({ error: 'Curso não encontrado' });
  if (req.user.role === 'teacher' && course.tid !== req.user.id) return res.status(403).json({ error: 'Acesso negado' });
  db.courses     = db.courses.filter(c => c.id !== req.params.id);
  db.modules     = db.modules.filter(m => m.cid !== req.params.id);
  db.lessons     = db.lessons.filter(l => l.cid !== req.params.id);
  db.enrollments = db.enrollments.filter(e => e.cid !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

/* ─────────────────────────────── MODULES ─────────────────────────────── */
app.get('/api/courses/:cid/modules', (req, res) => {
  const db = getDB();
  res.json(db.modules.filter(m => m.cid === req.params.cid).sort((a, b) => a.order - b.order));
});

app.post('/api/courses/:cid/modules', auth, staffOnly, (req, res) => {
  const db = getDB();
  const order = db.modules.filter(m => m.cid === req.params.cid).length + 1;
  const nm = { id: gid(), cid: req.params.cid, order, ...req.body, createdAt: new Date().toISOString() };
  db.modules.push(nm);
  saveDB(db);
  res.status(201).json(nm);
});

app.put('/api/modules/:id', auth, staffOnly, (req, res) => {
  const db = getDB();
  const idx = db.modules.findIndex(m => m.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Módulo não encontrado' });
  db.modules[idx] = { ...db.modules[idx], ...req.body, updatedAt: new Date().toISOString() };
  saveDB(db);
  res.json(db.modules[idx]);
});

app.delete('/api/modules/:id', auth, staffOnly, (req, res) => {
  const db = getDB();
  db.modules = db.modules.filter(m => m.id !== req.params.id);
  db.lessons = db.lessons.filter(l => l.mid !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

/* ─────────────────────────────── LESSONS ─────────────────────────────── */
app.get('/api/modules/:mid/lessons', (req, res) => {
  const db = getDB();
  res.json(db.lessons.filter(l => l.mid === req.params.mid).sort((a, b) => a.order - b.order));
});

app.post('/api/modules/:mid/lessons', auth, staffOnly, (req, res) => {
  const db = getDB();
  const mod = db.modules.find(m => m.id === req.params.mid);
  if (!mod) return res.status(404).json({ error: 'Módulo não encontrado' });
  const order = db.lessons.filter(l => l.mid === req.params.mid).length + 1;
  const nl = { id: gid(), mid: req.params.mid, cid: mod.cid, order, ...req.body, createdAt: new Date().toISOString() };
  db.lessons.push(nl);
  saveDB(db);
  res.status(201).json(nl);
});

app.put('/api/lessons/:id', auth, staffOnly, (req, res) => {
  const db = getDB();
  const idx = db.lessons.findIndex(l => l.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Aula não encontrada' });
  db.lessons[idx] = { ...db.lessons[idx], ...req.body, updatedAt: new Date().toISOString() };
  saveDB(db);
  res.json(db.lessons[idx]);
});

app.delete('/api/lessons/:id', auth, staffOnly, (req, res) => {
  const db = getDB();
  db.lessons = db.lessons.filter(l => l.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

/* ─────────────────────────────── ENROLLMENTS ─────────────────────────────── */
app.get('/api/enrollments', auth, (req, res) => {
  const db = getDB();
  let enr = db.enrollments;
  if (req.user.role === 'student')
    enr = enr.filter(e => e.uid === req.user.id);
  else if (req.user.role === 'teacher')
    enr = enr.filter(e => db.courses.some(c => c.id === e.cid && c.tid === req.user.id));
  // admin gets all
  const users   = db.users;
  const courses = db.courses;
  res.json(enr.map(e => ({
    ...e,
    studentName:  users.find(u => u.id === e.uid)?.name   || '',
    studentEmail: users.find(u => u.id === e.uid)?.email  || '',
    courseTitle:  courses.find(c => c.id === e.cid)?.title || ''
  })));
});

app.post('/api/enrollments', auth, (req, res) => {
  const { cid } = req.body;
  const db = getDB();
  let enr = db.enrollments.find(e => e.uid === req.user.id && e.cid === cid);
  if (!enr) {
    enr = { id: gid(), uid: req.user.id, cid, enrolledAt: new Date().toISOString(), progress: 0 };
    db.enrollments.push(enr);
    const ci = db.courses.findIndex(c => c.id === cid);
    if (ci >= 0) db.courses[ci].students = (db.courses[ci].students || 0) + 1;
    saveDB(db);
  }
  res.json(enr);
});

/* ─────────────────────────────── PROGRESS ─────────────────────────────── */
app.get('/api/progress/:cid', auth, (req, res) => {
  const db = getDB();
  res.json(db.progress.filter(p => p.uid === req.user.id && p.cid === req.params.cid));
});

app.post('/api/progress', auth, (req, res) => {
  const { lid, cid } = req.body;
  const db = getDB();
  const idx = db.progress.findIndex(p => p.uid === req.user.id && p.lid === lid);
  if (idx >= 0) { db.progress[idx].done = true; db.progress[idx].doneAt = new Date().toISOString(); }
  else db.progress.push({ id: gid(), uid: req.user.id, lid, cid, done: true, doneAt: new Date().toISOString() });
  const allLes = db.lessons.filter(l => l.cid === cid);
  const done   = db.progress.filter(p => p.uid === req.user.id && p.cid === cid && p.done).length;
  const ei     = db.enrollments.findIndex(e => e.uid === req.user.id && e.cid === cid);
  if (ei >= 0) db.enrollments[ei].progress = allLes.length ? Math.round(done / allLes.length * 100) : 0;
  saveDB(db);
  res.json({ ok: true });
});

/* ─────────────────────────────── SPA FALLBACK ─────────────────────────────── */
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

/* ─────────────────────────────── START ─────────────────────────────── */
app.listen(PORT, () => {
  console.log(`\n🚀 BlueNova rodando em http://localhost:${PORT}`);
  console.log('─────────────────────────────────────────');
  console.log(`🔑 Admin    : comercial@vertexdigital.art  / Guigui11`);
  console.log(`👨‍🏫 Professor: guilhermestecanella19@gmail.com / Guigui11`);
  console.log('─────────────────────────────────────────\n');
});
