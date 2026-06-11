const express      = require('express');
const session      = require('express-session');
const pgSession    = require('connect-pg-simple')(session);
const { Pool }     = require('pg');
const crypto       = require('crypto');
const path         = require('path');

/* ── Conexión a Supabase (PostgreSQL) ── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ── Inicializar tablas si no existen ── */
async function initDB(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id   TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      salt TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS predictions (
      match_id TEXT NOT NULL,
      user_id  TEXT NOT NULL,
      value    TEXT NOT NULL,
      PRIMARY KEY (match_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS match_edits (
      match_id   TEXT PRIMARY KEY,
      a          TEXT,
      b          TEXT,
      date_val   TEXT,
      time_val   TEXT,
      group_name TEXT
    );
    CREATE TABLE IF NOT EXISTS session (
      sid    TEXT        NOT NULL COLLATE "default",
      sess   JSON        NOT NULL,
      expire TIMESTAMPTZ NOT NULL,
      CONSTRAINT session_pkey PRIMARY KEY (sid)
    );
    CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
  `);
  console.log('✅  Base de datos lista (Supabase)');
}

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1);

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'oficina-mundial-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

/* ── SSE: actualizaciones en tiempo real ── */
const clients = new Set();

app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write('data: connected\n\n');
  clients.add(res);
  // Heartbeat cada 25s para mantener la conexión viva
  const hb = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(hb); clients.delete(res); });
});

function broadcast(payload){
  const msg = `data: ${JSON.stringify(payload)}\n\n`;
  clients.forEach(c => c.write(msg));
}

/* ── Estado completo ── */
app.get('/api/state', async (req, res) => {
  try {
    const [usersR, predsR, editsR] = await Promise.all([
      pool.query('SELECT id, name FROM users ORDER BY ctid'),
      pool.query('SELECT match_id, user_id, value FROM predictions'),
      pool.query('SELECT match_id, a, b, date_val, time_val, group_name FROM match_edits'),
    ]);

    const predictions = {};
    predsR.rows.forEach(r => {
      if(!predictions[r.match_id]) predictions[r.match_id] = {};
      predictions[r.match_id][r.user_id] = r.value;
    });

    const edits = {};
    editsR.rows.forEach(r => {
      edits[r.match_id] = { a:r.a, b:r.b, date:r.date_val, time:r.time_val, group:r.group_name };
    });

    res.json({
      users:       usersR.rows,
      predictions,
      edits,
      session:     req.session.userId || null
    });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: 'Error del servidor.' });
  }
});

/* ── Registro ── */
app.post('/api/register', async (req, res) => {
  const { name, pin } = req.body || {};
  if(!name || !pin || pin.length < 4)
    return res.status(400).json({ error: 'Datos inválidos.' });

  try {
    const exists = await pool.query('SELECT id FROM users WHERE LOWER(name)=LOWER($1)', [name]);
    if(exists.rows.length)
      return res.status(409).json({ error: 'Ya existe una cuenta con ese nombre. Usa "Iniciar sesión".' });

    const id   = crypto.randomUUID();
    const salt = crypto.randomBytes(8).toString('hex');
    const hash = crypto.createHash('sha256').update(salt + ':' + pin).digest('hex');

    await pool.query('INSERT INTO users(id,name,salt,hash) VALUES($1,$2,$3,$4)', [id, name, salt, hash]);
    req.session.userId = id;
    broadcast({ type: 'state-changed' });
    res.json({ id, name });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Login ── */
app.post('/api/login', async (req, res) => {
  const { name, pin } = req.body || {};
  if(!name || !pin) return res.status(400).json({ error: 'Escribe tu nombre y tu PIN.' });

  try {
    const r = await pool.query('SELECT * FROM users WHERE LOWER(name)=LOWER($1)', [name]);
    if(!r.rows.length) return res.status(404).json({ error: 'No existe esa cuenta. Usa "Crear cuenta".' });

    const user = r.rows[0];
    const hash = crypto.createHash('sha256').update(user.salt + ':' + pin).digest('hex');
    if(hash !== user.hash) return res.status(401).json({ error: 'PIN incorrecto.' });

    req.session.userId = user.id;
    res.json({ id: user.id, name: user.name });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Logout ── */
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* ── Cambiar nombre ── */
app.put('/api/rename', async (req, res) => {
  if(!req.session.userId) return res.status(401).json({ error: 'No autenticado.' });
  const { name } = req.body || {};
  if(!name) return res.status(400).json({ error: 'Nombre inválido.' });

  try {
    const conf = await pool.query('SELECT id FROM users WHERE LOWER(name)=LOWER($1) AND id!=$2', [name, req.session.userId]);
    if(conf.rows.length) return res.status(409).json({ error: 'Ya hay otra cuenta con ese nombre.' });

    await pool.query('UPDATE users SET name=$1 WHERE id=$2', [name, req.session.userId]);
    broadcast({ type: 'state-changed' });
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Eliminar cuenta ── */
app.delete('/api/account', async (req, res) => {
  if(!req.session.userId) return res.status(401).json({ error: 'No autenticado.' });
  const id = req.session.userId;

  try {
    await pool.query('DELETE FROM predictions WHERE user_id=$1', [id]);
    await pool.query('DELETE FROM users WHERE id=$1', [id]);
    req.session.destroy(() => {
      broadcast({ type: 'state-changed' });
      res.json({ ok: true });
    });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Pronóstico ── */
app.post('/api/prediction', async (req, res) => {
  if(!req.session.userId) return res.status(401).json({ error: 'No autenticado.' });
  const { matchId, value } = req.body || {};
  const mid = String(matchId);

  try {
    if(!value) {
      await pool.query('DELETE FROM predictions WHERE match_id=$1 AND user_id=$2', [mid, req.session.userId]);
    } else {
      await pool.query(
        'INSERT INTO predictions(match_id,user_id,value) VALUES($1,$2,$3) ON CONFLICT(match_id,user_id) DO UPDATE SET value=$3',
        [mid, req.session.userId, value]
      );
    }
    broadcast({ type: 'prediction-changed', matchId: mid });
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Editar partido ── */
app.post('/api/match-edit', async (req, res) => {
  if(!req.session.userId) return res.status(401).json({ error: 'No autenticado.' });
  const { matchId, a, b, date, time, group } = req.body || {};

  try {
    await pool.query(
      `INSERT INTO match_edits(match_id,a,b,date_val,time_val,group_name) VALUES($1,$2,$3,$4,$5,$6)
       ON CONFLICT(match_id) DO UPDATE SET a=$2,b=$3,date_val=$4,time_val=$5,group_name=$6`,
      [String(matchId), a, b, date, time, group || null]
    );
    broadcast({ type: 'match-edited', matchId });
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Restaurar partido ── */
app.delete('/api/match-edit/:id', async (req, res) => {
  if(!req.session.userId) return res.status(401).json({ error: 'No autenticado.' });

  try {
    await pool.query('DELETE FROM match_edits WHERE match_id=$1', [req.params.id]);
    broadcast({ type: 'match-edited', matchId: req.params.id });
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error del servidor.' }); }
});

/* ── Arranque ── */
const PORT = process.env.PORT || 3000;

initDB()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🏆  OFICINA corriendo en http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌  No se pudo conectar a la base de datos:', err.message);
    process.exit(1);
  });
