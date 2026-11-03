import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'node:crypto';
import webpush from 'web-push';
import { google } from 'googleapis';

const { PORT = 3000, BASE_URL, DATABASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET, GEMINI_API_KEY, GEMINI_MODEL = 'gemini-3.8-flash' } = process.env;
const MODEL = String(GEMINI_MODEL).trim().replace(/^models\//, '').replace(/\s+/g, '-');
const prod = process.env.NODE_ENV === 'production';
const db = new pg.Pool({ connectionString: DATABASE_URL, ssl: prod || /sslmode=require/.test(DATABASE_URL || '') ? { rejectUnauthorized: false } : false });
const q = (t, p) => db.query(t, p).then(r => r.rows);

await q(`
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, google_id TEXT UNIQUE NOT NULL, email TEXT, name TEXT, picture TEXT,
  refresh_token TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS events(
  id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, google_id TEXT,
  title TEXT NOT NULL, start_at TIMESTAMPTZ NOT NULL, end_at TIMESTAMPTZ, source TEXT DEFAULT 'manual',
  status TEXT DEFAULT 'pendiente', notes TEXT, UNIQUE(user_id, google_id));
CREATE TABLE IF NOT EXISTS notifications(
  id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, gmail_id TEXT,
  kind TEXT, title TEXT, snippet TEXT, status TEXT DEFAULT 'pendiente',
  created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(user_id, gmail_id));
ALTER TABLE events ADD COLUMN IF NOT EXISTS cal TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS all_day BOOLEAN DEFAULT false;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS from_addr TEXT;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ;
ALTER TABLE events ADD COLUMN IF NOT EXISTS kind TEXT;
CREATE TABLE IF NOT EXISTS type_rules(user_id INT REFERENCES users(id) ON DELETE CASCADE, title TEXT, kind TEXT, PRIMARY KEY(user_id, title));`);
await q(`DELETE FROM events WHERE source='calendar' AND cal IS NULL`);
await q(`
ALTER TABLE users ADD COLUMN IF NOT EXISTS name_custom TEXT, ADD COLUMN IF NOT EXISTS picture_custom TEXT, ADD COLUMN IF NOT EXISTS home TEXT,
  ADD COLUMN IF NOT EXISTS campus TEXT, ADD COLUMN IF NOT EXISTS tz TEXT DEFAULT 'America/Bogota', ADD COLUMN IF NOT EXISTS api_token TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS location TEXT;
CREATE TABLE IF NOT EXISTS push_subs(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, endpoint TEXT UNIQUE, sub JSONB);
CREATE TABLE IF NOT EXISTS sent(user_id INT, ref TEXT, PRIMARY KEY(user_id, ref));
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS usage(id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, app TEXT, day DATE, minutes INT, UNIQUE(user_id, app, day));`);

const oauth = () => new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, `${BASE_URL}/auth/callback`);
const app = express();
app.use(express.json({ limit: '400kb' }), cookieParser(), express.static('public'));

// ---------- Auth ----------
app.get('/auth/google', (_req, res) => res.redirect(oauth().generateAuthUrl({
  access_type: 'offline', prompt: 'consent',
  scope: ['openid', 'email', 'profile',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/tasks.readonly']
})));

app.get('/auth/callback', async (req, res) => {
  try {
    const c = oauth();
    const { tokens } = await c.getToken(String(req.query.code));
    c.setCredentials(tokens);
    const { data: p } = await google.oauth2({ version: 'v2', auth: c }).userinfo.get();
    const [u] = await q(`INSERT INTO users(google_id,email,name,picture,refresh_token) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(google_id) DO UPDATE SET email=$2,name=$3,picture=$4,
      refresh_token=COALESCE($5,users.refresh_token) RETURNING id`,
      [p.id, p.email, p.name, p.picture, tokens.refresh_token || null]);
    res.cookie('t', jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '30d' }),
      { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 30 * 864e5 });
    res.redirect('/');
  } catch (e) { console.error(e); res.status(500).send('Error de autenticación'); }
});

app.post('/auth/logout', (_req, res) => res.clearCookie('t').json({ ok: true }));

const auth = (req, res, next) => {
  try { req.uid = jwt.verify(req.cookies.t, JWT_SECRET).uid; next(); }
  catch { res.status(401).json({ error: 'no_auth' }); }
};
const gClient = async uid => {
  const [u] = await q('SELECT refresh_token FROM users WHERE id=$1', [uid]);
  const c = oauth(); c.setCredentials({ refresh_token: u.refresh_token }); return c;
};

// ---------- API ----------
app.get('/health', (_q, r) => r.json({ ok: true }));
app.get('/api/me', auth, async (req, res) => {
  const [u] = await q(`SELECT id,email,COALESCE(name_custom,name) AS name,COALESCE(picture_custom,picture) AS picture,picture AS google_picture,home,campus,tz,api_token FROM users WHERE id=$1`, [req.uid]);
  if (!u.api_token) { u.api_token = crypto.randomBytes(24).toString('hex'); await q('UPDATE users SET api_token=$2 WHERE id=$1', [req.uid, u.api_token]); }
  res.json(u);
});
app.patch('/api/me', auth, async (req, res) => {
  const { name, picture, home, campus, tz } = req.body, cut = (v, n) => v == null ? null : String(v).slice(0, n);
  if (picture && !/^data:image\/(jpeg|png|webp);base64,/.test(picture)) return res.status(400).json({ error: 'imagen_invalida' });
  await q(`UPDATE users SET
    name_custom = CASE WHEN $2::text IS NULL THEN name_custom WHEN $2 = '' THEN NULL ELSE $2 END,
    picture_custom = CASE WHEN $3::text IS NULL THEN picture_custom WHEN $3 = '' THEN NULL ELSE $3 END,
    home = COALESCE($4, home), campus = COALESCE($5, campus), tz = COALESCE($6, tz) WHERE id=$1`,
    [req.uid, cut(name, 80), cut(picture, 300000), cut(home, 200), cut(campus, 200), cut(tz, 60)]);
  res.json({ ok: true });
});
app.delete('/api/me', auth, async (req, res) => {
  await q('DELETE FROM users WHERE id=$1', [req.uid]); res.clearCookie('t').json({ ok: true });
});

// Sincroniza TODOS los calendarios, Google Tasks y Gmail
const DAY = 864e5;
const chunk = (a, n) => Array.from({ length: Math.ceil(a.length / n) }, (_, i) => a.slice(i * n, i * n + n));
async function listAll(fn, params, key = 'items', cap = Infinity) {
  const out = []; let pageToken;
  do { const { data } = await fn({ ...params, pageToken }); out.push(...(data[key] || [])); pageToken = data.nextPageToken; }
  while (pageToken && out.length < cap);
  return out;
}
app.post('/api/sync', auth, async (req, res) => {
  const out = { events: 0, tasks: 0, mails: 0, warnings: [] };
  try {
    const [me] = await q('SELECT google_id FROM users WHERE id=$1', [req.uid]);
    if (me.google_id === 'demo') { await seedDemo(req.uid); return res.json({ events: 7, tasks: 4, mails: 2, warnings: [] }); }
    const c = await gClient(req.uid), now = Date.now();
    await q(`DELETE FROM events WHERE user_id=$1 AND source='calendar' AND cal IS NULL`, [req.uid]);
    // 1) Calendarios (todos: clases, personal, festivos, compartidos…)
    const cal = google.calendar({ version: 'v3', auth: c });
    const cals = await listAll(p => cal.calendarList.list(p), { maxResults: 250, showHidden: true });
    for (const k of cals) {
      try {
        const evs = await listAll(p => cal.events.list(p), { calendarId: k.id, singleEvents: true, orderBy: 'startTime', maxResults: 250,
          timeMin: new Date(now - 40 * DAY).toISOString(), timeMax: new Date(now + 120 * DAY).toISOString() });
        for (const e of evs) {
          if (e.status === 'cancelled' || !e.start) continue;
          const allDay = !e.start.dateTime;
          await q(`INSERT INTO events(user_id,google_id,title,start_at,end_at,source,cal,all_day,location) VALUES($1,$2,$3,$4,$5,'calendar',$6,$7,$8)
            ON CONFLICT(user_id,google_id) DO UPDATE SET title=$3,start_at=$4,end_at=$5,cal=$6,all_day=$7,location=$8`,
            [req.uid, `${k.id}:${e.id}`, e.summary || '(sin título)', e.start.dateTime || `${e.start.date}T12:00:00Z`,
             e.end?.dateTime || null, k.summaryOverride || k.summary, allDay, e.location || null]);
          out.events++;
        }
      } catch { out.warnings.push('calendario ' + (k.summary || k.id)); }
    }
    // 2) Google Tasks (lo rojo tachado de tu calendario)
    try {
      const tk = google.tasks({ version: 'v1', auth: c });
      for (const l of await listAll(p => tk.tasklists.list(p), { maxResults: 100 })) {
        const ts = await listAll(p => tk.tasks.list(p), { tasklist: l.id, showCompleted: true, showHidden: true, maxResults: 100 });
        for (const t of ts) {
          if (!t.title) continue;
          const done = t.status === 'completed';
          if (done && t.due && new Date(t.due) < now - 40 * DAY) continue;
          if (t.due) {
            await q(`INSERT INTO events(user_id,google_id,title,start_at,source,cal,all_day,status) VALUES($1,$2,$3,$4,'task',$5,true,$6)
              ON CONFLICT(user_id,google_id) DO UPDATE SET title=$3,start_at=$4,cal=$5,status=$6`,
              [req.uid, 'task:' + t.id, t.title, t.due.slice(0, 10) + 'T12:00:00Z', l.title, done ? 'hecho' : 'pendiente']);
          } else if (!done) {
            await q(`INSERT INTO notifications(user_id,gmail_id,kind,title,snippet,from_addr,received_at) VALUES($1,$2,'tarea',$3,$4,$5,now())
              ON CONFLICT(user_id,gmail_id) DO NOTHING`, [req.uid, 'task:' + t.id, t.title, t.notes || 'Tarea sin fecha', l.title]);
          } else await q(`UPDATE notifications SET status='hecho' WHERE user_id=$1 AND gmail_id=$2`, [req.uid, 'task:' + t.id]);
          out.tasks++;
        }
      }
    } catch (e) { console.error('tareas:', e.message); out.warnings.push('tareas: ' + e.message.slice(0, 140)); }
    // 3) Gmail: citas/recordatorios y pagos/suscripciones, sin ruido de GitHub
    try {
      const gm = google.gmail({ version: 'v1', auth: c });
      const queries = [
        { kind: 'cita', q: 'newer_than:60d -from:github.com (cita OR appointment OR agendada OR reserva OR turno OR recordatorio OR reminder OR invitación OR entrevista)' },
        { kind: 'pago', q: 'newer_than:90d -from:github.com (factura OR recibo OR receipt OR invoice OR suscripción OR subscription OR renovación OR "próximo pago" OR cobro OR pago OR payment)' }
      ];
      await q(`DELETE FROM notifications WHERE user_id=$1 AND status='pendiente' AND gmail_id NOT LIKE 'task:%'`, [req.uid]);
      const found = new Map();
      for (const k of queries)
        for (const m of await listAll(p => gm.users.messages.list(p), { userId: 'me', q: k.q, maxResults: 100 }, 'messages', 150))
          if (!found.has(m.id)) found.set(m.id, k.kind);
      for (const part of chunk([...found], 10)) await Promise.all(part.map(async ([id, kind]) => {
        const { data: d } = await gm.users.messages.get({ userId: 'me', id, format: 'metadata', metadataHeaders: ['Subject', 'From'] });
        const H = n => d.payload.headers.find(h => h.name === n)?.value || '';
        await q(`INSERT INTO notifications(user_id,gmail_id,kind,title,snippet,from_addr,received_at) VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7::numeric/1000))
          ON CONFLICT(user_id,gmail_id) DO UPDATE SET kind=$3,title=$4,snippet=$5,from_addr=$6,received_at=to_timestamp($7::numeric/1000)`,
          [req.uid, id, kind, H('Subject') || '(sin asunto)', d.snippet, H('From'), Number(d.internalDate)]);
        out.mails++;
      }));
    } catch (e) { console.error('correo:', e.message); out.warnings.push('correo: ' + e.message.slice(0, 140)); }
    await q('UPDATE events e SET kind=r.kind FROM type_rules r WHERE e.user_id=r.user_id AND e.title=r.title AND e.user_id=$1', [req.uid]);
    res.json(out);
  } catch (e) { console.error(e); res.status(500).json({ error: 'sync_failed' }); }
});

// Un mismo evento (mismo título y hora) se muestra una sola vez aunque venga de dos calendarios
const dedupe = where => `SELECT * FROM (SELECT DISTINCT ON (lower(title), start_at) * FROM events WHERE user_id=$1 AND ${where}
  ORDER BY lower(title), start_at, (cal IS NULL), id DESC) x`;
app.get('/api/events', auth, async (req, res) =>
  res.json(await q(dedupe(`start_at >= now() - interval '40 days' AND start_at < now() + interval '120 days'`) + ' ORDER BY start_at', [req.uid])));
app.get('/api/history', auth, async (req, res) =>
  res.json(await q(dedupe('start_at < now()') + ' ORDER BY start_at DESC LIMIT 200', [req.uid])));
app.post('/api/events', auth, async (req, res) => {
  const { title, start_at, notes, kind } = req.body;
  if (!title || !start_at) return res.status(400).json({ error: 'faltan_datos' });
  res.json((await q('INSERT INTO events(user_id,title,start_at,notes,kind) VALUES($1,$2,$3,$4,$5) RETURNING *',
    [req.uid, title, start_at, notes || null, kind || null]))[0]);
});
app.patch('/api/events/:id', auth, async (req, res) =>
  res.json((await q('UPDATE events SET status=$1 WHERE id=$2 AND user_id=$3 RETURNING *',
    [req.body.status, req.params.id, req.uid]))[0]));
// Cambiar el tipo de un evento: se aplica a todos los que se llamen igual (y a los futuros)
app.patch('/api/events/:id/kind', auth, async (req, res) => {
  const kind = String(req.body.kind || '').trim().slice(0, 40);
  if (!kind) return res.status(400).json({ error: 'falta_tipo' });
  const [e] = await q('SELECT title FROM events WHERE id=$1 AND user_id=$2', [req.params.id, req.uid]);
  if (!e) return res.status(404).json({ error: 'no_existe' });
  await q('INSERT INTO type_rules(user_id,title,kind) VALUES($1,$2,$3) ON CONFLICT(user_id,title) DO UPDATE SET kind=$3', [req.uid, e.title, kind]);
  await q('UPDATE events SET kind=$3 WHERE user_id=$1 AND title=$2', [req.uid, e.title, kind]);
  res.json({ ok: true });
});
app.get('/api/notifications', auth, async (req, res) =>
  res.json(await q('SELECT * FROM notifications WHERE user_id=$1 ORDER BY COALESCE(received_at, created_at) DESC LIMIT 100', [req.uid])));
app.patch('/api/notifications/:id', auth, async (req, res) =>
  res.json((await q('UPDATE notifications SET status=$1 WHERE id=$2 AND user_id=$3 RETURNING *',
    [req.body.status, req.params.id, req.uid]))[0]));

// Asistente IA (Gemini) con contexto real de tu agenda
app.post('/api/ai', auth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.json({ reply: 'La IA aún no está activada. Agrega GEMINI_API_KEY en el .env.' });
  const tz = String(req.body.tz || 'America/Bogota');
  const loc = d => new Date(d).toLocaleString('es', { timeZone: tz, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  const evs = (await q(`SELECT title,start_at,status,source,cal,all_day,kind FROM events WHERE user_id=$1
    AND ((start_at BETWEEN now() - interval '7 days' AND now() + interval '14 days') OR (source='task' AND status='pendiente' AND start_at < now()))
    ORDER BY start_at LIMIT 80`, [req.uid])).map(e => ({
      titulo: e.title, cuando: e.all_day ? new Date(e.start_at).toISOString().slice(0, 10) : loc(e.start_at),
      origen: e.source === 'task' ? 'tarea de Google Tasks' : 'calendario: ' + e.cal, estado: e.status, tipo: e.kind || undefined }));
  const nots = await q(`SELECT kind,title,from_addr FROM notifications WHERE user_id=$1 AND status='pendiente' LIMIT 25`, [req.uid]);
  const system = `Eres el asistente personal de agenda de una persona desordenada que necesita ayuda para priorizar. Responde en español, breve y concreto (máximo 6 líneas), sin relleno. Ahora es ${loc(Date.now())} (${tz}). Al hablar de un evento di de qué tipo es (clase, tarea, pago, cita, festivo). Prioriza lo atrasado y lo urgente y sugiere qué hacer primero.\nAgenda: ${JSON.stringify(evs)}\nCorreos pendientes: ${JSON.stringify(nots)}`;
  try {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: String(req.body.message || '').slice(0, 2000) }] }] })
    });
    const d = await r.json();
    const text = d.candidates?.[0]?.content?.parts?.map(p => p.text).join('');
    if (!text) { console.error('Gemini:', JSON.stringify(d).slice(0, 600)); return res.json({ reply: `Gemini no respondió (modelo "${MODEL}"): ` + (d.error?.message || d.promptFeedback?.blockReason || 'respuesta vacía') }); }
    res.json({ reply: text });
  } catch (e) { console.error(e); res.json({ reply: 'No pude conectar con Gemini: ' + e.message }); }
});

// ---------- Recordatorios (Web Push) ----------
const k0 = await q("SELECT v FROM kv WHERE k='vapid'");
const VAPID = k0[0] ? JSON.parse(k0[0].v) : webpush.generateVAPIDKeys();
if (!k0[0]) await q("INSERT INTO kv VALUES('vapid',$1)", [JSON.stringify(VAPID)]);
webpush.setVapidDetails(process.env.VAPID_CONTACT || 'mailto:ritmo@example.com', VAPID.publicKey, VAPID.privateKey);
app.get('/api/push/key', auth, (_q, r) => r.json({ key: VAPID.publicKey }));
app.post('/api/push/sub', auth, async (req, res) => {
  const sub = req.body.sub; if (!sub?.endpoint) return res.status(400).json({ error: 'sub' });
  await q('INSERT INTO push_subs(user_id,endpoint,sub) VALUES($1,$2,$3) ON CONFLICT(endpoint) DO UPDATE SET user_id=$1,sub=$3', [req.uid, sub.endpoint, sub]);
  res.json({ ok: true });
});
async function push(uid, title, body) {
  for (const r of await q('SELECT endpoint,sub FROM push_subs WHERE user_id=$1', [uid]))
    try { await webpush.sendNotification(r.sub, JSON.stringify({ title, body })); }
    catch (e) { if ([404, 410].includes(e.statusCode)) await q('DELETE FROM push_subs WHERE endpoint=$1', [r.endpoint]); }
}
app.post('/api/push/test', auth, async (req, res) => { await push(req.uid, 'Ritmo', 'Todo listo. Así sonarán tus recordatorios: con calma y a tiempo.'); res.json({ ok: true }); });
const pick = a => a[Math.floor(Math.random() * a.length)];
const first = async (uid, ref) => (await q('INSERT INTO sent VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING 1', [uid, ref])).length > 0;
const hhmm = (d, tz) => new Date(d).toLocaleTimeString('en-GB', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false });
const ymd = (d, tz) => new Date(d).toLocaleDateString('en-CA', { timeZone: tz });
async function tick() {
  for (const u of await q('SELECT DISTINCT u.id, COALESCE(u.tz,$1) AS tz FROM users u JOIN push_subs p ON p.user_id=u.id', ['America/Bogota'])) {
    const now = Date.now(), day = ymd(now, u.tz), hm = hhmm(now, u.tz);
    // a) media hora antes de cada cosa con hora
    for (const e of await q(`SELECT id,title,start_at FROM events WHERE user_id=$1 AND NOT all_day AND status='pendiente' AND start_at BETWEEN now() + interval '25 minutes' AND now() + interval '35 minutes'`, [u.id]))
      if (await first(u.id, 'antes:' + e.id)) await push(u.id, 'Ritmo', pick([
        `En media hora: «${e.title}». Respira hondo, ya casi.`,
        `«${e.title}» empieza a las ${hhmm(e.start_at, u.tz)}. Hay tiempo para un vaso de agua.`,
        `Aviso con cariño: «${e.title}» a las ${hhmm(e.start_at, u.tz)}.`]));
    // b) resumen suave de la mañana
    if (hm >= '07:30' && hm < '09:00' && await first(u.id, 'resumen:' + day)) {
      const evs = await q(`SELECT title,start_at,all_day,source,cal,kind FROM events WHERE user_id=$1 AND status='pendiente' AND start_at BETWEEN now() - interval '40 days' AND now() + interval '2 days'`, [u.id]);
      const hoy = evs.filter(e => !e.all_day && ymd(e.start_at, u.tz) === day), tareas = evs.filter(e => e.source === 'task' && ymd(e.start_at, 'UTC') <= day);
      const clases = hoy.filter(e => (e.kind || (/clase/i.test(e.cal) ? 'Clase' : '')) === 'Clase').length, vencidas = tareas.filter(e => ymd(e.start_at, 'UTC') < day);
      let t = `Buen día. Hoy tienes ${hoy.length} ${hoy.length === 1 ? 'evento' : 'eventos'}${clases ? ` (${clases} de clase)` : ''}`;
      t += tareas.length ? ` y ${tareas.length} ${tareas.length === 1 ? 'tarea pendiente' : 'tareas pendientes'}.` : '.';
      t += vencidas.length ? ` Empieza por «${vencidas[0].title}», que ya venció. Un paso pequeño también cuenta.` : (hoy.length || tareas.length ? ' Vas con buen ritmo.' : ' Día libre: disfrútalo.');
      await push(u.id, 'Ritmo · tu día', t);
    }
  }
}
setInterval(() => tick().catch(e => console.error('recordatorios:', e.message)), 60000);

// ---------- Tiempo en apps (lo alimentan Atajos de iPhone / Tasker / a mano) ----------
const tokAuth = async (req, res, next) => {
  const t = req.get('x-ritmo-token') || req.query.t, [u] = t ? await q('SELECT id FROM users WHERE api_token=$1', [t]) : [];
  if (!u) return res.status(401).json({ error: 'token' }); req.uid = u.id; next();
};
const either = (req, res, next) => req.cookies.t ? auth(req, res, next) : tokAuth(req, res, next);
const today = async uid => { const [u] = await q('SELECT tz FROM users WHERE id=$1', [uid]); return ymd(Date.now(), u?.tz || 'America/Bogota'); };
app.post('/api/usage', either, async (req, res) => {
  const nombre = String(req.body.app || '').trim().slice(0, 40), ev = req.body.event, k = `open:${req.uid}:${nombre}`;
  if (!nombre) return res.status(400).json({ error: 'falta_app' });
  if (ev === 'open') { await q('INSERT INTO kv VALUES($1,$2) ON CONFLICT(k) DO UPDATE SET v=$2', [k, String(Date.now())]); return res.json({ ok: true }); }
  let m = Math.round(Number(req.body.minutes));
  if (ev === 'close') { const [o] = await q('DELETE FROM kv WHERE k=$1 RETURNING v', [k]); m = o ? Math.min(240, Math.max(1, Math.round((Date.now() - Number(o.v)) / 60000))) : 0; }
  if (!(m > 0 && m < 1440)) return res.json({ ok: false, note: 'sin_tiempo' });
  await q('INSERT INTO usage(user_id,app,day,minutes) VALUES($1,$2,$3,$4) ON CONFLICT(user_id,app,day) DO UPDATE SET minutes=usage.minutes+$4', [req.uid, nombre, await today(req.uid), m]);
  res.json({ ok: true, minutes: m });
});
app.get('/api/usage', auth, async (req, res) => res.json(await q(
  `SELECT app, COALESCE(SUM(minutes) FILTER (WHERE day=$2::date),0)::int AS hoy, SUM(minutes)::int AS semana FROM usage WHERE user_id=$1 AND day > $2::date - 7 GROUP BY app ORDER BY semana DESC`,
  [req.uid, await today(req.uid)])));

// ---------- Rutas TransMilenio / SITP (Google Routes API, transporte público) ----------
const secs = v => parseInt(String(v || '0'), 10) || 0;
app.get('/api/route/:id', auth, async (req, res) => {
  const KEY = process.env.GOOGLE_MAPS_KEY;
  if (!KEY) return res.json({ error: 'Falta GOOGLE_MAPS_KEY en el .env (activa Routes API en Google Cloud).' });
  const [u] = await q('SELECT home,campus FROM users WHERE id=$1', [req.uid]);
  const [e] = await q('SELECT title,start_at,location,kind,cal FROM events WHERE id=$1 AND user_id=$2', [req.params.id, req.uid]);
  if (!e) return res.status(404).json({ error: 'no_existe' });
  const clase = (e.kind || (/clase/i.test(e.cal) ? 'Clase' : '')) === 'Clase', to = e.location || (clase ? u.campus : null);
  if (!u.home) return res.json({ error: 'Agrega tu dirección de casa en Perfil.' });
  if (!to) return res.json({ error: 'Este evento no tiene lugar. Agrega el lugar habitual de clases en Perfil.' });
  const arrive = new Date(new Date(e.start_at).getTime() - 10 * 60000);
  if (arrive < Date.now()) return res.json({ error: 'Este evento ya casi empieza o ya pasó.' });
  const place = a => ({ address: /bogot/i.test(a) ? a : a + ', Bogotá, Colombia' });
  try {
    const r = await fetch('https://routes.googleapis.com/directions/v2:computeRoutes', { method: 'POST',
      headers: { 'content-type': 'application/json', 'X-Goog-Api-Key': KEY,
        'X-Goog-FieldMask': 'routes.duration,routes.legs.steps.travelMode,routes.legs.steps.staticDuration,routes.legs.steps.transitDetails' },
      body: JSON.stringify({ origin: place(u.home), destination: place(to), travelMode: 'TRANSIT', arrivalTime: arrive.toISOString(), computeAlternativeRoutes: true, languageCode: 'es', regionCode: 'CO' }) });
    const d = await r.json();
    if (!d.routes?.length) return res.json({ error: d.error?.message || 'Google no encontró rutas de transporte público.' });
    res.json({ to, options: d.routes.slice(0, 3).map(rt => {
      const steps = rt.legs?.[0]?.steps || [], tr = steps.filter(x => x.transitDetails); let walk = 0;
      for (const x of steps) { if (x.transitDetails) break; walk += secs(x.staticDuration); }
      const dep = tr[0]?.transitDetails?.stopDetails?.departureTime;
      return { minutes: Math.round(secs(rt.duration) / 60), leave: dep ? new Date(new Date(dep).getTime() - walk * 1000).toISOString() : null,
        lines: tr.map(x => { const l = x.transitDetails.transitLine || {}; return { name: l.nameShort || l.name, agency: l.agencies?.[0]?.name }; }) };
    }) });
  } catch (err) { console.error('ruta:', err.message); res.json({ error: 'No pude consultar la ruta: ' + err.message }); }
});

// ---------- Modo demo (DEMO_MODE=true): entra sin Google y con datos de ejemplo ----------
app.get('/api/config', (_q, r) => r.json({ demo: process.env.DEMO_MODE === 'true' }));
async function seedDemo(uid) {
  for (const t of ['events', 'notifications', 'usage']) await q(`DELETE FROM ${t} WHERE user_id=$1`, [uid]);
  const now = Date.now(), H = 36e5, day = n => ymd(now + n * 864e5, 'America/Bogota') + 'T12:00:00Z';
  const ev = [['Desarrollo cómputo_L510', 1.5, 'Clases', 'Clase', null], ['Redes cómputo_N407', 3.5, 'Clases', 'Clase', null],
    ['Entrevista de trabajo · Bancolombia', 26, 'Personal', 'Entrevista', 'Carrera 7 #71-21, Bogotá'], ['Gestión de proyectos aula', 28, 'Clases', 'Clase', null],
    ['Pago Spotify', 48, 'Personal', 'Pago', null], ['Cita odontología', 74, 'Personal', 'Cita', null]];
  for (const [i, [t, h, cal, kind, loc]] of ev.entries())
    await q(`INSERT INTO events(user_id,google_id,title,start_at,source,cal,kind,location) VALUES($1,$2,$3,$4,'calendar',$5,$6,$7)`, [uid, 'demo:' + i, t, new Date(now + h * H).toISOString(), cal, kind, loc]);
  for (const [i, [t, d, st]] of [['Entrega 1 bitácora', -3, 'pendiente'], ['Taller de gestión', 0, 'pendiente'], ['Guía de redes', 1, 'pendiente'], ['Quiz de redes', -6, 'hecho']].entries())
    await q(`INSERT INTO events(user_id,google_id,title,start_at,source,cal,all_day,status) VALUES($1,$2,$3,$4,'task','Mis tareas',true,$5)`, [uid, 'demo:t' + i, t, day(d), st]);
  await q(`INSERT INTO events(user_id,google_id,title,start_at,source,cal,all_day) VALUES($1,'demo:b','Cumpleaños de Laura',$2,'calendar','Aniversarios',true)`, [uid, day(2)]);
  for (const [i, [k, t, sn, fr]] of [['cita', 'Confirmación de tu cita con Odontosalud', 'Tu cita quedó agendada para el viernes a las 3:00 p. m.', 'Odontosalud <citas@odontosalud.co>'],
    ['pago', 'Tu suscripción se renueva pronto', 'Se cobrarán $16.900 el próximo lunes.', 'Spotify <no-reply@spotify.com>']].entries())
    await q(`INSERT INTO notifications(user_id,gmail_id,kind,title,snippet,from_addr,received_at) VALUES($1,$2,$3,$4,$5,$6,now())`, [uid, 'demo:n' + i, k, t, sn, fr]);
  const d0 = ymd(now, 'America/Bogota'), d3 = ymd(now - 3 * 864e5, 'America/Bogota');
  for (const [a, h0, h3] of [['Instagram', 85, 225], ['YouTube', 40, 150], ['WhatsApp', 25, 95]])
    await q('INSERT INTO usage(user_id,app,day,minutes) VALUES($1,$2,$3,$4),($1,$2,$5,$6)', [uid, a, d0, h0, d3, h3]);
}
app.get('/demo', async (req, res) => {
  if (process.env.DEMO_MODE !== 'true') return res.status(404).send('Modo demo desactivado');
  const [u] = await q(`INSERT INTO users(google_id,email,name,home,campus) VALUES('demo','demo@ritmo.app','Invitado','Calle 100 #15-20, Bogotá','Universidad Nacional de Colombia, Bogotá')
    ON CONFLICT(google_id) DO UPDATE SET home=EXCLUDED.home,campus=EXCLUDED.campus RETURNING id`);
  await seedDemo(u.id);
  res.cookie('t', jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '1d' }), { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 864e5 });
  res.redirect('/');
});

app.listen(PORT, () => console.log(`Ritmo en ${BASE_URL || 'http://localhost:' + PORT} · sync v2 · IA: ${MODEL}`));
