require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookieSession = require('cookie-session');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

if (!SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. Set it in your .env file before going live.');
}

const FIRST_DATE = '2026-10-01';
const FREE_LAST = '2030-12-31';
const PREMIUM_LAST = '2050-12-31';

/* ---------------------------------------------------------------- *
 * Tiny JSON file "database". Good enough for a small personal site.
 * Needs a persistent disk (Render/Railway work; plain Vercel
 * serverless functions do NOT keep files between requests).
 * ---------------------------------------------------------------- */
const DB_PATH = path.join(__dirname, 'data', 'db.json');

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) {
    return { users: {}, state: {} };
  }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

app.use(express.json({ limit: '512kb' }));
app.use(
  cookieSession({
    name: 'hg_session',
    keys: [SESSION_SECRET || 'dev-only-insecure-secret'],
    maxAge: 180 * 24 * 60 * 60 * 1000, // 180 days
    sameSite: 'lax',
  })
);
app.use(express.static(path.join(__dirname, 'public')));

function requireLogin(req, res, next) {
  const db = loadDB();
  const key = req.session && req.session.userId;
  const user = key && db.users[key];
  if (!user) return res.status(401).json({ error: 'not_logged_in' });
  req.db = db;
  req.userKey = key;
  req.user = user;
  next();
}

function publicUser(user) {
  return { username: user.username, tier: user.tier };
}

async function notifyDiscord(message) {
  if (!DISCORD_WEBHOOK_URL) return;
  try {
    await fetch(DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: message }),
    });
  } catch (e) {
    console.error('Discord webhook failed:', e.message);
  }
}

/* ---------------------------------------------------------------- *
 * Auth
 * ---------------------------------------------------------------- */
app.post('/api/signup', async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const email = String((req.body && req.body.email) || '').trim();

  if (username.length < 3 || username.length > 24 || !/^[a-zA-Z0-9_.-]+$/.test(username)) {
    return res.status(400).json({
      error: 'bad_username',
      message: 'Username must be 3-24 characters: letters, numbers, _ . -',
    });
  }
  if (password.length < 4 || password.length > 200) {
    return res.status(400).json({ error: 'bad_password', message: 'Password must be at least 4 characters.' });
  }
  // Loose check only — no verification email, no blocking on typos. Just needs to look like an address.
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'bad_email', message: 'Enter a valid email address.' });
  }

  const key = username.toLowerCase();
  const db = loadDB();
  if (db.users[key]) {
    return res.status(409).json({ error: 'username_taken', message: 'That username is already taken.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: crypto.randomUUID(),
    username,
    email,
    passwordHash,
    tier: 'free',
    createdAt: new Date().toISOString(),
  };
  db.users[key] = user;
  db.state[key] = {};
  saveDB(db);

  req.session.userId = key;

  notifyDiscord('🌌 **New Habit Galaxy signup:** `' + username + '` (' + email + ') — ' + user.createdAt);

  res.status(201).json({ user: publicUser(user) });
});

app.post('/api/login', async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const key = username.toLowerCase();

  const db = loadDB();
  const user = db.users[key];
  if (!user) return res.status(401).json({ error: 'invalid_credentials', message: 'Wrong username or password.' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials', message: 'Wrong username or password.' });

  req.session.userId = key;
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.get('/api/me', requireLogin, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

/* ---------------------------------------------------------------- *
 * Habit state — synced per account, filtered by tier's date range
 * ---------------------------------------------------------------- */
app.get('/api/state', requireLogin, (req, res) => {
  const state = req.db.state[req.userKey] || {};
  res.json({ state, tier: req.user.tier });
});

app.put('/api/state', requireLogin, (req, res) => {
  const incoming = (req.body && req.body.state) || {};
  const last = req.user.tier === 'premium' ? PREMIUM_LAST : FREE_LAST;

  const filtered = {};
  let dropped = 0;
  for (const k of Object.keys(incoming)) {
    const v = incoming[k];
    if (/^\d{4}-\d{2}-\d{2}$/.test(k) && k >= FIRST_DATE && k <= last && Number.isInteger(v) && v >= 0 && v < 4096) {
      filtered[k] = v;
    } else {
      dropped++;
    }
  }

  req.db.state[req.userKey] = filtered;
  saveDB(req.db);
  res.json({ ok: true, saved: Object.keys(filtered).length, dropped });
});

/* ---------------------------------------------------------------- *
 * Admin: grant/revoke premium by hand once someone pays you.
 * Protect with a secret header only you know (ADMIN_KEY in .env).
 * ---------------------------------------------------------------- */
app.post('/api/admin/tier', (req, res) => {
  if (!ADMIN_KEY || req.get('x-admin-key') !== ADMIN_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const tier = (req.body && req.body.tier) === 'premium' ? 'premium' : 'free';

  const db = loadDB();
  const user = db.users[username];
  if (!user) return res.status(404).json({ error: 'not_found' });

  user.tier = tier;
  saveDB(db);
  res.json({ ok: true, username: user.username, tier: user.tier });
});

app.listen(PORT, () => {
  console.log('Habit Galaxy server running on http://localhost:' + PORT);
});
