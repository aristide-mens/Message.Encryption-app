// server.js
// Minimal ephemeral session server for your congruence-based encrypt/decrypt algorithm.
// Run: npm init -y && npm i express cors helmet express-rate-limit
// then: node server.js
// NOTE: Run behind TLS in production (nginx / reverse proxy). Do not expose directly to the public Internet without TLS.

const express = require('express');
const crypto = require('crypto');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(helmet());
app.use(cors()); // lock this down to your front-end origin(s) in production
app.use(express.json({ limit: '50kb' }));

// Basic rate limiter (adjust for your needs)
const limiter = rateLimit({
  windowMs: 15 * 1000, // 15s
  max: 30, // max requests per window per IP
});
app.use(limiter);

// ---------- Algorithm & Symbol maps (same as client) ----------
const symbolMap = {
  'A': '+', 'B': '#', 'C': '°', 'D': '√', 'E': '\\',
  'F': '™', 'G': ']', 'H': '÷', 'I': 'π', 'J': '{',
  'K': '&', 'L': '^', 'M': '§', 'N': '¥', 'O': '∆',
  'P': '£', 'Q': '¢', 'R': '%', 'S': '~', 'T': '©',
  'U': '-', 'V': '•', 'W': '€', 'X': '®', 'Y': '✓', 'Z': '|'
};

const reverseSymbolMap = {};
for (const [k, v] of Object.entries(symbolMap)) reverseSymbolMap[v] = k;

// Coprimes with 26 (same as client)
const coprimesWith26 = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

function calculateAB(password) {
  // Replicates the client logic: first letter value influences a, sum influences b
  let firstLetterValue = 3;
  let total = 0;
  let hasLetters = false;

  for (const char of password) {
    if (/[a-zA-Z]/.test(char)) {
      const letterValue = char.toUpperCase().charCodeAt(0) - 65;
      if (!hasLetters) {
        firstLetterValue = letterValue;
        hasLetters = true;
      }
      total += letterValue;
    } else if (/[0-9]/.test(char)) {
      total += parseInt(char, 10);
    } else {
      total += char.charCodeAt(0) % 26;
    }
  }

  const a = coprimesWith26[firstLetterValue % coprimesWith26.length];
  const b = total % 26;
  return { a, b };
}

// modular inverse using extended euclidean algorithm (robust)
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  let m0 = m;
  let x0 = 0;
  let x1 = 1;
  if (m === 1) return 0;
  while (a > 1) {
    const q = Math.floor(a / m);
    let t = m;
    m = a % m;
    a = t;
    t = x0;
    x0 = x1 - q * x0;
    x1 = t;
  }
  if (x1 < 0) x1 += m0;
  return x1;
}

function encodeWithPassword(text, password) {
  const { a, b } = calculateAB(password);
  let result = '';
  for (const char of text) {
    if (/[a-zA-Z]/.test(char)) {
      const upperChar = char.toUpperCase();
      const x = upperChar.charCodeAt(0) - 65;
      const y = (a * x + b) % 26;
      const codedLetter = String.fromCharCode(y + 65);
      result += (symbolMap[codedLetter] || char);
    } else {
      result += char;
    }
  }
  return result;
}

function decodeWithPassword(text, password) {
  const { a, b } = calculateAB(password);
  const aInverse = modInverse(a, 26);
  let result = '';
  for (const ch of text) {
    if (reverseSymbolMap[ch]) {
      const codedLetter = reverseSymbolMap[ch];
      const y = codedLetter.charCodeAt(0) - 65;
      let x = (aInverse * (y - b)) % 26;
      if (x < 0) x += 26;
      const decodedLetter = String.fromCharCode(x + 65);
      result += decodedLetter;
    } else {
      result += ch;
    }
  }
  return result;
}

// ---------- Ephemeral session storage ----------
const sessions = new Map(); // sessionId -> { password, expiresAt, timeout }

// default TTL (ms)
const DEFAULT_TTL_MS = 60 * 1000; // 60 seconds

function createSession(password, ttl = DEFAULT_TTL_MS) {
  const sessionId = crypto.randomBytes(16).toString('hex');
  const expiresAt = Date.now() + ttl;
  // schedule cleanup
  const timeout = setTimeout(() => {
    const s = sessions.get(sessionId);
    if (s) {
      // attempt best-effort memory clean (strings immutable — see notes)
      s.password = null;
      sessions.delete(sessionId);
    }
  }, ttl);

  sessions.set(sessionId, { password, expiresAt, timeout });
  return sessionId;
}

function getAndDeleteSessionPassword(sessionId) {
  const entry = sessions.get(sessionId);
  if (!entry) return null;
  // Extract password and delete immediately
  const password = entry.password;
  clearTimeout(entry.timeout);
  // best-effort erase reference
  entry.password = null;
  sessions.delete(sessionId);
  return password;
}

// ---------- Endpoints ----------

// Create session (store password temporarily in RAM)
// Body: { password: string, ttlSeconds?: number } -> { sessionId: string, expiresAt: number }
app.post('/session', (req, res) => {
  try {
    const { password, ttlSeconds } = req.body;
    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: 'password required (string)' });
    }
    const ttlMs = (typeof ttlSeconds === 'number' && ttlSeconds > 0) ? ttlSeconds * 1000 : DEFAULT_TTL_MS;
    const sessionId = createSession(password, ttlMs);
    const entry = sessions.get(sessionId);
    return res.json({ sessionId, expiresAt: entry.expiresAt });
  } catch (err) {
    return res.status(500).json({ error: 'internal error' });
  }
});

// One-shot encode (password is not stored on server map)
app.post('/one-shot/encode', (req, res) => {
  const { password, message } = req.body;
  if (!password || !message) return res.status(400).json({ error: 'password and message required' });
  try {
    const encoded = encodeWithPassword(String(message), String(password));
    // best-effort: do not keep references to password
    return res.json({ result: encoded });
  } catch (err) {
    return res.status(500).json({ error: 'encode failed' });
  }
});

// One-shot decode
app.post('/one-shot/decode', (req, res) => {
  const { password, message } = req.body;
  if (!password || !message) return res.status(400).json({ error: 'password and message required' });
  try {
    const decoded = decodeWithPassword(String(message), String(password));
    return res.json({ result: decoded });
  } catch (err) {
    return res.status(500).json({ error: 'decode failed' });
  }
});

// Encode using stored session (consumes the password entry)
app.post('/encode', (req, res) => {
  const { sessionId, message } = req.body;
  if (!sessionId || !message) return res.status(400).json({ error: 'sessionId and message required' });
  const password = getAndDeleteSessionPassword(sessionId);
  if (!password) return res.status(404).json({ error: 'session not found or expired' });
  try {
    const encoded = encodeWithPassword(String(message), String(password));
    // best-effort remove local reference
    return res.json({ result: encoded });
  } catch (err) {
    return res.status(500).json({ error: 'encode failed' });
  }
});

// Decode using stored session (consumes the password entry)
app.post('/decode', (req, res) => {
  const { sessionId, message } = req.body;
  if (!sessionId || !message) return res.status(400).json({ error: 'sessionId and message required' });
  const password = getAndDeleteSessionPassword(sessionId);
  if (!password) return res.status(404).json({ error: 'session not found or expired' });
  try {
    const decoded = decodeWithPassword(String(message), String(password));
    return res.json({ result: decoded });
  } catch (err) {
    return res.status(500).json({ error: 'decode failed' });
  }
});

// Explicit delete (optional): allow client to explicitly instruct server to forget the password.
app.post('/session/delete', (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  const entry = sessions.get(sessionId);
  if (!entry) return res.status(404).json({ ok: false, message: 'not found' });
  clearTimeout(entry.timeout);
  entry.password = null;
  sessions.delete(sessionId);
  return res.json({ ok: true });
});

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Ephemeral-crypto-server running on port ${PORT}`);
});