// server.js
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import https from 'https';

// Load SSL certificate (self-signed or CA-signed)
const sslOptions = {
    key: fs.readFileSync('./ssl/key.pem'),
    cert: fs.readFileSync('./ssl/cert.pem')
};

const app = express();
const PORT = 443;

// Security middlewares
app.use(helmet());
app.use(cors({ origin: 'https://your-client-domain.com' })); // restrict to your client
app.use(bodyParser.json({ limit: '1kb' })); // small limit for security

// Rate limiter
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // max 10 requests per IP per minute
    message: { error: 'Too many requests, slow down.' }
});
app.use(limiter);

// In-memory password store
const tempPasswords = new Map();

// Helper: Securely delete password from memory
function wipePassword(passwordObj) {
    if (passwordObj && typeof passwordObj === 'object') {
        for (let key in passwordObj) {
            if (typeof passwordObj[key] === 'string') {
                passwordObj[key] = '\0'.repeat(passwordObj[key].length);
            }
        }
    }
}

// Dummy encryption/decryption functions (use same as client)
function encryptMessage(msg, password) {
    // Replace with your actual logic
    return msg.split('').reverse().join('') + '🔒';
}

function decryptMessage(msg, password) {
    // Replace with your actual logic
    if (msg.endsWith('🔒')) {
        return msg.slice(0, -1).split('').reverse().join('');
    }
    return msg;
}

// Store password temporarily
app.post('/store-password', (req, res) => {
    const { sessionId, password } = req.body;
    if (!sessionId || !password) return res.status(400).json({ error: 'Missing sessionId or password' });

    // Store in memory
    tempPasswords.set(sessionId, { password });
    setTimeout(() => {
        const pwObj = tempPasswords.get(sessionId);
        if (pwObj) wipePassword(pwObj);
        tempPasswords.delete(sessionId);
    }, 60 * 1000); // auto-delete after 1 minute

    res.json({ status: 'Password stored securely' });
});

// Encrypt endpoint
app.post('/encrypt', (req, res) => {
    const { sessionId, message } = req.body;
    if (!sessionId || !message) return res.status(400).json({ error: 'Missing sessionId or message' });

    const pwObj = tempPasswords.get(sessionId);
    if (!pwObj) return res.status(403).json({ error: 'Password expired or not found' });

    const result = encryptMessage(message, pwObj.password);

    // Wipe password immediately
    wipePassword(pwObj);
    tempPasswords.delete(sessionId);

    res.json({ result });
});

// Decrypt endpoint
app.post('/decrypt', (req, res) => {
    const { sessionId, message } = req.body;
    if (!sessionId || !message) return res.status(400).json({ error: 'Missing sessionId or message' });

    const pwObj = tempPasswords.get(sessionId);
    if (!pwObj) return res.status(403).json({ error: 'Password expired or not found' });

    const result = decryptMessage(message, pwObj.password);

    // Wipe password immediately
    wipePassword(pwObj);
    tempPasswords.delete(sessionId);

    res.json({ result });
});

// Start HTTPS server
https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`Secure server running on https://localhost:${PORT}`);
});