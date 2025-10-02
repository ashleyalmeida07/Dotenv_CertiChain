// --- API ENDPOINT: VERIFY BY HASH (HTML PAGE) ---

import express from 'express';
import { ethers } from 'ethers';
import multer from 'multer';
import archiver from 'archiver';
import { parse as csvParse } from 'csv-parse/sync';
import XLSX from 'xlsx';
import cors from 'cors';
import path from 'path';
import { DID } from 'dids';
import { Ed25519Provider } from 'key-did-provider-ed25519';
import { getResolver as keyDidResolver } from 'key-did-resolver';
import { Resolver } from 'did-resolver';
import { createVerifiableCredentialJwt, verifyCredential } from 'did-jwt-vc';
import { EdDSASigner } from 'did-jwt';
import { createJWS, verifyJWS } from 'did-jwt';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import fs from 'fs';
import qrcode from 'qrcode';
import { Pool } from 'pg';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
// bcrypt imported already above

dotenv.config();

// --- CONFIGURATION ---
const PORT = Number(process.env.PORT) || 3001;
const { PROVIDER_URL, SERVER_WALLET_PRIVATE_KEY, CONTRACT_ADDRESS, NEONDB_URL, KEY_ENCRYPTION_KEY, JWT_SECRET, OCRSPACE_API_KEY } = process.env;

// --- NeonDB Setup ---
const useDbSSL = (process.env.NEONDB_SSL || '').toLowerCase() === 'true'
    || (process.env.PGSSLMODE || '').toLowerCase() === 'require'
    || (NEONDB_URL || '').toLowerCase().includes('sslmode=require');

const pool = new Pool({
    connectionString: NEONDB_URL,
    ssl: useDbSSL ? { rejectUnauthorized: false } : undefined
});

// Test NeonDB connection on startup (only if URL provided)
if (NEONDB_URL) {
    pool.query('SELECT NOW()')
        .then(res => console.log('✅ NeonDB connected:', res.rows[0]))
        .catch(err => console.error('❌ NeonDB connection error:', err.message || err));
} else {
    console.warn('ℹ️ NEONDB_URL not set; running without database. Some endpoints will be unavailable.');
}

// Ensure DB schema exists
const ensureSchema = async () => {
    if (!NEONDB_URL) {
        console.warn('ℹ️ Skipping ensureSchema: NEONDB_URL not configured');
        return;
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`
            CREATE TABLE IF NOT EXISTS universities (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                provider_url TEXT NOT NULL,
                contract_address TEXT NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                public_address TEXT NOT NULL,
                force_password_change BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        // Create certificates table if it doesn't exist (fresh deployments)
        await client.query(`
            CREATE TABLE IF NOT EXISTS certificates (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                title TEXT NOT NULL,
                student_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                hash1 TEXT UNIQUE NOT NULL,
                hash2 TEXT UNIQUE NOT NULL,
                vc_jwt TEXT NOT NULL,
                university_id INTEGER REFERENCES universities(id),
                tx_hash TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS legacy_certificates (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                title TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                issued_on DATE,
                university_id INTEGER REFERENCES universities(id),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        // Extend legacy_certificates with integrity columns if missing
        await client.query(`
            ALTER TABLE legacy_certificates
            ADD COLUMN IF NOT EXISTS legacy_hash TEXT,
            ADD COLUMN IF NOT EXISTS hash_algo TEXT DEFAULT 'SHA256',
            ADD COLUMN IF NOT EXISTS canonical_version INT DEFAULT 1,
            ADD COLUMN IF NOT EXISTS did_signature TEXT,
            ADD COLUMN IF NOT EXISTS signed_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'imported';
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_legacy_hash ON legacy_certificates(legacy_hash);`);
        await client.query(`
            ALTER TABLE certificates
            ADD COLUMN IF NOT EXISTS university_id INTEGER REFERENCES universities(id),
            ADD COLUMN IF NOT EXISTS tx_hash TEXT;
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_certificates_hash2 ON certificates(hash2);
        `);
        // Admins table
        await client.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                active BOOLEAN NOT NULL DEFAULT TRUE
            );
        `);
        
        // Alerts table for invalid/forged attempts and other admin signals
        await client.query(`
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                details JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        // Ensure alerts sequence is aligned with current max(id)
        await client.query(`
            SELECT setval(
                pg_get_serial_sequence('alerts','id'),
                COALESCE((SELECT MAX(id) FROM alerts), 0),
                true
            );
        `);
        
        // Blacklist table for universities
        await client.query(`
            CREATE TABLE IF NOT EXISTS university_blacklist (
                id SERIAL PRIMARY KEY,
                uni_id INTEGER NOT NULL REFERENCES universities(id) ON DELETE CASCADE,
                reason TEXT,
                blacklisted_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_university_blacklist_uni_id ON university_blacklist(uni_id);`);
        // Ensure university_blacklist sequence is aligned with current max(id)
        await client.query(`
            SELECT setval(
                pg_get_serial_sequence('university_blacklist','id'),
                COALESCE((SELECT MAX(id) FROM university_blacklist), 0),
                true
            );
        `);
        await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_username ON admins(username);`);
        const existingAdmin = await client.query('SELECT id FROM admins LIMIT 1');
        if (!existingAdmin.rows.length) {
            const hash = await bcrypt.hash('Admin@123', 10);
            await client.query('INSERT INTO admins (username, password_hash, display_name) VALUES ($1,$2,$3)', ['superadmin', hash, 'System Administrator']);
            console.log('✅ Seeded default admin superadmin / Admin@123');
        }
        await client.query('COMMIT');
        console.log('✅ Schema ensured');
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('❌ Schema ensure error:', e);
    } finally {
        client.release();
    }
};

// --- BLOCKCHAIN SETUP ---
const contractABI = [
    {
        "inputs": [{ "internalType": "bytes32", "name": "_credentialId", "type": "bytes32" }],
        "name": "storeCredentialHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{ "internalType": "bytes32", "name": "", "type": "bytes32" }],
        "name": "isRevoked",
        "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }],
        "stateMutability": "view",
        "type": "function"
    }
];

let provider, wallet, contract;
try {
    if (PROVIDER_URL && SERVER_WALLET_PRIVATE_KEY && CONTRACT_ADDRESS) {
        provider = new ethers.JsonRpcProvider(PROVIDER_URL);
        wallet = new ethers.Wallet(SERVER_WALLET_PRIVATE_KEY, provider);
        contract = new ethers.Contract(CONTRACT_ADDRESS, contractABI, wallet);
    }
} catch (e) {
    console.warn('⚠️ Default blockchain setup skipped or failed:', e.message);
}

// In-memory DB (legacy placeholder)
const DB = { hashes_to_vcs: {} };

// Background jobs for bulk issuance
const JOBS = new Map();

// --- Alerts helper ---
function buildAlertMessage(type, details = {}) {
    try {
        switch (type) {
            case 'not_found':
                return `Hash not found: ${details.requestedHash || details.hash || 'unknown'}`;
            case 'not_found_pdf':
                return `PDF hash not found: ${details.hash2 ? String(details.hash2).slice(0, 10) + '…' : 'unknown'}`;
            case 'mismatch':
                return `Hash mismatch detected${details.university_id ? ` (uni ${details.university_id})` : ''}`;
            case 'revoked':
                return `Revoked certificate attempted${details.university_id ? ` (uni ${details.university_id})` : ''}`;
            case 'university_blacklisted':
                return `University blacklisted: ${details.university_name || details.university_id}`;
            default:
                return `Alert: ${type}`;
        }
    } catch {
        return `Alert: ${type}`;
    }
}

async function recordAlert(type, details) {
    try {
        if (!NEONDB_URL) return; // DB not configured; skip
        const payload = details && typeof details === 'object' ? details : (details || {});
        await pool.query('INSERT INTO alerts (type, details) VALUES ($1, $2)', [type, JSON.stringify(payload)]);
        // Try to broadcast if SSE is available
        try {
            if (typeof broadcastToAdmins === 'function') {
                const message = buildAlertMessage(type, payload);
                broadcastToAdmins({ type: 'alert', message, data: { type, details: payload }, ts: new Date().toISOString() });
            }
        } catch { /* noop */ }
    } catch (e) {
        console.error('⚠️ Failed to record alert:', type, e.message);
    }
}

// --- Auth helpers ---
const requireEnv = (k) => { if (!process.env[k]) throw new Error(`${k} not set`); return process.env[k]; };
const getJwtSecret = () => { if (!JWT_SECRET) throw new Error('JWT_SECRET not set'); return JWT_SECRET; };
const signToken = (payload) => jwt.sign(payload, getJwtSecret(), { expiresIn: '1d' });
const verifyToken = (token) => jwt.verify(token, getJwtSecret());

// --- Encryption helpers ---
const deriveAesKey = () => {
    if (!KEY_ENCRYPTION_KEY) throw new Error('KEY_ENCRYPTION_KEY not set');
    return crypto.createHash('sha256').update(KEY_ENCRYPTION_KEY).digest();
};
const encryptPrivateKey = (plainHexKey) => {
    const key = deriveAesKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(plainHexKey.replace(/^0x/, ''), 'hex');
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('base64')}:${enc.toString('base64')}:${tag.toString('base64')}`;
};
const decryptPrivateKey = (packed) => {
    const key = deriveAesKey();
    const [ivB64, encB64, tagB64] = packed.split(':');
    const iv = Buffer.from(ivB64, 'base64');
    const enc = Buffer.from(encB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return '0x' + dec.toString('hex');
};

// --- Auth middleware (supports Authorization header, query token, or cookie) ---
const auth = async (req, res, next) => {
    try {
        const hdr = req.headers.authorization || '';
        let token = null;
        if (hdr.startsWith('Bearer ')) token = hdr.slice(7).trim();
        if (!token && req.query && typeof req.query.token === 'string' && req.query.token.trim()) token = req.query.token.trim();
        if (!token && req.headers.cookie) {
            const found = req.headers.cookie.split(/;\s*/).find(c => c.startsWith('auth_token='));
            if (found) token = decodeURIComponent(found.split('=')[1] || '');
        }
        if (!token) return res.status(401).json({ error: 'missing_authorization_token' });
        if (!JWT_SECRET) return res.status(500).json({ error: 'server_jwt_secret_missing' });
        let decoded;
        try {
            decoded = verifyToken(token);
        } catch (e) {
            const msg = (e && e.name === 'TokenExpiredError') ? 'token_expired' : 'token_invalid';
            return res.status(401).json({ error: msg });
        }
        if (decoded && typeof decoded.universityId !== 'undefined') {
            req.universityId = decoded.universityId;
        }
        req.authPayload = decoded;
        next();
    } catch (e) {
        console.error('Auth middleware unexpected error:', e);
        return res.status(401).json({ error: 'auth_failure' });
    }
};

// --- Simple session store (prototype for role-based logins) ---


// --- University blockchain/DID context ---
const getUniversityContext = async (universityId) => {
    const { rows } = await pool.query(
        'SELECT id, name, provider_url, contract_address, encrypted_private_key FROM universities WHERE id = $1',
        [universityId]
    );
    if (!rows.length) throw new Error('University not found');
    const uni = rows[0];
    const privKey = decryptPrivateKey(uni.encrypted_private_key);
    const uniProvider = new ethers.JsonRpcProvider(uni.provider_url);
    const uniWallet = new ethers.Wallet(privKey, uniProvider);
    const uniContract = new ethers.Contract(uni.contract_address, contractABI, uniWallet);

    const seed = ethers.getBytes(privKey).slice(0, 32);
    const didProvider = new Ed25519Provider(seed);
    const did = new DID({ provider: didProvider, resolver: new Resolver({ ...keyDidResolver() }) });
    await did.authenticate();
    const uniIssuerObj = { did: did.id, signer: EdDSASigner(seed), alg: 'EdDSA' };

    return { uni, provider: uniProvider, wallet: uniWallet, contract: uniContract, issuerDid: did, issuerObj: uniIssuerObj };
};

// --- Optional chain debug helper (enabled when DEBUG_CHAIN env var is truthy) ---
function debugChain(ctx, phase, extra = {}) {
    if (!process.env.DEBUG_CHAIN) return;
    try {
        const payload = {
            phase,
            wallet: ctx?.wallet?.address,
            providerUrl: ctx?.uni?.provider_url,
            contract: ctx?.uni?.contract_address,
            ...extra,
            ts: new Date().toISOString()
        };
        console.log('[CHAIN_DEBUG]', JSON.stringify(payload));
    } catch (e) {
        console.log('[CHAIN_DEBUG_ERROR]', e.message);
    }
}

let issuerDid;
let issuerObj;

// --- PDF Generation (Node equivalent of the provided Python) ---
const generateCertificatePdf = async (data) => {
  const {
    university_name = 'University',
    student_name = 'Student Name',
    course_name = 'Course Name',
    degree_type = 'Certificate',
    graduation_year = new Date().getFullYear(),
    issue_date = new Date().toLocaleDateString(),
    student_id = 'N/A',
    subject_id = 'N/A',
    certificate_id = 'N/A',
    certificate_hash = '' // will be hash1 later
  } = data || {};

  const A4 = { width: 595, height: 842 };
  const margin = 50;
  
  // Colors matching the design
  const primaryBlue = rgb(0.2, 0.2, 0.6);
  const lightBlue = rgb(0.6, 0.8, 1.0);
  const darkText = rgb(0.2, 0.2, 0.2);
  const lightText = rgb(0.4, 0.4, 0.4);
  const white = rgb(1, 1, 1);

  const drawCentered = (page, font, text, size, y, color = darkText) => {
    const width = font.widthOfTextAtSize(text, size);
    const x = (A4.width - width) / 2;
    page.drawText(text, { x, y, size, font, color });
  };

  const drawRightAligned = (page, font, text, size, x, y, color = darkText) => {
    const width = font.widthOfTextAtSize(text, size);
    page.drawText(text, { x: x - width, y, size, font, color });
  };

  // 1) Build initial certificate without QR to compute hash1
  let doc = await PDFDocument.create();
  let page = doc.addPage([A4.width, A4.height]);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);

  // Background decorative elements
  // Top left decorative rectangle
  page.drawRectangle({
    x: 0,
    y: A4.height - 120,
    width: 120,
    height: 120,
    color: primaryBlue
  });

  // Bottom right decorative shapes
  page.drawRectangle({
    x: A4.width - 100,
    y: 0,
    width: 100,
    height: 100,
    color: lightBlue
  });

  page.drawRectangle({
    x: A4.width - 150,
    y: 50,
    width: 150,
    height: 100,
    color: primaryBlue
  });

  // Main certificate border
  const borderMargin = 30;
  page.drawRectangle({
    x: borderMargin,
    y: borderMargin,
    width: A4.width - (borderMargin * 2),
    height: A4.height - (borderMargin * 2),
    borderColor: darkText,
    borderWidth: 2
  });

  // Inner border
  const innerBorder = 35;
  page.drawRectangle({
    x: innerBorder,
    y: innerBorder,
    width: A4.width - (innerBorder * 2),
    height: A4.height - (innerBorder * 2),
    borderColor: lightText,
    borderWidth: 1
  });

  let y = A4.height - 100;

  // Certificate title
  drawCentered(page, bold, 'CERTIFICATE', 36, y, darkText);
  y -= 35;
  drawCentered(page, font, 'OF ACHIEVEMENT', 16, y, lightText);
  y -= 80;

  // Award text
  drawCentered(page, font, 'THIS CERTIFICATE IS AWARDED TO', 12, y, lightText);
  y -= 50;

  // Student name (prominent)
  drawCentered(page, bold, student_name.toUpperCase(), 28, y, darkText);
  y -= 60;

  // Description text
  const descriptionLines = [
    `Has successfully completed the requirements for`,
    `${degree_type} in`,
    `${course_name}`
  ];

  for (let i = 0; i < descriptionLines.length; i++) {
    const lineFont = i === 2 ? bold : font;
    const lineColor = i === 2 ? primaryBlue : darkText;
    drawCentered(page, lineFont, descriptionLines[i], 14, y, lineColor);
    y -= 25;
  }

  y -= 40;

  // Details section with better formatting
  const detailsStartY = y;
  const leftColumn = 80;
  const rightColumn = 320;
  const rowHeight = 20;

  const leftDetails = [
    ['PRN:', String(student_id)],
    ['Subject ID:', String(subject_id)]
  ];

  const rightDetails = [
    ['Name:', String(student_name)],
    ['Course:', String(course_name)]
  ];

  // Draw left column
  for (let i = 0; i < leftDetails.length; i++) {
    const [label, value] = leftDetails[i];
    page.drawText(label, { 
      x: leftColumn, 
      y: detailsStartY - (i * rowHeight), 
      size: 10, 
      font: bold, 
      color: lightText 
    });
    page.drawText(value, { 
      x: leftColumn + 70, 
      y: detailsStartY - (i * rowHeight), 
      size: 10, 
      font, 
      color: darkText 
    });
  }

  // Draw right column
  for (let i = 0; i < rightDetails.length; i++) {
    const [label, value] = rightDetails[i];
    page.drawText(label, { 
      x: rightColumn, 
      y: detailsStartY - (i * rowHeight), 
      size: 10, 
      font: bold, 
      color: lightText 
    });
    page.drawText(value, { 
      x: rightColumn + 50, 
      y: detailsStartY - (i * rowHeight), 
      size: 10, 
      font, 
      color: darkText 
    });
  }

  y -= 80;



  // Outer circle


//   added

  // Signatures section
  const sigLeftX = 120;
  const sigRightX = A4.width - 200;
  const sigY = y;
  const sigWidth = 120;

  // Left signature
  page.drawLine({
    start: { x: sigLeftX, y: sigY },
    end: { x: sigLeftX + sigWidth, y: sigY },
    thickness: 1,
    color: darkText
  });

  page.drawText('AUTHORIZED SIGNATURE', {
    x: sigLeftX + 10,
    y: sigY - 15,
    size: 8,
    font,
    color: lightText
  });

  page.drawText('Founder', {
    x: sigLeftX + 10,
    y: sigY - 28,
    size: 10,
    font: bold,
    color: darkText
  });

  // Right signature
  page.drawLine({
    start: { x: sigRightX, y: sigY },
    end: { x: sigRightX + sigWidth, y: sigY },
    thickness: 1,
    color: darkText
  });

  page.drawText('DATE', {
    x: sigRightX + 10,
    y: sigY - 15,
    size: 8,
    font,
    color: lightText
  });

  page.drawText(String(issue_date), {
    x: sigRightX + 10,
    y: sigY - 28,
    size: 10,
    font: bold,
    color: darkText
  });

  const preQrBuffer = await doc.save();

  // 2) Reload and embed QR with explanatory text, using provided or computed hash
  const doc2 = await PDFDocument.load(preQrBuffer);
  const page2 = doc2.getPages()[0];
  const font2 = await doc2.embedFont(StandardFonts.Helvetica);
  const bold2 = await doc2.embedFont(StandardFonts.HelveticaBold);

  // QR area (bottom left)
  const qrSize = 80;
  const qrX = 60;
  const qrY = 60;

  // Embed QR with hash1 (passed via certificate_hash)
  const hashInQr = data.certificate_hash;
  if (hashInQr) {
    const baseUrl = process.env.PUBLIC_BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
    const verifyUrl = `${baseUrl}/certificate-details.html?hash=${hashInQr}`;
    const qrDataUrl = await qrcode.toDataURL(verifyUrl);
    const qrBytes = Buffer.from(qrDataUrl.split(',')[1], 'base64');
    const qrImg = await doc2.embedPng(qrBytes);

    page2.drawImage(qrImg, {
      x: qrX,
      y: qrY,
      width: qrSize,
      height: qrSize
    });

    // QR info text
    const infoX = qrX + qrSize + 15;
    const infoY = qrY + qrSize - 10;

    const lines = [
      'Blockchain Verification',
      '',
      'Scan this QR code to verify',
      'this certificate on the blockchain.',
      '',
      `Hash: ${hashInQr.slice(0, 16)}...`
    ];

    let ty = infoY;
    for (const [idx, line] of lines.entries()) {
      const f = idx === 0 ? bold2 : font2;
      const s = idx === 0 ? 11 : 9;
      const c = idx === 0 ? primaryBlue : (idx === lines.length - 1 ? lightText : darkText);
      
      page2.drawText(line, {
        x: infoX,
        y: ty,
        size: s,
        font: f,
        color: c
      });
      ty -= (idx === 0 ? 16 : 12);
    }
  }

  const postQrBuffer = await doc2.save();
  return { preQrBuffer, postQrBuffer };
};

// --- SERVER & MIDDLEWARE ---
const app = express();
app.disable('x-powered-by');
app.use(cors());
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false // front-end inline styles/scripts currently in use
}));

// Minimal additional security header hardening (after helmet customization above)
app.use((req, res, next) => {
    // Prevent sniffing & clickjacking basic protections (helmet covers most, but explicit here)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    // Remove any accidental server disclosure headers if proxies added them
    ['Server', 'X-Powered-By'].forEach(h => {
        if (res.getHeader(h)) res.removeHeader(h);
    });
    next();
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Protected static pages mapping
// Serve protected dashboards via explicit routes only (files removed from /public)
// HTML-aware auth: redirects to login instead of JSON when no/invalid token
const pageAuth = (requiredRole) => async (req, res, next) => {
    try {
        const hdr = req.headers.authorization || '';
        let token = null;
        if (hdr.startsWith('Bearer ')) token = hdr.slice(7).trim();
        if (!token && req.headers.cookie) {
            const found = req.headers.cookie.split(/;\s*/).find(c => c.startsWith('auth_token='));
            if (found) token = decodeURIComponent(found.split('=')[1] || '');
        }
        if (!token) return res.redirect('/login.html');
        let decoded;
        try {
            decoded = verifyToken(token);
        } catch {
            return res.redirect('/login.html');
        }
        req.authPayload = decoded;
        if (requiredRole && decoded.role !== requiredRole) {
            // If logged in with wrong role, keep 403 to signal forbidden rather than looping redirect
            return res.status(403).send('Forbidden');
        }
        next();
    } catch {
        return res.redirect('/login.html');
    }
};

app.get('/admin-dashboard.html', pageAuth('admin'), (req, res) => {
    return res.sendFile(path.join(__dirname, 'protected', 'admin-dashboard.html'));
});
app.get('/university-dashboard.html', pageAuth('university'), (req, res) => {
    return res.sendFile(path.join(__dirname, 'protected', 'university-dashboard.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// Serve home page as entry point (change from redirect to login)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check for Render
app.get('/healthz', (req, res) => {
    res.status(200).json({ ok: true });
});

const upload = multer({ storage: multer.memoryStorage() });

// --- BLOCKCHAIN & DID SETUP ---
const setupIssuer = async () => {
    if (!SERVER_WALLET_PRIVATE_KEY) {
        console.log('ℹ️ No default server private key set; per-university login will provide issuers.');
        return;
    }

    const privateKey = SERVER_WALLET_PRIVATE_KEY.startsWith('0x')
        ? SERVER_WALLET_PRIVATE_KEY
        : '0x' + SERVER_WALLET_PRIVATE_KEY;

    // Ed25519 requires 32-byte seed
    const seed = ethers.getBytes(privateKey).slice(0, 32);

    // Create DID
    const provider = new Ed25519Provider(seed);
    const did = new DID({ provider, resolver: new Resolver({ ...keyDidResolver() }) });
    await did.authenticate();

    issuerDid = did;

    // Proper signer for did-jwt
    issuerObj = {
        did: issuerDid.id,
        signer: EdDSASigner(seed),
        alg: 'EdDSA'
    };

    console.log(`✅ Issuer DID successfully created: ${issuerDid.id}`);
};

const SESSIONS = new Map(); // retained for potential admin session tracking (legacy)

// Central helper to set auth cookie with hardened attributes
function setAuthCookie(res, token) {
    // 24h in seconds
    const maxAge = 86400;
    const isProd = process.env.NODE_ENV === 'production';
    // Always HttpOnly, Strict to mitigate CSRF, Secure only in production (so local dev over http still works)
    const parts = [
        `auth_token=${encodeURIComponent(token)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Strict',
        `Max-Age=${maxAge}`
    ];
    if (isProd) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
}

function clearAuthCookie(res) {
    const isProd = process.env.NODE_ENV === 'production';
    const parts = [
        'auth_token=',
        'Path=/',
        'HttpOnly',
        'SameSite=Strict',
        'Max-Age=0'
    ];
    if (isProd) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
}

// Unified login for admin & university (hardened cookie-based session, no token in body)
app.post('/auth/login', express.json(), async (req, res) => {
    try {
        const { role, username, email, password } = req.body || {};
        if (!role || !password) return res.status(400).json({ error: 'role and password required' });
        let responsePayload = null;
        if (role === 'admin') {
            if (!username) return res.status(400).json({ error: 'username required' });
            const q = await pool.query('SELECT * FROM admins WHERE LOWER(username)=LOWER($1) AND active=TRUE LIMIT 1', [username]);
            if (!q.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
            const admin = q.rows[0];
            const ok = await bcrypt.compare(password, admin.password_hash);
            if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
            const token = signToken({ role: 'admin', adminId: admin.id });
            setAuthCookie(res, token);
            responsePayload = { role: 'admin', admin: { id: admin.id, username: admin.username, display_name: admin.display_name } };
        } else if (role === 'university') {
            if (!email) return res.status(400).json({ error: 'email required' });
            const q = await pool.query('SELECT * FROM universities WHERE LOWER(email)=LOWER($1) LIMIT 1', [email]);
            if (!q.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
            const uni = q.rows[0];
            if (!uni.password_hash) return res.status(500).json({ error: 'University account misconfigured' });
            const ok = await bcrypt.compare(password, uni.password_hash);
            if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
            const token = signToken({ role: 'university', universityId: uni.id });
            setAuthCookie(res, token);
            responsePayload = { role: 'university', university: { id: uni.id, email: uni.email, name: uni.name, public_address: uni.public_address, forcePasswordChange: !!uni.force_password_change } };
        } else {
            return res.status(400).json({ error: 'unsupported role' });
        }
        // Prevent caching of auth-bearing response
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        // Front-end (login.html) expects data.token always; include it even if cookie mode.
        // We retain the httpOnly cookie for security but also return the token for legacy localStorage usage.
        const cookieHeader = res.getHeader('Set-Cookie');
        if (!responsePayload.token) {
            let tokenFromCookie = null;
            if (cookieHeader) {
                const headerStr = Array.isArray(cookieHeader) ? cookieHeader.join('\n') : String(cookieHeader);
                const m = headerStr.match(/auth_token=([^;]+)/);
                if (m) tokenFromCookie = decodeURIComponent(m[1]);
            }
            // Best effort: token may have been generated above when signing
            if (!tokenFromCookie && typeof signToken === 'function') {
                // Re-sign minimal payload if missing (should not normally happen)
                try {
                    if (responsePayload.role === 'university' && responsePayload.university?.id) {
                        tokenFromCookie = signToken({ role: 'university', universityId: responsePayload.university.id });
                    } else if (responsePayload.role === 'admin' && responsePayload.admin?.id) {
                        tokenFromCookie = signToken({ role: 'admin', adminId: responsePayload.admin.id });
                    }
                } catch { /* no-op */ }
            }
            if (tokenFromCookie) responsePayload.token = tokenFromCookie;
        }
        return res.json(responsePayload);
    } catch (e) {
        console.error('Login error', e);
        return res.status(500).json({ error: 'Login failed' });
    }
});
// --- ADMIN: Register University ---
app.post('/admin/universities/register', express.json(), async (req, res) => {
    try {
        let { name, email } = req.body || {};
        if (!name || !email) {
            return res.status(400).json({ error: 'name and email are required' });
        }
        const password = crypto.randomBytes(12).toString('base64');
        const provider_url = process.env.PROVIDER_URL;
        const contract_address = process.env.CONTRACT_ADDRESS;
        if (!provider_url || !contract_address) {
            return res.status(400).json({ error: 'provider_url/contract_address missing and no defaults configured' });
        }
        const generated = ethers.Wallet.createRandom();
        const wallet_private_key = generated.privateKey;
        const passHash = await bcrypt.hash(password, 10);
        const encrypted = encryptPrivateKey(wallet_private_key);
        const pub = generated.address;
        const result = await pool.query(
            'INSERT INTO universities (name, email, password_hash, provider_url, contract_address, encrypted_private_key, public_address, force_password_change) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, provider_url = EXCLUDED.provider_url, contract_address = EXCLUDED.contract_address, encrypted_private_key = EXCLUDED.encrypted_private_key, public_address = EXCLUDED.public_address, force_password_change = TRUE RETURNING id, public_address, contract_address',
            [name, email, passHash, provider_url, contract_address, encrypted, pub, true]
        );
        try {
            broadcastToAdmins({
                type: 'university_created',
                message: `New institution registered: ${name}`,
                data: { id: result.rows[0].id, name, email },
                ts: new Date().toISOString()
            });
        } catch {}
        res.status(200).json({
            id: result.rows[0].id,
            email,
            password,
            publicAddress: result.rows[0].public_address,
            contractAddress: result.rows[0].contract_address
        });
    } catch (e) {
        console.error('❌ Admin university register error:', e);
        res.status(500).json({ error: 'Admin registration failed' });
    }
});

app.get('/verify/:hash', async (req, res) => {
    try {
        const givenHash = req.params.hash;
        // Join with universities to fetch university name
        let rows = (await pool.query(
            `SELECT c.vc_jwt, c.university_id, u.name AS university_name, c.name, c.title, c.student_id, c.subject_id, c.hash1, c.hash2, c.tx_hash
             FROM certificates c
             JOIN universities u ON c.university_id = u.id
             WHERE c.hash1 = $1`,
            [givenHash]
        )).rows;
        let matchedBy = 'hash1';
        if (!rows.length) {
            rows = (await pool.query(
                `SELECT c.vc_jwt, c.university_id, u.name AS university_name, c.name, c.title, c.student_id, c.subject_id, c.hash1, c.hash2, c.tx_hash
                 FROM certificates c
                 JOIN universities u ON c.university_id = u.id
                 WHERE c.hash2 = $1`,
                [givenHash]
            )).rows;
            matchedBy = 'hash2';
        }
        if (!rows.length) {
            await recordAlert('not_found', { requestedHash: givenHash });
            return res.status(404).json({ error: 'Certificate not found or altered.' });
        }

        const record = rows[0];
        const vcJwt = record.vc_jwt;
    const resolver = new Resolver({ ...keyDidResolver() });

        let subject = {}, vcHash1 = null, vcHash2 = null;
        let credentialStatus = null;
        try {
            const verifiedVc = await verifyCredential(vcJwt, resolver);
            subject = verifiedVc?.verifiableCredential?.credentialSubject || {};
            vcHash1 = subject.hash1;
            vcHash2 = subject.hash2;
            credentialStatus = verifiedVc?.verifiableCredential?.credentialStatus || null;
        } catch (e) {
            // ignore VC verification errors; still show DB info
        }

        const dbHash1 = record.hash1;
        const dbHash2 = record.hash2;
        const vcHash1MatchesDB = !!vcHash1 && vcHash1 === dbHash1;
        const vcHash2MatchesDB = !!vcHash2 && vcHash2 === dbHash2;

        let isRevoked = false;
        let contractAddress = null;
        try {
            const ctx = await getUniversityContext(Number(record.university_id));
            contractAddress = ctx.uni.contract_address;
            isRevoked = await ctx.contract.isRevoked(dbHash2);
        } catch { }

        const isConsistent = vcHash1MatchesDB && vcHash2MatchesDB;
        const statusMsg = isRevoked
            ? '❌ Certificate is revoked on blockchain.'
            : (isConsistent ? '✅ Certificate is authentic and consistent.' : '⚠️ Credential verified, but hashes are inconsistent.');

        // Record security-relevant alerts
        try {
            if (isRevoked) {
                await recordAlert('revoked', { hash2: dbHash2, university_id: record.university_id });
            } else if (!isConsistent) {
                await recordAlert('mismatch', { dbHash1, dbHash2, vcHash1, vcHash2, university_id: record.university_id });
            }
        } catch { /* ignore */ }

        res.json({
            isValid: !isRevoked && isConsistent,
            statusMsg,
            matchedBy,
            name: record.name,
            prn: record.student_id,
            title: record.title,
            subject_id: record.subject_id,
            university_id: record.university_id,
            university_name: record.university_name,
            hash1: dbHash1,
            hash2: dbHash2,
            vcJwt,
            credentialSubject: subject,
            credentialStatus,
            vcHash1MatchesDB,
            vcHash2MatchesDB,
            isRevoked,
            contractAddress,
            txHash: record.tx_hash || null,
            requestedHash: givenHash
        });
    } catch (err) {
        res.status(500).json({ error: 'Verification failed. Please try again later.' });
    }
});
// --- University Registration ---
app.post('/universities/register', express.json(), async (req, res) => {
    try {
        let { name, email, password, provider_url, contract_address, wallet_private_key } = req.body || {};
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'name, email, password are required' });
        }
        // Default to global chain config if not provided
        provider_url = provider_url || process.env.PROVIDER_URL;
        contract_address = contract_address || process.env.CONTRACT_ADDRESS;
        if (!provider_url || !contract_address) {
            return res.status(400).json({ error: 'provider_url/contract_address missing and no defaults configured' });
        }
        // Generate a server-side wallet if none provided
        if (!wallet_private_key) {
            const generated = ethers.Wallet.createRandom();
            wallet_private_key = generated.privateKey; // 0x-prefixed
        }
        const passHash = await bcrypt.hash(password, 10);
        const encrypted = encryptPrivateKey(wallet_private_key);
        const pub = new ethers.Wallet(wallet_private_key).address;
        const result = await pool.query(
            'INSERT INTO universities (name, email, password_hash, provider_url, contract_address, encrypted_private_key, public_address) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, provider_url = EXCLUDED.provider_url, contract_address = EXCLUDED.contract_address, encrypted_private_key = EXCLUDED.encrypted_private_key, public_address = EXCLUDED.public_address RETURNING id, public_address, contract_address',
            [name, email, passHash, provider_url, contract_address, encrypted, pub]
        );
        res.status(200).json({ id: result.rows[0].id, publicAddress: result.rows[0].public_address, contractAddress: result.rows[0].contract_address });
    } catch (e) {
        console.error('❌ University register error:', e);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// --- University Login ---
app.post('/universities/login', express.json(), async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) return res.status(400).json({ error: 'email and password required' });
        const { rows } = await pool.query('SELECT id, password_hash, name, public_address, contract_address, force_password_change FROM universities WHERE email = $1', [email]);
        if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
        const uni = rows[0];
        const ok = await bcrypt.compare(password, uni.password_hash);
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
        const token = signToken({ universityId: uni.id });
        res.status(200).json({
            token,
            university: {
                id: uni.id,
                name: uni.name,
                publicAddress: uni.public_address,
                contractAddress: uni.contract_address,
                forcePasswordChange: !!uni.force_password_change
            }
        });
    } catch (e) {
        console.error('❌ Login error:', e);
        res.status(500).json({ error: 'Login failed' });
    }
});

// --- University Change Password ---
app.post('/universities/change-password', auth, express.json(), async (req, res) => {
    try {
        const university_id = req.universityId;
        const { newPassword } = req.body || {};
        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters.' });
        }
        const passHash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE universities SET password_hash = $1, force_password_change = FALSE WHERE id = $2', [passHash, university_id]);
        res.status(200).json({ success: true });
    } catch (e) {
        console.error('❌ Change password error:', e);
        res.status(500).json({ error: 'Password change failed' });
    }
});

// --- University Wallet Balance ---
app.get('/universities/me/balance', auth, async (req, res) => {
    try {
        const university_id = req.universityId;
        const ctx = await getUniversityContext(Number(university_id));
        const wei = await ctx.provider.getBalance(ctx.wallet.address);
        const ether = ethers.formatEther(wei);
        // Optionally include network information
        let network = null;
        try { network = await ctx.provider.getNetwork(); } catch { }
        res.status(200).json({
            address: ctx.wallet.address,
            balanceWei: wei.toString(),
            balanceEther: ether,
            network: network ? { chainId: Number(network.chainId), name: network.name } : null
        });
    } catch (e) {
        console.error('❌ Fetch balance error:', e);
        res.status(500).json({ error: 'Failed to fetch balance' });
    }
});

// --- University Chain Context (diagnostic) ---
app.get('/universities/me/chain-context', auth, async (req, res) => {
    try {
        const university_id = req.universityId;
        const ctx = await getUniversityContext(Number(university_id));
        const [balance, nonce, network, latestCerts] = await Promise.all([
            ctx.provider.getBalance(ctx.wallet.address),
            ctx.provider.getTransactionCount(ctx.wallet.address),
            ctx.provider.getNetwork().catch(() => null),
            pool.query('SELECT id, hash2, tx_hash, created_at FROM certificates WHERE university_id=$1 ORDER BY id DESC LIMIT 5', [Number(university_id)])
        ]);
        res.json({
            walletAddress: ctx.wallet.address,
            providerUrl: ctx.uni.provider_url,
            contractAddress: ctx.uni.contract_address,
            balanceWei: balance.toString(),
            balanceEther: ethers.formatEther(balance),
            nonce,
            network: network ? { chainId: Number(network.chainId), name: network.name } : null,
            recentCertificates: latestCerts.rows
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch chain context', detail: e.message });
    }
});

// --- API ENDPOINT: ISSUE CREDENTIAL ---
app.post('/issue', auth, upload.single('base_pdf'), async (req, res) => {
    try {
        const { prn_number, name, title, subject_id } = req.body;
        const university_id = req.universityId;
        const ctx = await getUniversityContext(Number(university_id));
        debugChain(ctx, 'issue_start', {});

        // Build PDF without QR to compute hash1, then add QR and compute hash2
        const pre = await generateCertificatePdf({
            university_name: ctx.uni.name,
            student_name: name,
            course_name: title,
            subject_id,
            degree_type: 'Certificate',
            graduation_year: new Date().getFullYear(),
            issue_date: new Date().toLocaleDateString(),
            student_id: prn_number,
            certificate_id: 'N/A',
            certificate_hash: ''
        });
        const hash1 = ethers.sha256(pre.preQrBuffer);
        // Build final PDF embedding hash1 in the QR
        const post = await generateCertificatePdf({
            university_name: ctx.uni.name,
            student_name: name,
            course_name: title,
            subject_id,
            degree_type: 'Certificate',
            graduation_year: new Date().getFullYear(),
            issue_date: new Date().toLocaleDateString(),
            student_id: prn_number,
            certificate_id: 'N/A',
            certificate_hash: hash1
        });
        const hash2 = ethers.sha256(post.postQrBuffer);
        const finalPdfBuffer = post.postQrBuffer;

        // 7. Create VC payload
        const vcPayload = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'AcademicCertificate'],
            issuer: { id: ctx.issuerDid.id },
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
                id: `urn:prn:${prn_number}`,
                name,
                title,
                subject_id,
                hash1,
                hash2,
            },
        };
        const vcJwt = await createVerifiableCredentialJwt(vcPayload, ctx.issuerObj);

        // 8. Store hash2 on blockchain
        let blockchainStatus = 'pending';
        let txHash = null;
        try {
            const preBal = await ctx.provider.getBalance(ctx.wallet.address);
            const preNonce = await ctx.provider.getTransactionCount(ctx.wallet.address);
            debugChain(ctx, 'tx_before_send', { preBalanceWei: preBal.toString(), preNonce, hash2 });
            const tx = await ctx.contract.storeCredentialHash(hash2);
            txHash = tx.hash || null;
            debugChain(ctx, 'tx_submitted', { txHash, gasLimit: tx.gasLimit ? tx.gasLimit.toString() : undefined });
            const receipt = await tx.wait();
            const postBal = await ctx.provider.getBalance(ctx.wallet.address);
            const gasUsed = receipt?.gasUsed ? receipt.gasUsed.toString() : null;
            const effGasPrice = receipt?.effectiveGasPrice ? receipt.effectiveGasPrice.toString() : null;
            let gasCostWei = null;
            try { if (gasUsed && effGasPrice) gasCostWei = (BigInt(gasUsed) * BigInt(effGasPrice)).toString(); } catch {}
            blockchainStatus = 'stored';
            txHash = txHash || (receipt && receipt.transactionHash) || null;
            debugChain(ctx, 'tx_mined', { txHash, gasUsed, effGasPrice, gasCostWei, postBalanceWei: postBal.toString(), balanceDeltaWei: (preBal - postBal).toString() });
            console.log(`✅ Hash stored on blockchain: ${hash2} (tx: ${txHash})`);
        } catch (err) {
            blockchainStatus = 'error';
            debugChain(ctx, 'tx_error', { error: err.message, stack: err.stack });
            console.error('Blockchain storage error:', err);
        }

        // 9. Save to NeonDB
        try {
            await pool.query(
                'INSERT INTO certificates (name, title, student_id, subject_id, hash1, hash2, vc_jwt, university_id, tx_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
                [name, title, prn_number, subject_id, hash1, hash2, vcJwt, Number(university_id), txHash]
            );
            // Broadcast live certificate issuance to dashboards
            try {
                const uniRow = await pool.query('SELECT name FROM universities WHERE id=$1', [Number(university_id)]);
                const uniName = uniRow.rows[0]?.name || 'University';
                broadcastToAdmins({
                    type: 'certificate_issued',
                    message: `New certificate issued: "${title}" for ${name} by ${uniName}`,
                    data: { name, title, university_id: Number(university_id), hash2 },
                    ts: new Date().toISOString()
                });
            } catch {}
        } catch (err) {
            console.error('NeonDB insert error:', err);
        }

        // 10. Respond
        if (req.headers.accept && req.headers.accept.includes('application/json')) {
            const pdfBufferNode = Buffer.from(finalPdfBuffer);
            const pdfBase64 = pdfBufferNode.toString('base64');
            const pdfFileName = `certificate-${prn_number || 'issued'}.pdf`;
            res.status(200).json({
                vcJwt,
                blockchainStatus,
                hash1,
                hash2,
                txHash,
                universityId: Number(university_id),
                pdfBase64,
                pdfContentType: 'application/pdf',
                pdfFileName
            });
        } else {
            res.setHeader('Content-Disposition', 'attachment; filename=certificate-signed.pdf');
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('x-vc-jwt', vcJwt);
            res.setHeader('x-blockchain-status', blockchainStatus);
            res.send(Buffer.from(finalPdfBuffer));
        }
    } catch (error) {
        console.error('❌ Issuance Error:', error);
        res.status(500).json({ error: 'Failed to issue certificate.' });
    }
});

// --- Helpers for bulk parsing and job processing ---
const parseBulkFile = (file) => {
    const filename = file.originalname.toLowerCase();
    if (filename.endsWith('.csv')) {
        const text = file.buffer.toString('utf8');
        return csvParse(text, { columns: true, skip_empty_lines: true, trim: true });
    }
    if (filename.endsWith('.xlsx') || filename.endsWith('.xls')) {
        const wb = XLSX.read(file.buffer, { type: 'buffer' });
        const sheetName = wb.SheetNames[0];
        return XLSX.utils.sheet_to_json(wb.Sheets[sheetName], { defval: '' });
    }
    throw new Error('Unsupported file type. Upload .csv or .xlsx');
};

const processBulkJob = async (job) => {
    try {
        const { universityId, rows } = job;
        const ctx = await getUniversityContext(Number(universityId));

        const outDir = path.join(__dirname, 'jobs');
        try { fs.mkdirSync(outDir, { recursive: true }); } catch { }
        const zipPath = path.join(outDir, `${job.id}.zip`);

        const output = fs.createWriteStream(zipPath);
        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.pipe(output);
        archive.on('error', err => { throw err; });

        const summary = [];

        for (let i = 0; i < rows.length; i++) {
            job.current = i + 1;
            const row = rows[i];
            const prn_number = String(row.prn_number || '').trim();
            const name = String(row.name || '').trim();
            const title = String(row.title || '').trim();
            const subject_id = String(row.subject_id || '').trim();
            const entry = { index: i, prn_number, name, title, subject_id };
            try {
                if (!prn_number || !name || !title || !subject_id) throw new Error('Missing required fields');

                const pre = await generateCertificatePdf({
                    university_name: ctx.uni.name,
                    student_name: name,
                    course_name: title,
                    subject_id,
                    degree_type: 'Certificate',
                    graduation_year: new Date().getFullYear(),
                    issue_date: new Date().toLocaleDateString(),
                    student_id: prn_number,
                    certificate_id: 'N/A',
                    certificate_hash: ''
                });
                const hash1 = ethers.sha256(pre.preQrBuffer);
                const post = await generateCertificatePdf({
                    university_name: ctx.uni.name,
                    student_name: name,
                    course_name: title,
                    subject_id,
                    degree_type: 'Certificate',
                    graduation_year: new Date().getFullYear(),
                    issue_date: new Date().toLocaleDateString(),
                    student_id: prn_number,
                    certificate_id: 'N/A',
                    certificate_hash: hash1
                });
                const finalPdfBuffer = post.postQrBuffer;
                const hash2 = ethers.sha256(finalPdfBuffer);

                const vcPayload = {
                    '@context': ['https://www.w3.org/2018/credentials/v1'],
                    type: ['VerifiableCredential', 'AcademicCertificate'],
                    issuer: { id: ctx.issuerDid.id },
                    issuanceDate: new Date().toISOString(),
                    credentialSubject: { id: `urn:prn:${prn_number}`, name, title, subject_id, hash1, hash2 },
                };
                const vcJwt = await createVerifiableCredentialJwt(vcPayload, ctx.issuerObj);

                let txHash = null;
                try {
                    const tx = await ctx.contract.storeCredentialHash(hash2);
                    const receipt = await tx.wait();
                    txHash = tx.hash || (receipt && receipt.transactionHash) || null;
                } catch (e) {
                    entry.blockchainError = e.message;
                }

                try {
                    await pool.query(
                        'INSERT INTO certificates (name, title, student_id, subject_id, hash1, hash2, vc_jwt, university_id, tx_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
                        [name, title, prn_number, subject_id, hash1, hash2, vcJwt, Number(universityId), txHash]
                    );
                } catch (e) {
                    entry.dbError = e.message;
                }

                archive.append(Buffer.from(finalPdfBuffer), { name: `certificate-${prn_number || 'issued'}.pdf` });

                Object.assign(entry, { hash1, hash2, txHash, status: 'ok' });
            } catch (e) {
                entry.status = 'error';
                entry.error = e.message;
            }
            summary.push(entry);
        }

        archive.append(Buffer.from(JSON.stringify(summary, null, 2)), { name: 'summary.json' });
        const csvHeader = 'index,prn_number,name,title,subject_id,hash1,hash2,txHash,status,error,blockchainError,dbError\n';
        const csvLines = summary.map(s => [s.index, s.prn_number, s.name, s.title, s.subject_id, s.hash1, s.hash2, s.txHash, s.status, s.error, s.blockchainError, s.dbError]
            .map(v => v == null ? '' : String(v).replaceAll('"', '""'))
            .map(v => /[",\n]/.test(v) ? `"${v}"` : v)
            .join(','));
        archive.append(Buffer.from(csvHeader + csvLines.join('\n')), { name: 'summary.csv' });

        await archive.finalize();
        await new Promise((resolve, reject) => {
            output.on('close', resolve);
            output.on('error', reject);
        });

        job.status = 'completed';
        job.zipPath = zipPath;
        job.finishedAt = Date.now();
    } catch (e) {
        job.status = 'failed';
        job.error = e.message;
    }
};

// --- LEGACY CERTIFICATES: CSV Upload (name,title,subject_id,issued_on) ---
function normalizeLegacyDate(input) {
    const s = String(input || '').trim();
    if (!s) return '';
    // ISO yyyy-mm-dd
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
        const d = new Date(s + 'T00:00:00Z');
        if (!Number.isNaN(d.getTime())) return s;
    }
    // dd-mm-yyyy or dd/mm/yyyy or dd.mm.yyyy
    const m = s.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{4})$/);
    if (m) {
        const dd = m[1].padStart(2, '0');
        const mm = m[2].padStart(2, '0');
        const yyyy = m[3];
        const iso = `${yyyy}-${mm}-${dd}`;
        const d = new Date(iso + 'T00:00:00Z');
        if (!Number.isNaN(d.getTime())) return iso;
    }
    throw new Error(`Invalid date: ${s}`);
}

function parseLegacyCsv(buffer) {
    const text = buffer.toString('utf8');
    const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
    if (!lines.length) return { headers: [], rows: [] };
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/\s+/g, '_'));
    const required = ['name', 'title', 'subject_id', 'issued_on'];
    for (const r of required) if (!headers.includes(r)) throw new Error('Missing required header: ' + r);
    const idx = Object.fromEntries(headers.map((h, i) => [h, i]));
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].split(',');
        if (!cols.length) continue;
        const issuedRaw = (cols[idx.issued_on] || '').trim();
        let issued_on = '';
        if (issuedRaw) {
            try {
                issued_on = normalizeLegacyDate(issuedRaw);
            } catch (e) {
                throw new Error(`Invalid issued_on "${issuedRaw}" on row ${i + 1}. Use YYYY-MM-DD or DD-MM-YYYY/DD/MM/YYYY.`);
            }
        }
        const row = {
            name: (cols[idx.name] || '').trim(),
            title: (cols[idx.title] || '').trim(),
            subject_id: (cols[idx.subject_id] || '').trim(),
            issued_on
        };
        if (!(row.name || row.title || row.subject_id)) continue;
        rows.push(row);
    }
    return { headers, rows };
}

// ---- Legacy Hash & Signing Helpers ----
const LEGACY_CANONICAL_VERSION = 1;
function canonicalizeLegacyRow(row) {
    const name = (row.name || '').trim();
    const title = (row.title || '').trim();
    const subject_id = (row.subject_id || '').trim();
    const issued_on = row.issued_on ? new Date(row.issued_on).toISOString().slice(0, 10) : '';
    const university_id = row.university_id;
    const canonical = [
        `name:${name}`,
        `title:${title}`,
        `subject_id:${subject_id}`,
        `issued_on:${issued_on}`,
        `university_id:${university_id}`
    ].join('\n');
    const hash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
    return { canonical, hash };
}

async function signLegacyHash(universityId, hash) {
    const { issuerObj } = await getUniversityContext(universityId);
    const payload = { h: hash, t: new Date().toISOString(), v: LEGACY_CANONICAL_VERSION };
    const jws = await createJWS(payload, issuerObj.signer, { did: issuerObj.did, alg: 'EdDSA' });
    return jws;
}

async function verifyLegacySignature(universityId, hash, jws) {
    try {
        if (!jws) return false;
    const resolver = new Resolver({ ...keyDidResolver() });
    const verified = await verifyJWS(jws, { resolver });
        if (!verified || !verified.payload) return false;
        return verified.payload.h === hash;
    } catch (e) {
        return false;
    }
}

app.post('/legacy/preview', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const parsed = parseLegacyCsv(req.file.buffer);
        res.json({ total: parsed.rows.length, sample: parsed.rows.slice(0, 25) });
    } catch (e) {
        res.status(400).json({ error: e.message || 'Failed to parse CSV' });
    }
});

app.post('/legacy/deploy', auth, upload.single('file'), async (req, res) => {
    const client = await pool.connect();
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const parsed = parseLegacyCsv(req.file.buffer);
        const university_id = req.universityId;
        await client.query('BEGIN');
        let inserted = 0;
        for (const r of parsed.rows) {
            await client.query(
                'INSERT INTO legacy_certificates (name,title,subject_id,issued_on,university_id) VALUES ($1,$2,$3,$4,$5)',
                [r.name, r.title, r.subject_id, r.issued_on || null, university_id]
            );
            inserted++;
        }
        await client.query('COMMIT');
        res.json({ inserted, total: parsed.rows.length });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: e.message || 'Failed to deploy legacy certificates' });
    } finally {
        client.release();
    }
});

// --- LEGACY: Backfill missing hashes & signatures for a university ---
app.post('/legacy/backfill', auth, async (req, res) => {
    try {
        const uniId = req.universityId;
        const { rows } = await pool.query('SELECT * FROM legacy_certificates WHERE university_id = $1 AND legacy_hash IS NULL', [uniId]);
        let processed = 0;
        for (const row of rows) {
            const { hash } = canonicalizeLegacyRow(row);
            const jws = await signLegacyHash(uniId, hash);
            await pool.query(
                `UPDATE legacy_certificates SET legacy_hash=$1, hash_algo='SHA256', canonical_version=$2, did_signature=$3, signed_at=NOW(), status='signed' WHERE id=$4`,
                [hash, LEGACY_CANONICAL_VERSION, jws, row.id]
            );
            processed++;
        }
        res.json({ processed, total: rows.length });
    } catch (e) {
        res.status(500).json({ error: e.message || 'Backfill failed' });
    }
});

// --- LEGACY: Verify by ID (public) ---
app.get('/legacy/verify/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid id' });
    const { rows } = await pool.query('SELECT lc.*, u.name AS university_name FROM legacy_certificates lc JOIN universities u ON lc.university_id = u.id WHERE lc.id = $1', [id]);
        if (!rows.length) return res.status(404).json({ error: 'Not found' });
        const row = rows[0];
        const { hash } = canonicalizeLegacyRow(row);
        const hashMatch = row.legacy_hash ? row.legacy_hash === hash : false;
        let signatureValid = false;
        if (row.did_signature && hashMatch) {
            signatureValid = await verifyLegacySignature(row.university_id, hash, row.did_signature);
        }
        let tier = 'DB only';
        if (row.legacy_hash && hashMatch && !row.did_signature) tier = 'Hashed';
        if (hashMatch && signatureValid) tier = 'Signed';
        if (row.legacy_hash && !hashMatch) tier = 'Compromised (hash mismatch)';
        res.json({
            id: row.id,
            university_id: row.university_id,
            university_name: row.university_name,
            name: row.name,
            title: row.title,
            subject_id: row.subject_id,
            issued_on: row.issued_on,
            legacy_hash: row.legacy_hash,
            recomputed_hash: hash,
            hashMatch,
            signatureValid,
            tier,
            did_signature: row.did_signature,
            signed_at: row.signed_at,
            canonical_version: row.canonical_version
        });
    } catch (e) {
        res.status(500).json({ error: e.message || 'Legacy verification failed' });
    }
});

// --- LEGACY: Manual verification by fields (public) ---
app.post('/legacy/manual-verify', express.json(), async (req, res) => {
    try {
        let { name, title, subject_id, student_id } = req.body || {};
        name = (name || '').trim();
        title = (title || '').trim();
        subject_id = (subject_id || '').trim();
        if (!name || !title || !subject_id) {
            return res.status(400).json({ error: 'name, title, subject_id are required' });
        }
        // Case-insensitive comparison on all three fields
        const q = await pool.query(
            `SELECT lc.*, u.name AS university_name FROM legacy_certificates lc JOIN universities u ON lc.university_id = u.id
             WHERE LOWER(lc.name)=LOWER($1) AND LOWER(lc.title)=LOWER($2) AND LOWER(lc.subject_id)=LOWER($3) LIMIT 1`,
            [name, title, subject_id]
        );
        if (!q.rows.length) return res.status(404).json({ error: 'No matching legacy certificate' });
        const row = q.rows[0];
        const { hash } = canonicalizeLegacyRow(row);
        const hashMatch = row.legacy_hash ? row.legacy_hash === hash : false;
        let signatureValid = false;
        if (row.did_signature && hashMatch) {
            try { signatureValid = await verifyLegacySignature(row.university_id, hash, row.did_signature); } catch { }
        }
        let tier = 'DB only';
        if (row.legacy_hash && hashMatch && !row.did_signature) tier = 'Hashed';
        if (hashMatch && signatureValid) tier = 'Signed';
        if (row.legacy_hash && !hashMatch) tier = 'Compromised (hash mismatch)';
    return res.json({ matched: true, redirect: `/certificate-details.html?legacyId=${row.id}`, tier, id: row.id, university_name: row.university_name });
    } catch (e) {
        res.status(500).json({ error: e.message || 'Manual legacy verification failed' });
    }
});

// --- BULK: preview, start, status, download ---
app.post('/issue/bulk/preview', auth, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'No file uploaded.' });
        const rows = parseBulkFile(file);
        const required = ['prn_number', 'name', 'title', 'subject_id'];
        const missingHeader = required.find(h => !(h in (rows[0] || {})));
        if (rows.length === 0 || missingHeader) {
            return res.status(400).json({ error: 'Invalid template. Required headers: prn_number,name,title,subject_id' });
        }
        // Return first few rows as preview
        res.json({
            total: rows.length,
            headers: Object.keys(rows[0] || {}),
            sample: rows.slice(0, 5)
        });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.post('/issue/bulk/start', auth, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'No file uploaded.' });
        const rows = parseBulkFile(file);
        const required = ['prn_number', 'name', 'title', 'subject_id'];
        const missingHeader = required.find(h => !(h in (rows[0] || {})));
        if (rows.length === 0 || missingHeader) {
            return res.status(400).json({ error: 'Invalid template. Required headers: prn_number,name,title,subject_id' });
        }
        const id = crypto.randomBytes(8).toString('hex');
        const job = { id, status: 'queued', createdAt: Date.now(), current: 0, total: rows.length, universityId: req.universityId, rows };
        JOBS.set(id, job);
        // Start async processing (next tick)
        setTimeout(async () => {
            job.status = 'processing';
            await processBulkJob(job);
        }, 10);
        res.json({ jobId: id, total: job.total });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.get('/issue/bulk/status/:jobId', auth, async (req, res) => {
    const job = JOBS.get(req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ id: job.id, status: job.status, current: job.current || 0, total: job.total || 0, error: job.error });
});

app.get('/issue/bulk/download/:jobId', auth, async (req, res) => {
    const job = JOBS.get(req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.status !== 'completed' || !job.zipPath) return res.status(400).json({ error: 'Job not completed' });
    try {
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=certificates-${job.id}.zip`);
        const stream = fs.createReadStream(job.zipPath);
        stream.pipe(res);
        stream.on('error', (e) => {
            console.error('Stream error:', e);
            try { res.status(500).end(); } catch { }
        });
    } catch (e) {
        res.status(500).json({ error: 'Failed to download ZIP' });
    }
});

// --- API ENDPOINT: BULK ISSUE CREDENTIALS ---
app.post('/issue/bulk', auth, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'No file uploaded. Please upload a CSV or XLSX file as "file".' });

        const university_id = req.universityId;
        const ctx = await getUniversityContext(Number(university_id));

        const filename = file.originalname.toLowerCase();
        let rows = [];
        if (filename.endsWith('.csv')) {
            try {
                const text = file.buffer.toString('utf8');
                rows = csvParse(text, { columns: true, skip_empty_lines: true, trim: true });
            } catch (e) {
                return res.status(400).json({ error: 'Failed to parse CSV: ' + e.message });
            }
        } else if (filename.endsWith('.xlsx') || filename.endsWith('.xls')) {
            try {
                const wb = XLSX.read(file.buffer, { type: 'buffer' });
                const sheetName = wb.SheetNames[0];
                rows = XLSX.utils.sheet_to_json(wb.Sheets[sheetName], { defval: '' });
            } catch (e) {
                return res.status(400).json({ error: 'Failed to parse Excel: ' + e.message });
            }
        } else {
            return res.status(400).json({ error: 'Unsupported file type. Upload .csv or .xlsx' });
        }

        // Expected headers: prn_number, name, title, subject_id
        const required = ['prn_number', 'name', 'title', 'subject_id'];
        const missingHeader = required.find(h => !(h in (rows[0] || {})));
        if (rows.length === 0 || missingHeader) {
            return res.status(400).json({ error: 'Invalid template. Required headers: prn_number,name,title,subject_id' });
        }

        res.setHeader('Content-Type', 'application/zip');
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        res.setHeader('Content-Disposition', `attachment; filename=certificates-${ts}.zip`);

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.on('error', (err) => { console.error('Zip error:', err); try { res.status(500).end(); } catch { } });
        archive.pipe(res);

        const summary = [];

        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];
            const prn_number = String(row.prn_number || '').trim();
            const name = String(row.name || '').trim();
            const title = String(row.title || '').trim();
            const subject_id = String(row.subject_id || '').trim();

            const entry = { index: i, prn_number, name, title, subject_id };
            try {
                if (!prn_number || !name || !title || !subject_id) throw new Error('Missing required fields');

                // Generate pre/final PDFs and hashes
                const pre = await generateCertificatePdf({
                    university_name: ctx.uni.name,
                    student_name: name,
                    course_name: title,
                    subject_id,
                    degree_type: 'Certificate',
                    graduation_year: new Date().getFullYear(),
                    issue_date: new Date().toLocaleDateString(),
                    student_id: prn_number,
                    certificate_id: 'N/A',
                    certificate_hash: ''
                });
                const hash1 = ethers.sha256(pre.preQrBuffer);
                const post = await generateCertificatePdf({
                    university_name: ctx.uni.name,
                    student_name: name,
                    course_name: title,
                    subject_id,
                    degree_type: 'Certificate',
                    graduation_year: new Date().getFullYear(),
                    issue_date: new Date().toLocaleDateString(),
                    student_id: prn_number,
                    certificate_id: 'N/A',
                    certificate_hash: hash1
                });
                const finalPdfBuffer = post.postQrBuffer;
                const hash2 = ethers.sha256(finalPdfBuffer);

                // Issue VC
                const vcPayload = {
                    '@context': ['https://www.w3.org/2018/credentials/v1'],
                    type: ['VerifiableCredential', 'AcademicCertificate'],
                    issuer: { id: ctx.issuerDid.id },
                    issuanceDate: new Date().toISOString(),
                    credentialSubject: { id: `urn:prn:${prn_number}`, name, title, subject_id, hash1, hash2 },
                };
                const vcJwt = await createVerifiableCredentialJwt(vcPayload, ctx.issuerObj);

                // Store on chain
                let txHash = null;
                try {
                    const tx = await ctx.contract.storeCredentialHash(hash2);
                    const receipt = await tx.wait();
                    txHash = tx.hash || (receipt && receipt.transactionHash) || null;
                } catch (e) {
                    // Continue even if chain store fails; record error
                    entry.blockchainError = e.message;
                }

                // Save DB
                try {
                    await pool.query(
                        'INSERT INTO certificates (name, title, student_id, subject_id, hash1, hash2, vc_jwt, university_id, tx_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
                        [name, title, prn_number, subject_id, hash1, hash2, vcJwt, Number(universityId), txHash]
                    );
                } catch (e) {
                    entry.dbError = e.message;
                }

                // Add PDF to zip
                const fn = `certificate-${prn_number || 'issued'}.pdf`;
                archive.append(Buffer.from(finalPdfBuffer), { name: fn });

                Object.assign(entry, { hash1, hash2, txHash, status: 'ok' });
            } catch (e) {
                entry.status = 'error';
                entry.error = e.message;
            }
            summary.push(entry);
        }

        // Add summary.json and optionally CSV
        archive.append(Buffer.from(JSON.stringify(summary, null, 2)), { name: 'summary.json' });
        // Simple CSV
        const csvHeader = 'index,prn_number,name,title,subject_id,hash1,hash2,txHash,status,error,blockchainError,dbError\n';
        const csvLines = summary.map(s => [s.index, s.prn_number, s.name, s.title, s.subject_id, s.hash1, s.hash2, s.txHash, s.status, s.error, s.blockchainError, s.dbError]
            .map(v => v == null ? '' : String(v).replaceAll('"', '""'))
            .map(v => /[",\n]/.test(v) ? `"${v}"` : v)
            .join(','));
        archive.append(Buffer.from(csvHeader + csvLines.join('\n')), { name: 'summary.csv' });

        await archive.finalize();
    } catch (e) {
        console.error('❌ Bulk issue error:', e);
        if (!res.headersSent) res.status(500).json({ error: 'Bulk issuance failed' });
    }
});

// Store active admin SSE connections for real-time updates
const adminConnections = new Set();

// Broadcast function for real-time updates
const broadcastToAdmins = (data) => {
    const message = `data: ${JSON.stringify(data)}\n\n`;
    adminConnections.forEach(res => {
        try {
            res.write(message);
        } catch (e) {
            console.warn('Failed to send to admin connection:', e.message);
            adminConnections.delete(res);
        }
    });
};

// Server-Sent Events for real-time alerts
app.get('/api/alerts/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Add to active connections
    adminConnections.add(res);
    console.log(`✅ Admin dashboard connected (${adminConnections.size} active connections)`);

    // Send initial connection message
    res.write(`data: ${JSON.stringify({
        type: 'connection',
        message: 'Connected to admin dashboard alerts',
        ts: Date.now()
    })}\n\n`);

    // Send recent activity and alerts as initial payload
    Promise.all([
        pool.query(`
            SELECT c.name, c.title, u.name as university_name, c.created_at
            FROM certificates c
            JOIN universities u ON c.university_id = u.id
            WHERE c.created_at > NOW() - INTERVAL '1 hour'
            ORDER BY c.created_at DESC
            LIMIT 5
        `),
        pool.query(`
            SELECT id, type, details, created_at
            FROM alerts
            ORDER BY id DESC
            LIMIT 10
        `)
    ]).then(([certs, alerts]) => {
        certs.rows.forEach(cert => {
            res.write(`data: ${JSON.stringify({
                type: 'certificate_issued',
                message: `New certificate issued: "${cert.title}" for ${cert.name} by ${cert.university_name}`,
                ts: new Date(cert.created_at).getTime()
            })}\n\n`);
        });
        alerts.rows.forEach(a => {
            const details = typeof a.details === 'string' ? a.details : JSON.stringify(a.details || {});
            res.write(`data: ${JSON.stringify({
                type: 'alert',
                message: `Alert ${a.type}: ${details?.slice(0, 60)}`,
                ts: new Date(a.created_at).getTime()
            })}\n\n`);
        });
    }).catch(console.error);

    // Keep connection alive with periodic heartbeat
    const heartbeat = setInterval(() => {
        try {
            res.write(`data: ${JSON.stringify({
                type: 'heartbeat',
                message: 'Dashboard connection active',
                ts: Date.now()
            })}\n\n`);
        } catch (e) {
            clearInterval(heartbeat);
            adminConnections.delete(res);
        }
    }, 30000);

    // Clean up on client disconnect
    req.on('close', () => {
        clearInterval(heartbeat);
        adminConnections.delete(res);
        console.log(`❌ Admin dashboard disconnected (${adminConnections.size} remaining connections)`);
    });
});

// Get recent activity/alerts
app.get('/api/recent-activity', async (req, res) => {
    try {
        // Get recent universities
        const recentUnis = await pool.query(`
            SELECT name, created_at, 'university_created' as activity_type
            FROM universities 
            WHERE created_at > NOW() - INTERVAL '24 hours'
            ORDER BY created_at DESC
            LIMIT 10
        `);

        // Get recent certificates
        const recentCerts = await pool.query(`
            SELECT c.name, c.title, u.name as university_name, c.created_at, 'certificate_issued' as activity_type
            FROM certificates c
            JOIN universities u ON c.university_id = u.id
            WHERE c.created_at > NOW() - INTERVAL '24 hours'
            ORDER BY c.created_at DESC
            LIMIT 10
        `);

        // Get recent blacklists
        const recentBlacklists = await pool.query(`
            SELECT u.name, b.blacklisted_at as created_at, 'university_blacklisted' as activity_type, b.reason as blacklist_reason
            FROM university_blacklist b
            JOIN universities u ON b.uni_id = u.id
            WHERE b.blacklisted_at > NOW() - INTERVAL '24 hours'
            ORDER BY b.blacklisted_at DESC
            LIMIT 10
        `);

        // Combine and sort by timestamp
        const allActivity = [
            ...recentUnis.rows,
            ...recentCerts.rows,
            ...recentBlacklists.rows
        ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json(allActivity);
    } catch (error) {
        console.error('Error fetching recent activity:', error);
        res.status(500).json({ error: 'Failed to fetch recent activity' });
    }
});

// Dashboard admin stats endpoint (main with forgeries support)
app.get('/admin/stats', async (req, res) => {
    try {
        console.log('Stats endpoint called');

        // Debug: Check if alerts table has any data
        const alertCount = await pool.query('SELECT COUNT(*) as total FROM alerts');
        console.log('Total alerts in database:', alertCount.rows[0].total);

        // Debug: Check what alert types exist
        const alertTypes = await pool.query('SELECT type, COUNT(*) as count FROM alerts GROUP BY type ORDER BY count DESC');
        console.log('Alert types breakdown:', alertTypes.rows);

        // Start with basic counts
        const uniCount = (await pool.query('SELECT COUNT(*)::int AS c FROM universities')).rows[0].c;
        console.log('University count:', uniCount);

        const certCount = (await pool.query('SELECT COUNT(*)::int AS c FROM certificates')).rows[0].c;
        console.log('Certificate count:', certCount);

        const blacklistedCount = (await pool.query('SELECT COUNT(*)::int AS c FROM university_blacklist')).rows[0].c;
        console.log('Blacklisted count:', blacklistedCount);

        // Additional dynamic stats
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);

        const dailyCerts = (await pool.query('SELECT COUNT(*)::int AS c FROM certificates WHERE created_at >= $1', [todayStart])).rows[0].c;
        const weeklyGrowth = (await pool.query(`
            SELECT 
                COUNT(CASE WHEN created_at >= NOW() - INTERVAL '7 days' THEN 1 END)::int as this_week,
                COUNT(CASE WHEN created_at >= NOW() - INTERVAL '14 days' AND created_at < NOW() - INTERVAL '7 days' THEN 1 END)::int as last_week
            FROM certificates
        `)).rows[0];

        const growthRate = weeklyGrowth.last_week > 0
            ? (((weeklyGrowth.this_week - weeklyGrowth.last_week) / weeklyGrowth.last_week) * 100).toFixed(1)
            : weeklyGrowth.this_week > 0 ? '+100.0' : '0.0';

        const topInstitution = (await pool.query(`
            SELECT u.name, COUNT(c.id)::int as cert_count
            FROM universities u
            LEFT JOIN certificates c ON u.id = c.university_id
            WHERE u.id NOT IN (SELECT uni_id FROM university_blacklist)
            GROUP BY u.id, u.name
            ORDER BY cert_count DESC
            LIMIT 1
        `)).rows[0];

        const alertCounts = (await pool.query(`
            SELECT 
                COALESCE(COUNT(CASE WHEN type = 'not_found' OR type = 'not_found_pdf' THEN 1 END), 0)::int as not_found,
                COALESCE(COUNT(CASE WHEN type = 'mismatch' THEN 1 END), 0)::int as mismatch,
                COALESCE(COUNT(CASE WHEN type = 'revoked' THEN 1 END), 0)::int as revoked,
                COALESCE(COUNT(CASE WHEN created_at >= $1 THEN 1 END), 0)::int as today_total,
                COALESCE(COUNT(CASE WHEN type = 'mismatch' AND created_at >= $1 THEN 1 END), 0)::int as forgeries_today,
                COALESCE(COUNT(CASE WHEN type = 'not_found_pdf' THEN 1 END), 0)::int as pdf_forgeries,
                COALESCE(COUNT(*), 0)::int as total_all_alerts
            FROM alerts
        `, [todayStart])).rows[0];

        console.log('Alert counts:', alertCounts); // Debug logging
        console.log('Today start:', todayStart); // Debug logging

        // Calculate success rate: (total certificates - failed verifications) / total certificates
        const failedVerifications = alertCounts.mismatch + alertCounts.not_found;
        const successRate = certCount > 0 ? (((certCount - failedVerifications) / certCount) * 100).toFixed(1) : '100.0';
        console.log('Success rate calculation:', {
            certCount,
            failedVerifications,
            mismatch: alertCounts.mismatch,
            notFound: alertCounts.not_found,
            calculatedRate: successRate
        });

        const responseData = {
            universities: uniCount,
            certificates: certCount,
            blacklisted: blacklistedCount,
            dailyCertificates: dailyCerts,
            weeklyGrowth: growthRate,
            topInstitution: topInstitution?.name || 'N/A',
            topInstitutionCount: topInstitution?.cert_count || 0,
            alertCounts,
            totalAlerts: alertCounts.total_all_alerts,
            successRate: successRate
        };

        console.log('Sending response:', responseData);
        res.json(responseData);
    } catch (e) {
        console.error('Stats error:', e);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});


app.get('/admin/alerts', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
        const rows = (await pool.query('SELECT id, type, details, created_at FROM alerts ORDER BY id DESC LIMIT $1', [limit])).rows;
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
});

app.post('/admin/universities/:id/blacklist', express.json(), async (req, res) => {
    console.log(`🔧 Blacklist request received for university ID: ${req.params.id}`);
    console.log(`🔧 Request body:`, req.body);

    try {
        const uniId = Number(req.params.id);
        const { reason } = req.body || {};

        console.log(`🔧 Parsed uniId: ${uniId}, reason: "${reason}"`);

        // Validate university exists
        const uniCheck = await pool.query('SELECT name FROM universities WHERE id = $1', [uniId]);
        if (uniCheck.rows.length === 0) {
            console.log(`❌ University not found for ID: ${uniId}`);
            return res.status(404).json({ error: 'University not found' });
        }
        const uniName = uniCheck.rows[0].name;
        console.log(`✅ Found university: ${uniName}`);

        // Check if already blacklisted
        const existingBlacklist = await pool.query('SELECT 1 FROM university_blacklist WHERE uni_id = $1', [uniId]);

        if (existingBlacklist.rows.length > 0) {
            // Update existing blacklist entry
            await pool.query('UPDATE university_blacklist SET reason = $1, blacklisted_at = NOW() WHERE uni_id = $2', [reason || null, uniId]);
        } else {
            // Insert new blacklist entry; self-heal sequence if out-of-sync causes 23505
            try {
                await pool.query('INSERT INTO university_blacklist(uni_id, reason) VALUES ($1, $2)', [uniId, reason || null]);
            } catch (e) {
                if (e && e.code === '23505') {
                    console.warn('Primary key conflict detected on university_blacklist; resyncing sequence and retrying...');
                    try {
                        await pool.query(`
                            SELECT setval(
                                pg_get_serial_sequence('university_blacklist','id'),
                                COALESCE((SELECT MAX(id) FROM university_blacklist), 0),
                                true
                            );
                        `);
                        await pool.query('INSERT INTO university_blacklist(uni_id, reason) VALUES ($1, $2)', [uniId, reason || null]);
                    } catch (e2) {
                        console.error('Failed to recover from sequence mismatch on university_blacklist:', e2);
                        throw e; // propagate original error
                    }
                } else {
                    throw e;
                }
            }
        }

        // Log the blacklist action as an alert
        await pool.query('INSERT INTO alerts (type, details) VALUES ($1, $2)', [
            'university_blacklisted',
            JSON.stringify({
                university_id: uniId,
                university_name: uniName,
                reason: reason || 'No reason provided',
                admin_action: true,
                timestamp: new Date().toISOString()
            })
        ]);

        // Send real-time notification
        broadcastToAdmins({
            type: 'university_blacklisted',
            message: `Institution "${uniName}" has been blacklisted`,
            data: { university_id: uniId, name: uniName, reason },
            ts: new Date().toISOString()
        });

        console.log(`✅ University blacklisted: ${uniName} (ID: ${uniId})`);
        res.json({ success: true, message: 'University blacklisted successfully' });
    } catch (e) {
        console.error('❌ Blacklist error:', e);
        res.status(500).json({ error: 'Failed to blacklist university: ' + e.message });
    }
});

app.delete('/admin/universities/:id/blacklist', async (req, res) => {
    try {
        const uniId = Number(req.params.id);

        // Check if university exists and get name
        const uniCheck = await pool.query('SELECT name FROM universities WHERE id = $1', [uniId]);
        if (uniCheck.rows.length === 0) {
            return res.status(404).json({ error: 'University not found' });
        }
        const uniName = uniCheck.rows[0].name;

        // Check if university is actually blacklisted
        const blacklistCheck = await pool.query('SELECT 1 FROM university_blacklist WHERE uni_id = $1', [uniId]);
        if (blacklistCheck.rows.length === 0) {
            return res.status(400).json({ error: 'University is not blacklisted' });
        }

        // Remove from blacklist
        await pool.query('DELETE FROM university_blacklist WHERE uni_id = $1', [uniId]);

        // Log the unblacklist action as an alert
        await pool.query('INSERT INTO alerts (type, details) VALUES ($1, $2)', [
            'university_unblacklisted',
            JSON.stringify({
                university_id: uniId,
                university_name: uniName,
                admin_action: true,
                timestamp: new Date().toISOString()
            })
        ]);

        // Send real-time notification
        broadcastToAdmins({
            type: 'university_unblacklisted',
            message: `Institution "${uniName}" has been removed from blacklist`,
            data: { university_id: uniId, name: uniName },
            ts: new Date().toISOString()
        });

        console.log(`✅ University unblacklisted: ${uniName} (ID: ${uniId})`);
        res.json({ success: true, message: 'University removed from blacklist successfully' });
    } catch (e) {
        console.error('❌ Unblacklist error:', e);
        res.status(500).json({ error: 'Failed to unblacklist university: ' + e.message });
    }
});

app.get('/admin/test-forgeries', async (req, res) => {
    try {
        // Insert a test forgery alert for today
        await pool.query(`
            INSERT INTO alerts (type, details, created_at) 
            VALUES ('mismatch', '{"test": "forgery detection"}', NOW())
        `);
        res.json({ message: 'Test forgery alert created' });
    } catch (e) {
        console.error('Error creating test forgery:', e);
        res.status(500).json({ error: 'Failed to create test forgery' });
    }
});


app.get('/admin/health', async (req, res) => {
    try {
        // Test database connection
        const result = await pool.query('SELECT 1 as test');
        res.json({
            status: 'healthy',
            database: 'connected',
            timestamp: new Date().toISOString(),
            test_query: result.rows[0]
        });
    } catch (e) {
        console.error('Health check failed:', e);
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: e.message,
            timestamp: new Date().toISOString()
        });
    }
});


app.get('/admin/universities', async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT u.id, u.name, u.email, u.public_address, u.contract_address,
                   (b.uni_id IS NOT NULL) AS blacklisted,
                   b.reason, b.blacklisted_at,
                   COUNT(c.id)::int as certificate_count,
                   u.created_at
            FROM universities u
            LEFT JOIN university_blacklist b ON b.uni_id = u.id
            LEFT JOIN certificates c ON c.university_id = u.id
            GROUP BY u.id, u.name, u.email, u.public_address, u.contract_address, b.uni_id, b.reason, b.blacklisted_at, u.created_at
            ORDER BY u.id ASC
        `);
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: 'Failed to list universities' });
    }
});


// Role enforcement helper
function requireRole(role) {
    return (req, res, next) => {
        if (!req.authRole || req.authRole !== role) {
            return res.status(403).json({ error: 'forbidden' });
        }
        next();
    };
}

// Lightweight auth extraction (reuse full auth for token validation then set role)
const authWithRole = async (req, res, next) => {
    // Reuse existing auth middleware logic by calling it then enriching
    const originalNext = next;
    auth(req, res, () => {
        // Determine role from decoded token heuristics
        // The existing auth middleware only sets universityId. We infer admin by absence.
        if (req.universityId) {
            req.authRole = 'university';
        } else {
            // Future: extend auth middleware to attach decoded payload
            req.authRole = 'admin';
        }
        originalNext();
    });
};

app.get('/admin', auth, (req, res) => {
    if (req.authPayload?.role !== 'admin') return res.redirect('/login.html');
    res.redirect('/admin-dashboard.html');
});

// Protected university dashboard asset route (optional hardening)
app.get('/university-dashboard', auth, (req, res) => {
    if (req.authPayload?.role !== 'university') return res.redirect('/login.html');
    res.redirect('/university-dashboard.html');
});

// Logout endpoint clears cookie
app.post('/auth/logout', (req, res) => {
    clearAuthCookie(res);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.json({ ok: true });
});

// Duplicate route removed (consolidated above with certificate counts)

app.get('/admin/test', (req, res) => {
    res.json({ message: 'Admin test endpoint working', timestamp: new Date().toISOString() });
});

// --- API ENDPOINT: VERIFY UPLOADED PDF ---
app.post('/verify', upload.single('pdf_file'), async (req, res) => {
    try {
        console.log('[VERIFY_UPLOAD] request received');
        const pdfBuffer = req.file?.buffer;
        if (!pdfBuffer) {
            console.log('[VERIFY_UPLOAD] no file present');
            return res.status(400).json({ isValid: false, message: 'No PDF file uploaded.' });
        }
        console.log('[VERIFY_UPLOAD] file size bytes:', pdfBuffer.length);
        const MAX_BYTES = 950 * 1024; // 950KB
        if (pdfBuffer.length > MAX_BYTES) {
            console.log('[VERIFY_UPLOAD] file too large');
            return res.status(413).json({ isValid: false, message: 'File too large. Max 950KB.' });
        }

        const hash2 = ethers.sha256(pdfBuffer);
    let rows = (await pool.query('SELECT * FROM certificates WHERE hash2 = $1', [hash2])).rows;
    console.log('[VERIFY_UPLOAD] computed hash2', hash2, 'found rows', rows.length);
        let dbRecord = rows[0] || null;
        let matchedBy = 'hash2';

        // OCR helper
        async function runOcr(buf) {
            if (!OCRSPACE_API_KEY) return { text: null, fields: null, error: 'OCR key missing' };
            try {
                const boundary = '----ocr' + crypto.randomBytes(6).toString('hex');
                const parts = [];
                const pushField = (name, value) => {
                    parts.push(Buffer.from(`--${boundary}\r\n`));
                    parts.push(Buffer.from(`Content-Disposition: form-data; name="${name}"\r\n\r\n`));
                    parts.push(Buffer.from(value + '\r\n'));
                };
                pushField('apikey', OCRSPACE_API_KEY);
                pushField('language', 'eng');
                pushField('isTable', 'true');
                parts.push(Buffer.from(`--${boundary}\r\n`));
                parts.push(Buffer.from('Content-Disposition: form-data; name="file"; filename="file.pdf"\r\n'));
                parts.push(Buffer.from('Content-Type: application/pdf\r\n\r\n'));
                parts.push(buf);
                parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
                const body = Buffer.concat(parts);
                const resp = await fetch('https://api.ocr.space/parse/image', { method: 'POST', headers: { 'Content-Type': 'multipart/form-data; boundary=' + boundary }, body });
                const json = await resp.json();
                const text = json?.ParsedResults?.[0]?.ParsedText || '';
                const joined = text.replace(/\r?\n/g, ' ');
                const fields = {};
                const prn = joined.match(/PRN[:\s]*([A-Za-z0-9\-\/]+)/i); if (prn) fields.prn = prn[1];
                const subj = joined.match(/Subject ID[:\s]*([A-Za-z0-9\-]+)/i); if (subj) fields.subject_id = subj[1];
                const name = joined.match(/certify that\s+([A-Z][A-Za-z .']{2,80})\s+has successfully/i); if (name) fields.name = name[1].trim();
                const title = joined.match(/Certificate in\s+([A-Z][A-Za-z0-9 &,'()./-]{2,80})/i); if (title) fields.title = title[1].trim();
                return { text, fields, error: null };
            } catch (e) { return { text: null, fields: null, error: e.message }; }
        }

        let ocr = null;
        if (!dbRecord) {
            ocr = await runOcr(pdfBuffer);
            if (ocr.fields) {
                const f = ocr.fields;
                if (!dbRecord && f.prn && f.subject_id) rows = (await pool.query('SELECT * FROM certificates WHERE student_id=$1 AND subject_id=$2 ORDER BY id DESC LIMIT 1', [f.prn, f.subject_id])).rows;
                if (!rows.length && f.prn && f.title) rows = (await pool.query('SELECT * FROM certificates WHERE student_id=$1 AND title ILIKE $2 ORDER BY id DESC LIMIT 1', [f.prn, f.title])).rows;
                if (!rows.length && f.name && f.title) rows = (await pool.query('SELECT * FROM certificates WHERE name ILIKE $1 AND title ILIKE $2 ORDER BY id DESC LIMIT 1', [f.name, f.title])).rows;
                dbRecord = rows[0] || null;
                if (dbRecord) matchedBy = 'ocr-fields';
            }
        } else {
            ocr = await runOcr(pdfBuffer); // optional for confirmation
        }

        let vcJwt = dbRecord ? dbRecord.vc_jwt : null;
        let credentialSubject = null;
        let vcHash1 = null, vcHash2 = null;
        if (vcJwt) {
            try {
                const resolver = new Resolver({ ...keyDidResolver() });
                const verified = await verifyCredential(vcJwt, resolver);
                credentialSubject = verified?.verifiableCredential?.credentialSubject || null;
                vcHash1 = credentialSubject?.hash1 || null;
                vcHash2 = credentialSubject?.hash2 || null;
            } catch { }
        }

        let blockchainRevoked = false; let contractAddress = null;
        if (dbRecord) {
            try { const ctx = await getUniversityContext(Number(dbRecord.university_id)); contractAddress = ctx.uni.contract_address; blockchainRevoked = await ctx.contract.isRevoked(dbRecord.hash2); } catch { }
        }

        const dbFound = !!dbRecord;
        const hashesMatch = dbRecord ? (dbRecord.hash2 === hash2) : false;
        const ocrVerified = !!(ocr && ocr.fields && dbRecord && (
            (ocr.fields.prn ? ocr.fields.prn === dbRecord.student_id : true) &&
            (ocr.fields.name ? ocr.fields.name.toLowerCase() === dbRecord.name.toLowerCase() : true) &&
            (ocr.fields.title ? ocr.fields.title.toLowerCase() === dbRecord.title.toLowerCase() : true)
        ));

        let verificationTier;
        if (dbFound && !blockchainRevoked && hashesMatch && ocrVerified) verificationTier = 'Blockchain + OCR verified';
        else if (!dbFound && ocrVerified) verificationTier = 'OCR matched text only (no blockchain record)';
        else if (dbFound && !blockchainRevoked && hashesMatch) verificationTier = 'Blockchain verified (OCR not conclusive)';
        else if (dbRecord && blockchainRevoked) verificationTier = 'Record revoked on blockchain';
        else if (dbFound && !hashesMatch && ocrVerified && !blockchainRevoked) verificationTier = 'OCR verified (hash mismatch – likely re-scanned copy)';
        else verificationTier = 'Verification failed';

        const isValid = verificationTier.startsWith('Blockchain') || verificationTier.startsWith('OCR verified (hash mismatch');

        // Record alerts for modern path
        try {
            if (!dbFound) {
                await recordAlert('not_found_pdf', { hash2 });
            } else if (blockchainRevoked) {
                await recordAlert('revoked', { hash2, university_id: dbRecord.university_id });
            } else if (dbFound && !hashesMatch) {
                await recordAlert('mismatch', { dbHash2: dbRecord.hash2, computedHash2: hash2, university_id: dbRecord.university_id });
            }
        } catch { /* ignore */ }

        if (verificationTier.startsWith('Blockchain') || verificationTier.startsWith('OCR verified (hash mismatch')) {
            const redirectHash = hashesMatch ? hash2 : (dbRecord?.hash2 || hash2);
            const tierParam = encodeURIComponent(verificationTier);
            console.log('[VERIFY_UPLOAD] returning modern redirect tier', verificationTier);
            return res.json({
                mode: 'modern',
                isValid,
                verificationTier,
                redirect: `/certificate-details.html?hash=${redirectHash}&ocr=${ocrVerified ? 1 : 0}&tier=${tierParam}`,
                hash1: dbRecord?.hash1 || null,
                hash2,
                ocrVerified,
                blockchainRevoked,
                contractAddress,
                matchedBy,
                hashesMatch
            });
        }

        // If modern path failed to produce a valid verification, attempt LEGACY MATCHING (strict)
        let legacyAttempt = null;
        if (!isValid) {
            try {
                // Lazy import to avoid adding cost when not needed
                const pdfParse = (await import('pdf-parse')).default;
                const parsed = await pdfParse(pdfBuffer).catch(() => null);
                const text = parsed?.text || '';
                const flat = text.replace(/\r?\n+/g, ' ').replace(/\s+/g, ' ').trim();
                // Basic heuristics similar to earlier OCR fields extraction
                const fields = {};
                const prn = flat.match(/PRN[:\s]*([A-Za-z0-9\-\/]+)/i); if (prn) fields.prn = prn[1];
                const subj = flat.match(/Subject ID[:\s]*([A-Za-z0-9\-]+)/i); if (subj) fields.subject_id = subj[1];
                const name = flat.match(/certify that\s+([A-Z][A-Za-z .']{2,80})\s+has successfully/i); if (name) fields.name = name[1].trim();
                const title = flat.match(/Certificate in\s+([A-Z][A-Za-z0-9 &,'().\/-]{2,80})/i); if (title) fields.title = title[1].trim();
                // Build candidate query where we have at least name or title
                let candidates = [];
                if (fields.name || fields.title || fields.subject_id) {
                    const clauses = [];
                    const params = [];
                    let idx = 1;
                    // Use AND to reduce spurious matches; include only present fields
                    if (fields.name) { clauses.push(`LOWER(name) = LOWER($${idx++})`); params.push(fields.name); }
                    if (fields.title) { clauses.push(`LOWER(title) = LOWER($${idx++})`); params.push(fields.title); }
                    if (fields.subject_id) { clauses.push(`subject_id = $${idx++}`); params.push(fields.subject_id); }
                    if (clauses.length) {
                        const where = clauses.join(' AND ');
                        const q = await pool.query(`SELECT * FROM legacy_certificates WHERE ${where} LIMIT 50`, params);
                        candidates = q.rows;
                    }
                }
                // Scoring
                function score(row) {
                    let s = 0; let reasons = [];
                    if (fields.name && row.name && row.name.toLowerCase() === fields.name.toLowerCase()) { s += 0.45; reasons.push('name'); }
                    if (fields.title && row.title && row.title.toLowerCase() === fields.title.toLowerCase()) { s += 0.35; reasons.push('title'); }
                    if (fields.subject_id && row.subject_id === fields.subject_id) { s += 0.15; reasons.push('subject'); }
                    if (row.legacy_hash) {
                        try { const { hash } = canonicalizeLegacyRow(row); if (hash === row.legacy_hash) { s += 0.05; reasons.push('hash'); } } catch { }
                    }
                    return { score: s, reasons };
                }
                const rankedRaw = candidates.map(r => { const sc = score(r); return { row: r, score: sc.score, reasons: sc.reasons }; }).sort((a, b) => b.score - a.score).slice(0, 10);
                const MIN_SCORE = 0.6; // require combined strong match
                const ranked = rankedRaw.filter(r => r.score >= MIN_SCORE);
                if (ranked.length) {
                    const top = ranked[0];
                    const { row } = top;
                    let hashMatch = false, signatureValid = false; let tier = 'DB only';
                    try {
                        const { hash } = canonicalizeLegacyRow(row); hashMatch = !!row.legacy_hash && row.legacy_hash === hash;
                        if (hashMatch && row.did_signature) signatureValid = await verifyLegacySignature(row.university_id, hash, row.did_signature);
                        if (row.legacy_hash && hashMatch && !row.did_signature) tier = 'Hashed';
                        if (hashMatch && signatureValid) tier = 'Signed';
                        if (row.legacy_hash && !hashMatch) tier = 'Compromised (hash mismatch)';
                    } catch { }
                    legacyAttempt = {
                        mode: 'legacy',
                        autoRedirect: top.score >= 0.85 && tier !== 'Compromised (hash mismatch)',
                        topScore: top.score,
                        extracted: fields,
                        candidates: ranked.map(r => ({
                            id: r.row.id,
                            name: r.row.name,
                            title: r.row.title,
                            subject_id: r.row.subject_id,
                            issued_on: r.row.issued_on,
                            score: r.score,
                            has_hash: !!r.row.legacy_hash,
                            has_signature: !!r.row.did_signature
                        })),
                        redirect: (top.score >= 0.85 && tier !== 'Compromised (hash mismatch)') ? `/certificate-details.html?legacyId=${top.row.id}` : null,
                        matchedTier: tier,
                        hashMatch,
                        signatureValid
                    };
                }
            } catch (e) {
                legacyAttempt = { mode: 'legacy', error: e.message };
            }
        }

        if (legacyAttempt) {
            console.log('[VERIFY_UPLOAD] legacy attempt response', !!legacyAttempt.autoRedirect);
            return res.json({
                isValid: !!legacyAttempt.autoRedirect,
                verificationTier: legacyAttempt.matchedTier || null,
                legacy: legacyAttempt,
                hash2,
                modernAttempt: {
                    dbFound,
                    verificationTier,
                    blockchainRevoked,
                    ocrVerified
                }
            });
        }

        console.log('[VERIFY_UPLOAD] returning modern non-redirect tier', verificationTier);
        return res.json({
            mode: 'modern',
            isValid,
            verificationTier,
            message: verificationTier,
            hash1: dbRecord?.hash1 || null,
            hash2,
            dbFound,
            hashesMatch,
            blockchainRevoked,
            ocrVerified,
            ocrExtracted: ocr?.fields || null,
            ocrError: ocr?.error || null,
            matchedBy,
            vcJwt,
            credentialSubject,
            contractAddress
        });
    } catch (error) {
        console.error('❌ OCR Verification Error:', error);
        res.status(500).json({ isValid: false, message: 'Internal verification error' });
    }
});

// --- START SERVER ---
app.listen(PORT, async () => {
    await ensureSchema();
    await setupIssuer();
    console.log(`🚀 Server running! Open http://localhost:${PORT} in your browser.`);
});

