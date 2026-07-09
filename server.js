'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const helmet = require('helmet');

const app = express();
const ROOT_DIR = __dirname;
const INDEX_HTML = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const JWT_COOKIE = 'meetly_session';

const OTP_LENGTH = 6;
const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const VERIFY_MAX_ATTEMPTS = 5;

const usersByEmail = new Map();
const otpByEmail = new Map();
const rateBuckets = new Map();

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://cdnjs.cloudflare.com',
          'https://cdn.jsdelivr.net'
        ],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        mediaSrc: ["'self'", 'blob:'],
        fontSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: false
  })
);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

function nowMs() {
  return Date.now();
}

function pruneRateBucket(bucket, cutoff) {
  while (bucket.length && bucket[0] < cutoff) {
    bucket.shift();
  }
}

function hitRateLimit(key, limit, windowMs) {
  const now = nowMs();
  const cutoff = now - windowMs;
  const bucket = rateBuckets.get(key) || [];
  pruneRateBucket(bucket, cutoff);
  if (bucket.length >= limit) {
    rateBuckets.set(key, bucket);
    return true;
  }
  bucket.push(now);
  rateBuckets.set(key, bucket);
  return false;
}

function sanitizeEmail(input) {
  return String(input || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return emailRegex.test(email);
}

function isValidOtp(otp) {
  return /^\d{6}$/.test(String(otp || ''));
}

function getRequesterIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function rateLimitMiddleware(prefix, limit, windowMs) {
  return function rateLimitHandler(req, res, next) {
    const ip = getRequesterIp(req);
    const key = `${prefix}:${ip}`;
    if (hitRateLimit(key, limit, windowMs)) {
      return res.status(429).json({ error: 'Too many requests. Please try again shortly.' });
    }
    return next();
  };
}

app.use(rateLimitMiddleware('global', 300, 60 * 1000));

function hashOtp(otp, salt) {
  return crypto.scryptSync(String(otp), salt, 32).toString('hex');
}

function createOtpCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(OTP_LENGTH, '0');
}

function getMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 465);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: true,
    family: 4,
    auth: {
      user,
      pass
    },
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000
  });
}

async function sendOtpEmail(email, otp) {
  const transporter = getMailer();

  if (!transporter) {
    throw new Error("Mailer not configured");
  }

  console.log("===== SMTP CONFIG =====");
  console.log("HOST:", process.env.SMTP_HOST);
  console.log("PORT:", process.env.SMTP_PORT);
  console.log("SECURE:", process.env.SMTP_SECURE);
  console.log("USER:", process.env.SMTP_USER);
  console.log("FROM:", process.env.FROM_EMAIL);

  try {
    await transporter.verify();
    console.log("SMTP connection successful");

    const info = await transporter.sendMail({
      from: process.env.FROM_EMAIL || process.env.SMTP_USER,
      to: email,
      subject: "Meetly Verification Code",
      text: `Your OTP is ${otp}`,
      html: `<h2>Your OTP is <b>${otp}</b></h2>`
    });

    console.log("EMAIL SENT");
    console.log(info);

  } catch (err) {
    console.error("SMTP ERROR");
    console.error(err);
    throw err;
  }
}

function issueSession(res, user) {
  const token = jwt.sign(
    {
      sub: user.id,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie(JWT_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/'
  });
}

function getSessionUser(req) {
  const token = req.cookies?.[JWT_COOKIE];
  if (!token) {
    return null;
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || !payload.email) {
      return null;
    }
    const user = usersByEmail.get(payload.email);
    return user || null;
  } catch {
    return null;
  }
}

app.get('/', rateLimitMiddleware('page', 120, 60 * 1000), (req, res) => {
  res.type('html').send(INDEX_HTML);
});

app.post('/send-otp', async (req, res) => {
  const email = sanitizeEmail(req.body?.email);
  const ip = getRequesterIp(req);

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  if (hitRateLimit(`send-ip:${ip}`, 20, 15 * 60 * 1000) || hitRateLimit(`send-email:${ip}:${email}`, 5, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many OTP requests. Please try again shortly.' });
  }

  const now = nowMs();
  const existingOtp = otpByEmail.get(email);
  if (existingOtp && existingOtp.resendAt > now) {
    const retryAfterSeconds = Math.ceil((existingOtp.resendAt - now) / 1000);
    return res.status(429).json({ error: 'Please wait before requesting another code.', retryAfterSeconds });
  }

  const otp = createOtpCode();
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashOtp(otp, salt);

  otpByEmail.set(email, {
    hash,
    salt,
    expiresAt: now + OTP_TTL_MS,
    resendAt: now + RESEND_COOLDOWN_MS,
    attempts: 0
  });

  try {
    await sendOtpEmail(email, otp);
    return res.status(200).json({ message: 'If the email is reachable, a verification code has been sent.', resendAfterSeconds: 60 });
  }catch (error) {
    console.error("OTP ERROR:");
    console.error(error);

    otpByEmail.delete(email);

    return res.status(500).json({
        error: error.message,
        stack: error.stack
    });
}
});

app.post('/verify-otp', (req, res) => {
  const email = sanitizeEmail(req.body?.email);
  const otp = String(req.body?.otp || '').trim();
  const ip = getRequesterIp(req);

  if (!isValidEmail(email) || !isValidOtp(otp)) {
    return res.status(400).json({ error: 'Invalid verification details.' });
  }

  if (hitRateLimit(`verify-ip:${ip}`, 60, 15 * 60 * 1000) || hitRateLimit(`verify-email:${ip}:${email}`, 10, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many verification attempts. Please try later.' });
  }

  const record = otpByEmail.get(email);
  const now = nowMs();
  if (!record || record.expiresAt < now) {
    otpByEmail.delete(email);
    return res.status(400).json({ error: 'Invalid or expired code.' });
  }

  if (record.attempts >= VERIFY_MAX_ATTEMPTS) {
    otpByEmail.delete(email);
    return res.status(429).json({ error: 'Too many invalid attempts. Request a new code.' });
  }

  const attemptedHash = hashOtp(otp, record.salt);
  const valid = crypto.timingSafeEqual(Buffer.from(record.hash, 'hex'), Buffer.from(attemptedHash, 'hex'));
  if (!valid) {
    record.attempts += 1;
    otpByEmail.set(email, record);
    return res.status(400).json({ error: 'Invalid or expired code.' });
  }

  otpByEmail.delete(email);

  let user = usersByEmail.get(email);
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      email,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString()
    };
    usersByEmail.set(email, user);
  } else {
    user.lastLoginAt = new Date().toISOString();
  }

  issueSession(res, user);
  return res.status(200).json({
    message: 'Verification successful.',
    user: {
      id: user.id,
      email: user.email
    }
  });
});

app.post('/logout', (req, res) => {
  res.clearCookie(JWT_COOKIE, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  });
  res.status(200).json({ message: 'Logged out.' });
});

app.get('/me', (req, res) => {
  const user = getSessionUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return res.status(200).json({
    user: {
      id: user.id,
      email: user.email
    }
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  // Intentionally avoid logging secrets or OTP data.
  console.log(`Meetly running on http://localhost:${PORT}`);
});
