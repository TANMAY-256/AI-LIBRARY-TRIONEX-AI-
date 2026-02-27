/**
 * Serves the app + API keys from .env and GitHub OAuth.
 *
 * 1. Copy .env.example to .env and add your keys (GEMINI_KEY, REMOVEBG_KEY, etc.)
 * 2. Run: node server.js
 * 3. Open http://localhost:3001/dashboard.html (keys from .env are loaded automatically)
 *
 * GitHub OAuth: set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env
 */
const http = require('http');
const https = require('https');
const url = require('url');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

// Simple in-memory OTP store: email -> { otp, expires }
const otpStore = new Map();


// Load .env from project root (no extra package needed)
const envPath = path.join(__dirname, '.env');

// Global error handlers to prevent server crash
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION:', reason);
});

if (fs.existsSync(envPath)) {
  try {
    fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach(function (line) {
      var m = line.match(/^\s*([^#=]+)=(.*)$/);
      if (m) process.env[m[1].trim()] = m[2].trim().replace(/^["']|["']$/g, '');
    });
  } catch (e) { }
}

const PORT = process.env.PORT || 3001;
const CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';

function httpsPost(host, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request({
      hostname: host,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let out = '';
      res.on('data', (c) => out += c);
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(out));
          } else {
            reject(new Error(`Request failed with status ${res.statusCode}: ${out}`));
          }
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function httpsGet(host, path, auth) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: host,
      path: path,
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + auth, 'User-Agent': 'AI-TRIONEX-AI' }
    }, (res) => {
      let out = '';
      res.on('data', (c) => out += c);
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(out));
          } else {
            reject(new Error(`Request failed with status ${res.statusCode}: ${out}`));
          }
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.ico': 'image/x-icon', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2' };

const server = http.createServer(async (req, res) => {
  try {
    const parsed = url.parse(req.url, true);
    const originalPath = parsed.pathname || '/index.html';
    const cleanPath = originalPath.toLowerCase().replace(/\/+$/, '') || '/index.html';
    const method = req.method.toUpperCase();

    console.log(`[${new Date().toLocaleTimeString()}] ${method} ${originalPath}`);
    if (Object.keys(parsed.query).length > 0) {
      console.log(`  Query: ${JSON.stringify(parsed.query)}`);
    }

    // Standard CORS for all responses
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Authorization, Origin, Accept');
    res.setHeader('Access-Control-Max-Age', '86400');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const matchPath = (parsed.pathname || '/').toLowerCase().split('?')[0].replace(/\/+$/, '') || '/';
    console.log(`  Match Path: ${matchPath}, Method: ${method}`);

    const sendJson = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    };

    // API: Config
    if (matchPath === '/api/config') {
      sendJson(200, {
        geminiKey: process.env.GEMINI_KEY || '',
        removeBgKey: process.env.REMOVEBG_KEY || '',
        openaiKey: process.env.OPENAI_KEY || '',
        googleClientId: process.env.GOOGLE_CLIENT_ID || '',
        facebookAppId: process.env.FACEBOOK_APP_ID || '',
        githubClientId: process.env.GITHUB_CLIENT_ID || ''
      });
      return;
    }

    // API: GitHub Auth
    if (matchPath === '/api/github-auth') {
      const code = parsed.query.code;
      const redirectUri = (parsed.query.redirect_uri || '').replace(/^"(.*)"$/, '$1');
      if (!code || !redirectUri) {
        res.writeHead(400); res.end('Missing code or redirect_uri');
        return;
      }
      const tokenRes = await httpsPost('github.com', '/login/oauth/access_token', {
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code: code, redirect_uri: redirectUri
      });
      const accessToken = tokenRes.access_token;
      if (!accessToken) {
        res.writeHead(302, { Location: redirectUri + '#error=no_token' }); res.end();
        return;
      }
      const userRes = await httpsGet('api.github.com', '/user', accessToken);
      const email = userRes.email || userRes.login + '@github.user';
      const name = userRes.name || userRes.login || 'User';
      res.writeHead(302, { Location: redirectUri + '#email=' + encodeURIComponent(email) + '&name=' + encodeURIComponent(name) });
      res.end();
      return;
    }

    // API: OTP Request
    if (matchPath === '/api/otp/request') {
      if (method !== 'POST') {
        res.writeHead(405); res.end('Method Not Allowed');
        return;
      }
      let body = '';
      req.on('data', c => body += c);
      req.on('end', async () => {
        try {
          const { email } = JSON.parse(body || '{}');
          if (!email) {
            res.writeHead(400); res.end(JSON.stringify({ success: false, message: 'Email required' }));
            return;
          }
          const otp = Math.floor(100000 + Math.random() * 900000).toString();
          otpStore.set(email.toLowerCase().trim(), { otp, expires: Date.now() + 5 * 60 * 1000 });

          const u = process.env.GMAIL_USER, p = process.env.GMAIL_PASS;
          if (!u || !p) {
            res.writeHead(500); res.end(JSON.stringify({ success: false, message: 'Gmail not configured in .env' }));
            return;
          }
          await nodemailer.createTransport({ service: 'gmail', auth: { user: u, pass: p } })
            .sendMail({
              from: `"Trionex AI" <${u}>`, to: email, subject: 'Your Trionex AI Verification Code',
              html: `
              <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
                <div style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:32px 24px;text-align:center;">
                  <h1 style="color:#ffffff;margin:0;font-size:24px;font-weight:700;letter-spacing:0.5px;">◇ Trionex AI</h1>
                </div>
                <div style="padding:32px 28px;">
                  <p style="color:#374151;font-size:16px;margin:0 0 8px;">Hello,</p>
                  <p style="color:#374151;font-size:16px;margin:0 0 24px;">We received a request to reset the password for your Trionex AI account. Use the verification code below to complete the process:</p>
                  <div style="background:#f3f4f6;border-radius:10px;padding:20px;text-align:center;margin:0 0 24px;">
                    <p style="color:#6b7280;font-size:13px;margin:0 0 8px;text-transform:uppercase;letter-spacing:1.5px;">Verification Code</p>
                    <p style="color:#1f2937;font-size:36px;font-weight:700;margin:0;letter-spacing:8px;">${otp}</p>
                  </div>
                  <p style="color:#6b7280;font-size:14px;margin:0 0 20px;">⏳ This code is valid for <strong>5 minutes</strong>. Please do not share it with anyone.</p>
                  <div style="border-top:1px solid #e5e7eb;padding-top:20px;">
                    <p style="color:#9ca3af;font-size:13px;margin:0;">🔒 If you did not request a password reset, you can safely ignore this email. Your account remains secure.</p>
                  </div>
                </div>
                <div style="background:#f9fafb;padding:16px 28px;text-align:center;border-top:1px solid #e5e7eb;">
                  <p style="color:#9ca3af;font-size:12px;margin:0;">© ${new Date().getFullYear()} Trionex AI — Experience premium AI tools without paying a single rupee.</p>
                </div>
              </div>`
            });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, message: 'OTP sent' }));
        } catch (e) {
          res.writeHead(500); res.end(JSON.stringify({ success: false, message: e.message }));
        }
      });
      return;
    }

    // API: OTP Verify
    if (matchPath === '/api/otp/verify') {
      if (method !== 'POST') {
        res.writeHead(405); res.end('Method Not Allowed');
        return;
      }
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const { email, otp } = JSON.parse(body || '{}');
          const key = (email || '').toLowerCase().trim();
          const record = otpStore.get(key);
          if (!record || record.otp !== otp || Date.now() > record.expires) {
            res.writeHead(400); res.end(JSON.stringify({ success: false, message: 'Invalid or expired OTP' }));
            return;
          }
          otpStore.delete(key);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, message: 'OTP verified' }));
        } catch (e) {
          res.writeHead(500); res.end(JSON.stringify({ success: false, message: 'Server error' }));
        }
      });
      return;
    }

    // API: Log Signup (CSV)
    if (matchPath === '/api/log-signup') {
      if (method !== 'POST') {
        res.writeHead(405); res.end('Method Not Allowed');
        return;
      }
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const { username, email, time } = JSON.parse(body || '{}');
          if (!email) {
            res.writeHead(400); res.end(JSON.stringify({ success: false, message: 'Email required' }));
            return;
          }
          const csvFile = path.join(__dirname, 'signup_data.csv');
          const dateStr = new Date().toISOString().split('T')[0];
          const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
          const csvLine = `${dateStr},${timeStr},"${username || ''}","${email}"\n`;

          // If file doesn't exist, add headers
          if (!fs.existsSync(csvFile)) {
            fs.writeFileSync(csvFile, 'Date,Time,Username,Email\n');
          }

          fs.appendFile(csvFile, csvLine, (err) => {
            if (err) {
              console.error('Error writing to CSV:', err);
              res.writeHead(500); res.end(JSON.stringify({ success: false, message: 'Error saving log' }));
            } else {
              console.log('Logged signup to CSV:', email);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ success: true }));
            }
          });
        } catch (e) {
          res.writeHead(500); res.end(JSON.stringify({ success: false, message: 'Server error' }));
        }
      });
      return;
    }



    // Static files fallback
    let fileToServe = originalPath;
    if (fileToServe === '/') fileToServe = '/index.html';
    const filePath = path.join(__dirname, fileToServe.replace(/^\//, '').replace(/\.\./g, ''));

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'text/plain' });
      fs.createReadStream(filePath).pipe(res);
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  } catch (err) {
    console.error('Server Error:', err);
    if (!res.headersSent) {
      res.writeHead(500);
      res.end('Internal Server Error');
    }
  }
});

server.listen(PORT, () => {
  console.log('App running at http://localhost:' + PORT + '/');
  console.log('Dashboard: http://localhost:' + PORT + '/dashboard.html');
  console.log('API config (keys from .env): http://localhost:' + PORT + '/api/config');
  if (!CLIENT_ID || !CLIENT_SECRET) {
    console.log('WARNING: Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env for GitHub login');
  }
  if (!process.env.GEMINI_KEY) {
    console.log('WARNING: Set GEMINI_KEY in .env for AI Chatbot');
  }
});
