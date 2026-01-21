import 'dotenv/config';
import { SMTPServer } from 'smtp-server';
import { google } from 'googleapis';

import fs from 'node:fs';

const GOOGLE_APPLICATION_CREDENTIALS = mustEnv('GOOGLE_APPLICATION_CREDENTIALS');
const GMAIL_IMPERSONATE = mustEnv('GMAIL_IMPERSONATE');

const SMTP_HOST = process.env.SMTP_HOST || '127.0.0.1';
const SMTP_PORT = Number(process.env.SMTP_PORT || 1025);

const MAX_BYTES = Number(process.env.MAX_BYTES || 25 * 1024 * 1024);
const ALLOW_RCPT_DOMAINS = (process.env.ALLOW_RCPT_DOMAINS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

function mustEnv(k) {
  const v = process.env[k];
  if (!v) throw new Error(`Missing required env var: ${k}`);
  return v;
}

function base64UrlEncode(buffer) {
  // Gmail expects base64url, no padding
  return buffer
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

function parseEmailDomain(addr = '') {
  const m = String(addr).match(/@([^>]+)>?$/);
  return m ? m[1].toLowerCase() : '';
}

function isTransientGoogleError(err) {
  const status = err?.code || err?.response?.status;
  return status === 429 || (status >= 500 && status <= 599);
}

function smtpReplyFromGoogleError(err) {
  const status = err?.code || err?.response?.status || 500;
  const msg = (err?.message || err?.response?.data?.error?.message || 'Gmail send failed')
    .toString()
    .slice(0, 200);

  // Map to SMTP-ish codes
  if (status === 401 || status === 403) return { code: 535, message: `5.7.8 Auth failed: ${msg}` };
  if (status === 400) return { code: 550, message: `5.5.0 Bad request: ${msg}` };
  if (status === 404) return { code: 550, message: `5.1.1 Not found: ${msg}` };
  if (status === 429) return { code: 451, message: `4.7.0 Rate limited: ${msg}` };
  if (status >= 500 && status <= 599) return { code: 451, message: `4.3.0 Temporary Gmail error: ${msg}` };

  return { code: 550, message: `5.0.0 Gmail error (${status}): ${msg}` };
}

function ensureMinimalHeaders(raw) {
  // Minimal “do not break things” header injection.
  // We only add Date if missing. We avoid rewriting From/To/Subject.
  const text = raw.toString('utf8');
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd === -1) return raw;

  const headers = text.slice(0, headerEnd);
  const body = text.slice(headerEnd + 4);

  const hasDate = /^date:/im.test(headers);
  if (hasDate) return raw;

  const dateLine = `Date: ${new Date().toUTCString()}\r\n`;
  const newText = headers + '\r\n' + dateLine + '\r\n' + body;
  return Buffer.from(newText, 'utf8');
}

function createGmailClient() {
  const key = JSON.parse(fs.readFileSync(GOOGLE_APPLICATION_CREDENTIALS, 'utf8'));

  const auth = new google.auth.JWT({
    email: key.client_email,      // veterano-mailer@veteranocc.iam.gserviceaccount.com
    key: key.private_key,
    scopes: ['https://www.googleapis.com/auth/gmail.send'],
    subject: GMAIL_IMPERSONATE,   // no-reply@veterano.cc
  });

  return google.gmail({ version: 'v1', auth });
}

const gmail = createGmailClient();

const server = new SMTPServer({
  // No AUTH, localhost-only trust boundary
  authOptional: true,
  disabledCommands: ['AUTH', 'STARTTLS'],
  disableReverseLookup: true,

  // Keep SMTP server behavior simple
  banner: 'smtp-gmail-bridge',

  // Size enforcement happens while streaming
  size: MAX_BYTES,

  onConnect(session, cb) {
    // Accept all loopback connections
    cb();
  },

  onRcptTo(address, session, cb) {
    if (ALLOW_RCPT_DOMAINS.length > 0) {
      const domain = parseEmailDomain(address.address);
      if (!ALLOW_RCPT_DOMAINS.includes(domain)) {
        const err = new Error(`Recipient domain not allowed: ${domain || '(unknown)'}`);
        err.responseCode = 550;
        return cb(err);
      }
    }
    cb();
  },

  async onData(stream, session, callback) {
    const envelopeFrom = session.envelope.mailFrom?.address || '';
    const rcptTo = (session.envelope.rcptTo || []).map(r => r.address).filter(Boolean);

    let total = 0;
    const chunks = [];

    stream.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BYTES) {
        // smtp-server will turn this into a 552 by default if we error here
        stream.pause();
        const err = new Error(`Message exceeds MAX_BYTES (${MAX_BYTES})`);
        err.responseCode = 552;
        stream.emit('error', err);
        return;
      }
      chunks.push(chunk);
    });

    stream.on('error', (err) => {
      callback(err);
    });

    stream.on('end', async () => {
      try {
        const raw = Buffer.concat(chunks);
        const normalized = ensureMinimalHeaders(raw);
        const rawB64Url = base64UrlEncode(normalized);

        // NOTE: Gmail uses headers inside the raw message for To/Cc/Bcc/etc.
        // Envelope rcptTo is NOT automatically applied, so ensure your internal app
        // sets proper To/Cc/Bcc headers (or add your own rewriting later).
        const resp = await gmail.users.messages.send({
          userId: GMAIL_IMPERSONATE,
          requestBody: { raw: rawB64Url },
        });

        const gmailId = resp?.data?.id || 'unknown';
        console.log(`[OK] from=${envelopeFrom} rcpt=${rcptTo.length} bytes=${normalized.length} gmailId=${gmailId}`);

        // SMTP success reply (include id for the calling app)
        callback(null, `2.0.0 Ok: queued as ${gmailId}`);
      } catch (err) {
        const transient = isTransientGoogleError(err);
        const reply = smtpReplyFromGoogleError(err);

        console.error(
          `[FAIL] from=${envelopeFrom} rcpt=${rcptTo.length} transient=${transient} err=${err?.message || err}`
        );

        const e = new Error(reply.message);
        e.responseCode = reply.code;
        callback(e);
      }
    });
  },
});

server.on('error', (err) => {
  console.error('SMTP server error:', err);
  process.exitCode = 1;
});

server.listen(SMTP_PORT, SMTP_HOST, () => {
  console.log(`smtp-gmail-bridge listening on ${SMTP_HOST}:${SMTP_PORT}`);
});
