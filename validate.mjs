import { google } from 'googleapis';
import fs from 'node:fs';
import 'dotenv/config';

const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
const subject = process.env.GMAIL_IMPERSONATE;

if (!keyPath || !subject) {
  console.error('Missing GOOGLE_APPLICATION_CREDENTIALS or GMAIL_IMPERSONATE in env');
  process.exit(1);
}

const key = JSON.parse(fs.readFileSync(keyPath, 'utf8'));

const auth = new google.auth.JWT({
  email: key.client_email,
  key: key.private_key,
  scopes: ['https://www.googleapis.com/auth/gmail.send'],
  subject,
});

const gmail = google.gmail({ version: 'v1', auth });

const raw = Buffer.from(
  `From: ${subject}\r\nTo: ${subject}\r\nSubject: test\r\n\r\nhello\r\n`,
  'utf8'
).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

try {
  const r = await gmail.users.messages.send({ userId: subject, requestBody: { raw } });
  console.log('OK', r.data.id);
} catch (e) {
  console.error('FAIL', e?.response?.data || e.message);
  process.exit(1);
}
