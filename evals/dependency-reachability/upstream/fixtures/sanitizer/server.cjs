const http = require('node:http');
const qp = require('nodemailer/lib/qp');
const { simpleParser } = require('../index.js');
const { boundary } = require('./archive.json');

async function archive(req, res) {
  if (req.method !== 'POST' || req.url !== '/archive') {
    res.writeHead(404).end();
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const attachment = qp.wrap(qp.encode(Buffer.concat(chunks)));
  const message = [
    'From: uploads@example.invalid',
    'To: archive@example.invalid',
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: application/octet-stream',
    'Content-Disposition: attachment; filename="upload.bin"',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    attachment,
    `--${boundary}--`,
    '',
  ].join('\r\n');
  const parsed = await simpleParser(message);
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ attachments: parsed.attachments.length }));
}

http.createServer((req, res) => {
  archive(req, res).catch(() => res.writeHead(400).end());
}).listen(process.env.PORT || 8080);
