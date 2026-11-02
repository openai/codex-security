const { fork } = require('node:child_process');
const http = require('node:http');
const config = require('./deploy.json');
const parse = require('./parse.cjs');

const worker = config.worker === 'local' && Object.values(config.routes).includes('queue')
  ? fork(require.resolve('./worker.cjs'), [], { serialization: 'advanced' })
  : null;

async function ingest(req, res) {
  const delivery = config.routes[req.url];
  if (req.method !== 'POST' || !delivery) {
    res.writeHead(404).end();
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks);
  if (delivery === 'direct') {
    const mail = await parse(raw);
    res.writeHead(200).end(mail.text || '');
    return;
  }
  if (delivery !== 'queue') throw new Error('Invalid delivery mode');
  if (worker) {
    worker.send(raw);
  } else {
    const result = await fetch(config.workerUrl, { method: 'POST', body: raw });
    if (!result.ok) throw new Error('Worker rejected message');
  }
  res.writeHead(202).end();
}

http.createServer((req, res) => {
  ingest(req, res).catch(() => res.writeHead(400).end());
}).listen(process.env.PORT || 8080);
