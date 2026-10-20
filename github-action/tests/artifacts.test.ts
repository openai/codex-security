import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { uploadReports } from '../src/artifacts.js';
import { parseInputs } from '../src/inputs.js';

test('enterprise artifacts use the runner results service through the real client', async t => {
  const root = await mkdtemp(join(tmpdir(), 'action-artifact-'));
  t.after(() => rm(root, {recursive:true, force:true}));
  const previous = {...process.env};
  t.after(() => {
    for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
    Object.assign(process.env, previous);
  });
  const requests: {url?: string; authorization?: string; body: any}[] = [];
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    requests.push({url:request.url, authorization:request.headers.authorization, body:JSON.parse(body)});
    // Stop after artifact creation so this test needs no external blob service.
    response.writeHead(200, {'Content-Type':'application/json'});
    response.end(JSON.stringify({ok:false}));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const payload = Buffer.from(JSON.stringify({scp:'Actions.Results:synthetic-run:synthetic-job'})).toString('base64url');
  const token = `e30.${payload}.synthetic-signature`;
  Object.assign(process.env, {
    GITHUB_SERVER_URL:'https://example-enterprise.ghe.com',
    ACTIONS_RESULTS_URL:`http://127.0.0.1:${address.port}`,
    ACTIONS_RUNTIME_TOKEN:token,
  });
  await assert.rejects(uploadReports(new Map([['findings.json', Buffer.from('{}')]]), parseInputs(() => '', root), root),
    /CreateArtifact: response from backend was not ok/);
  assert.equal(requests.length, 1);
  assert.match(requests[0].url ?? '', /\/twirp\/.*\.ArtifactService\/CreateArtifact$/);
  assert.equal(requests[0].authorization, `Bearer ${token}`);
  assert.equal(requests[0].body.workflow_run_backend_id, 'synthetic-run');
  assert.equal(requests[0].body.workflow_job_run_backend_id, 'synthetic-job');
  assert.equal(requests[0].body.name, 'codex-security');
  assert.deepEqual(await readdir(root), []);
});
