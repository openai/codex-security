// Opt-in real Chromium smoke test; see README.md for prerequisites and invocation.
import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {EventEmitter, once} from 'node:events';
import {copyFile, mkdir, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {fixture} from './fixture.mjs';

// Only the CDP requests needed by this workflow; Chrome's pipe avoids a debug port.
function launchChrome(executable, profile) {
  const child = spawn(executable, [
    '--headless', '--remote-debugging-pipe', `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--window-size=1440,1000', 'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe']});
  const events = new EventEmitter(), pending = new Map();
  let id = 0, buffer = '', stderr = '', failure;
  child.stderr.setEncoding('utf8').on('data', data => { stderr += data; });
  function fail(error) {
    failure = error;
    for (const request of pending.values()) request.reject(error);
    events.emit('failure', error);
  }
  child.on('error', fail);
  child.on('exit', code => fail(new Error(`Chromium exited (${code}): ${stderr}`)));
  child.stdio[3].on('error', fail);
  child.stdio[4].setEncoding('utf8').on('data', data => {
    buffer += data;
    let boundary;
    while ((boundary = buffer.indexOf('\0')) !== -1) {
      const message = JSON.parse(buffer.slice(0, boundary));
      buffer = buffer.slice(boundary + 1);
      if (message.id) {
        const request = pending.get(message.id);
        if (message.error) request?.reject(new Error(JSON.stringify(message.error)));
        else request?.resolve(message.result);
      } else if (message.method === 'Runtime.exceptionThrown') {
        fail(new Error(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text));
      } else events.emit(message.method, message.params);
    }
  });
  return {
    async send(method, params = {}, sessionId) {
      if (failure) throw failure;
      const requestId = ++id;
      let timer;
      try {
        return await new Promise((resolve, reject) => {
          timer = setTimeout(() => reject(new Error(`CDP timeout: ${method}\n${stderr}`)), 15_000);
          pending.set(requestId, {resolve, reject});
          child.stdio[3].write(JSON.stringify({id: requestId, method, params, sessionId}) + '\0');
        });
      } finally { clearTimeout(timer); pending.delete(requestId); }
    },
    async event(method, predicate = () => true) {
      if (failure) throw failure;
      let listener, rejectListener, timer;
      try {
        return await new Promise((resolve, reject) => {
          listener = value => { if (predicate(value)) resolve(value); };
          rejectListener = reject;
          events.on(method, listener).on('failure', rejectListener);
          timer = setTimeout(() => reject(new Error(`No ${method} event from Chromium`)), 15_000);
        });
      } finally {
        clearTimeout(timer);
        events.off(method, listener).off('failure', rejectListener);
      }
    },
    async close() {
      if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
      const exited = once(child, 'exit');
      child.kill();
      const timer = setTimeout(() => child.kill('SIGKILL'), 5_000);
      try { await exited; } finally { clearTimeout(timer); }
    },
  };
}

test('downloaded SVG preserves the selected route and unverified detection basis', {timeout: 60_000}, async t => {
  assert.ok(process.env.CHROME_PATH, 'Set CHROME_PATH to an installed Chrome/Chromium executable; this check never skips.');
  const work = await mkdtemp(join(tmpdir(), 'threat-model-browser-'));
  let server, chrome;
  t.after(async () => {
    await chrome?.close();
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    await rm(work, {recursive: true, force: true});
  });
  const skill = process.env.BROWSER_SMOKE_SKILL_DIR || fileURLToPath(new URL('../../../skills/threat-model-visualize/', import.meta.url));
  const {model, assessment} = fixture();
  const htmlPath = join(work, 'explorer.html'), downloadPath = join(work, 'downloads');
  await mkdir(downloadPath);
  await writeFile(join(work, 'model.json'), JSON.stringify(model));
  await writeFile(join(work, 'assessment.md'), assessment);
  execFileSync(process.env.PYTHON || 'python3', [join(skill, 'scripts/build_explorer.py'),
    join(work, 'model.json'), '--assessment', join(work, 'assessment.md'), '--output', htmlPath]);
  const html = await readFile(htmlPath);
  server = createServer((_request, response) => {
    response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'}).end(html);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  chrome = launchChrome(process.env.CHROME_PATH, join(work, 'profile'));
  t.diagnostic(JSON.stringify(await chrome.send('Browser.getVersion')));
  await chrome.send('Browser.setDownloadBehavior', {behavior: 'allow', downloadPath, eventsEnabled: true});
  const {targetId} = await chrome.send('Target.createTarget', {url: 'about:blank'});
  const {sessionId} = await chrome.send('Target.attachToTarget', {targetId, flatten: true});
  const send = (method, params) => chrome.send(method, params, sessionId);
  await send('Page.enable');
  await send('Runtime.enable');
  const evaluate = async expression => {
    const {result, exceptionDetails} = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    assert.equal(exceptionDetails, undefined, JSON.stringify(exceptionDetails));
    return result.value;
  };
  const loaded = chrome.event('Page.loadEventFired');
  await send('Page.navigate', {url: `http://127.0.0.1:${server.address().port}/explorer.html`});
  await loaded;
  await evaluate('document.fonts.ready.then(() => true)');
  async function node(selector) {
    const {root} = await send('DOM.getDocument');
    const {nodeId} = await send('DOM.querySelector', {nodeId: root.nodeId, selector});
    assert.notEqual(nodeId, 0, `Missing real DOM element: ${selector}`);
    return nodeId;
  }
  async function click(selector) {
    const nodeId = await node(selector);
    await send('DOM.scrollIntoViewIfNeeded', {nodeId});
    const {model: box} = await send('DOM.getBoxModel', {nodeId});
    const x = (box.content[0] + box.content[4]) / 2, y = (box.content[1] + box.content[5]) / 2;
    await send('Input.dispatchMouseEvent', {type: 'mousePressed', x, y, button: 'left', clickCount: 1});
    await send('Input.dispatchMouseEvent', {type: 'mouseReleased', x, y, button: 'left', clickCount: 1});
  }
  await click('[data-scenario="H1"]');
  await node('#route-select');
  await evaluate(`(() => {
    const select = document.querySelector('#route-select');
    select.value = 'alternate-route';
    select.dispatchEvent(new Event('change', {bubbles: true}));
  })()`);
  assert.equal(await evaluate('document.querySelector("#route-select").value'), 'alternate-route');
  await click('[data-panel="controls"]');
  await click('[data-control="audit"]');
  assert.equal(await evaluate('document.querySelector("[data-control=audit]").getAttribute("aria-pressed")'), 'true');
  await click('#in');
  assert.match(await evaluate('document.querySelector("#viewport").getAttribute("transform")'), /1\.2/);
  const downloaded = chrome.event('Browser.downloadProgress', value => value.state === 'completed');
  // Observe the pending download before clicking so an export exception is reported immediately.
  const [download] = await Promise.all([downloaded, click('#svg-download')]);
  const svgPath = join(downloadPath, 'threat-model-map.svg');
  const svg = await readFile(svgPath, 'utf8');
  if (process.env.BROWSER_SMOKE_ARTIFACTS) {
    const artifacts = resolve(process.env.BROWSER_SMOKE_ARTIFACTS);
    await mkdir(artifacts, {recursive: true});
    await copyFile(htmlPath, join(artifacts, 'explorer.html'));
    await copyFile(svgPath, join(artifacts, 'threat-model-map.svg'));
  }
  const exported = await evaluate(`(() => {
    const doc = new DOMParser().parseFromString(${JSON.stringify(svg)}, 'image/svg+xml');
    return {error: doc.querySelector('parsererror')?.textContent, root: doc.documentElement.localName,
      viewport: !!doc.querySelector('#viewport'), transform: doc.querySelector('#viewport')?.getAttribute('transform'),
      active: doc.querySelector('[data-edge="alternate-flow"]')?.getAttribute('data-path-state'),
      other: doc.querySelector('[data-edge="primary-flow"]')?.getAttribute('data-path-state'),
      text: [...doc.querySelectorAll('text')].map(node => node.textContent).join(' ')};
  })()`);
  assert.equal(exported.error, undefined);
  assert.equal(exported.root, 'svg');
  assert.equal(exported.viewport, true);
  assert.equal(exported.transform, null, 'Downloaded map must remove the live zoom transform');
  assert.equal(exported.active, 'active');
  assert.equal(exported.other, 'context');
  assert.match(exported.text, /Documented flow: Alternate service flow/);
  assert.doesNotMatch(exported.text, /Documented flow: Primary service flow/);
  assert.match(exported.text, /Detects activity · path continues/);
  assert.match(exported.text, /EXISTING · EFFECT UNVERIFIED/, 'Export must retain the unverified detection qualification');
  assert.match(exported.text, /The hook is enabled\. Requests continue\./);
  t.diagnostic(`Read and XML-parsed the browser download (${download.receivedBytes} bytes).`);
});
