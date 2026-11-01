import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { PassThrough, Readable } from 'node:stream';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';
import { BlobClient } from '@azure/storage-blob';
import archiver from 'archiver';
import { uploadToBlobStorage } from '../node_modules/@actions/artifact/lib/internal/upload/blob-upload.js';
import { createZipUploadStream } from '../node_modules/@actions/artifact/lib/internal/upload/zip.js';

const require = createRequire(import.meta.url);
const { compose } = require('readable-stream');
const { codes: { ERR_MISSING_ARGS } } = require('readable-stream/lib/ours/errors.js');
const uploadUrl = 'https://example.invalid/artifact';

function mockUpload(t, implementation) {
  t.mock.method(BlobClient.prototype, 'getBlockBlobClient', () => ({
    uploadStream: implementation,
  }));
}

function captureOutput(t) {
  let output = '';
  const write = process.stdout.write;
  // Expected failure diagnostics must not become annotations on the test job.
  t.mock.method(process.stdout, 'write', (chunk, encodingOrCallback, callback) => {
    // The Node test runner also sends binary reporter events through stdout.
    if (typeof chunk !== 'string') return write.call(process.stdout, chunk, encodingOrCallback, callback);
    output += chunk;
    if (typeof encodingOrCallback === 'function') encodingOrCallback();
    else if (typeof callback === 'function') callback();
    return true;
  });
  return () => output;
}

test('missing stream arguments retain their names and TypeError', () => {
  assert.throws(() => compose(), {
    name: 'TypeError',
    code: 'ERR_MISSING_ARGS',
    message: 'The "streams" argument must be specified',
  });
  for (const [names, message] of [
    [['source', 'destination'], 'The "source" and "destination" arguments must be specified'],
    [['source', 'destination', 'callback'], 'The "source", "destination", and "callback" arguments must be specified'],
  ]) {
    const error = new ERR_MISSING_ARGS(...names);
    assert.ok(error instanceof TypeError);
    assert.equal(error.code, 'ERR_MISSING_ARGS');
    assert.equal(error.message, message);
  }
});

test('artifact upload preserves bytes, upload size, and SHA-256', async t => {
  const chunks = [Buffer.from('first report\n'), Buffer.from('second report\n')];
  let uploaded;
  mockUpload(t, async (input, _bufferSize, _concurrency, options) => {
    const received = [];
    for await (const chunk of input) received.push(chunk);
    uploaded = Buffer.concat(received);
    options.onProgress({ loadedBytes: uploaded.length });
    assert.equal(options.blobHTTPHeaders.blobContentType, 'application/zip');
  });
  const result = await uploadToBlobStorage(uploadUrl, Readable.from(chunks), 'application/zip');
  const expected = Buffer.concat(chunks);
  assert.deepEqual(uploaded, expected);
  assert.deepEqual(result, {
    uploadSize: expected.length,
    sha256Hash: createHash('sha256').update(expected).digest('hex'),
  });
});

test('source failures reject artifact upload with the original error', { timeout: 5000 }, async t => {
  const source = new PassThrough();
  const failure = new Error('Synthetic report read failure');
  let destination;
  let signal;
  mockUpload(t, async (input, _bufferSize, _concurrency, options) => {
    destination = input;
    signal = options.abortSignal;
    for await (const _chunk of input) { /* Consume the upload stream. */ }
  });
  const upload = uploadToBlobStorage(uploadUrl, source, 'application/zip');
  source.write('partial report');
  source.destroy(failure);
  await assert.rejects(upload, error => error === failure);
  assert.equal(destination.destroyed, true);
  assert.equal(signal.aborted, true);
});

test('remote upload failures cancel the source stream', { timeout: 5000 }, async t => {
  const source = new PassThrough();
  const failure = new Error('Synthetic upload failure');
  let destination;
  mockUpload(t, async input => {
    destination = input;
    throw failure;
  });
  await assert.rejects(uploadToBlobStorage(uploadUrl, source, 'application/zip'), error => error === failure);
  assert.equal(source.destroyed, true);
  assert.equal(destination.destroyed, true);
});

test('archive errors reject upload without an uncaught error or rejection', { timeout: 5000 }, async t => {
  const output = captureOutput(t);
  const create = archiver.create;
  let archive;
  t.mock.method(archiver, 'create', (...args) => {
    archive = create(...args);
    return archive;
  });
  mockUpload(t, async input => {
    for await (const _chunk of input) { /* Consume the upload stream. */ }
  });
  const source = await createZipUploadStream([{ sourcePath: null, destinationPath: 'reports/' }]);
  const upload = uploadToBlobStorage(uploadUrl, source, 'application/zip');
  const failure = new Error('Synthetic archive compression failure');
  // Exercise both the archive error event and its finalize() rejection.
  archive._module.engine.emit('error', failure);
  await assert.rejects(upload, error => error === failure);
  await setImmediate();
  assert.equal(source.destroyed, true);
  assert.equal(archive.destroyed, true);
  assert.match(output(), /^::error::An error has occurred while creating the zip file for upload$/m);
  assert.ok(output().includes(`Error: ${failure.message}`));
});

test('a completed ZIP archive still uploads successfully', { timeout: 5000 }, async t => {
  let uploaded;
  mockUpload(t, async (input, _bufferSize, _concurrency, options) => {
    const received = [];
    for await (const chunk of input) received.push(chunk);
    uploaded = Buffer.concat(received);
    options.onProgress({ loadedBytes: uploaded.length });
  });
  const source = await createZipUploadStream([{ sourcePath: null, destinationPath: 'reports/' }]);
  const result = await uploadToBlobStorage(uploadUrl, source, 'application/zip');
  assert.equal(uploaded.readUInt32LE(0), 0x04034b50);
  assert.equal(uploaded.readUInt32LE(uploaded.length - 22), 0x06054b50);
  assert.equal(result.uploadSize, uploaded.length);
  assert.equal(result.sha256Hash, createHash('sha256').update(uploaded).digest('hex'));
});

test('archive errors during file registration reach the returned stream', { timeout: 5000 }, async t => {
  const output = captureOutput(t);
  const create = archiver.create;
  const failure = new Error('Synthetic archive source failure');
  t.mock.method(archiver, 'create', (...args) => {
    const archive = create(...args);
    archive.file = () => {
      archive.emit('error', failure);
      return archive;
    };
    return archive;
  });
  mockUpload(t, async input => {
    for await (const _chunk of input) { /* Consume the upload stream. */ }
  });
  const source = await createZipUploadStream([{
    sourcePath: 'report.json', destinationPath: 'report.json',
    stats: { isSymbolicLink: () => false },
  }]);
  await assert.rejects(uploadToBlobStorage(uploadUrl, source, 'application/zip'), error => error === failure);
  assert.match(output(), /^::error::An error has occurred while creating the zip file for upload$/m);
  assert.ok(output().includes(`Error: ${failure.message}`));
});
