import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { importSource } from "./import-module.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { createCodexSecurityArtifactWriterServer } = await importSource(
  path.join(import.meta.dirname, "../artifact-writer-main.ts"),
);
const { readDeepReductionSources } = await importSource(
  path.join(import.meta.dirname, "../src/artifact-deep-reducer.ts"),
);

async function worker(root: string, label: string) {
  const output = path.join(
    root,
    "artifacts/deep_discovery/workers",
    label,
    "output",
  );
  const reducerRoot = path.join(
    root,
    "artifacts/deep_discovery/dedup/run/output",
  );
  await fs.mkdir(output, { recursive: true });
  await fs.mkdir(reducerRoot, { recursive: true });
  const server = await createCodexSecurityArtifactWriterServer({
    CODEX_SECURITY_ARTIFACT_ROOT: output,
    CODEX_SECURITY_REPO_ROOT: root,
    CODEX_SECURITY_SCAN_ID: scanId,
  });
  const client = new Client({ name: "worker-draft-fixture", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    output,
    draft: (id: string) =>
      client.callTool({
        name: "record_codex_security_scan_draft",
        arguments: workerDraft([finding(id, `src/${id}.ts`)]),
      }),
    async findings() {
      const sources = await readDeepReductionSources({
        root: reducerRoot,
        repoRoot: root,
        scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: root,
          claimedWorkers: [
            { id: label, resultPath: path.join(output, "result.json") },
          ],
        },
      });
      return sources.discoveries[0].result.findings
        .map((row: { identity: { anchor: string } }) => row.identity.anchor)
        .sort();
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}

test("concurrent registered worker drafts retain both findings for reduction", async () => {
  const root = await temporaryDirectory("worker-draft-concurrent-", true);
  const w = await worker(root, "discovery-0001");
  try {
    const replies = await Promise.all([w.draft("first"), w.draft("second")]);
    for (const reply of replies) {
      assert.equal(reply.isError, undefined);
      assert.equal(
        JSON.parse((reply.content as { text: string }[])[0]!.text).status,
        "draft_written",
      );
    }
    assert.deepEqual(await w.findings(), ["first", "second"]);
  } finally {
    await w.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a blocked worker draft does not block another worker", async (t) => {
  const root = await temporaryDirectory("worker-draft-independent-", true);
  const first = await worker(root, "discovery-0001");
  const other = await worker(root, "discovery-0002");
  const blocked = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const rename = fs.rename;
  let paused = false;
  t.mock.method(fs, "rename", async (...args: Parameters<typeof rename>) => {
    if (
      !paused &&
      String(args[1]).startsWith(
        path.join(first.output, "checkpoints") + path.sep,
      )
    ) {
      paused = true;
      blocked.resolve();
      await release.promise;
    }
    return rename(...args);
  });
  const pending = first.draft("first");
  try {
    await blocked.promise;
    const reply = await other.draft("other");
    assert.equal(reply.isError, undefined);
    assert.deepEqual(await other.findings(), ["other"]);
    release.resolve();
    assert.equal((await pending).isError, undefined);
    assert.deepEqual(await first.findings(), ["first"]);
  } finally {
    release.resolve();
    await pending;
    t.mock.restoreAll();
    await Promise.all([first.close(), other.close()]);
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a failed worker write releases the next registered draft", async (t) => {
  const root = await temporaryDirectory("worker-draft-failure-", true);
  const w = await worker(root, "discovery-0001");
  const rename = fs.rename;
  let failed = false;
  t.mock.method(fs, "rename", async (...args: Parameters<typeof rename>) => {
    if (
      !failed &&
      String(args[1]).startsWith(path.join(w.output, "checkpoints") + path.sep)
    ) {
      failed = true;
      throw new Error("Injected checkpoint write failure");
    }
    return rename(...args);
  });
  try {
    const ids = ["first", "second"];
    const replies = await Promise.all(ids.map((id) => w.draft(id)));
    assert.equal(replies.filter((reply) => reply.isError).length, 1);
    const accepted = replies.findIndex((reply) => !reply.isError);
    assert.deepEqual(await w.findings(), [ids[accepted]]);
  } finally {
    t.mock.restoreAll();
    await w.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});
