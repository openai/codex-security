import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { scenarios, setupInventory } from "./inventory.mjs";

const primary = "release_record";
const archive = "archived_release_record";
const query = { service: "sample-worker", revision: "a".repeat(40) };
const expectedStatuses = {
  healthy: ["ok", "ok", "not_found"],
  transient: ["rate_limited", "ok", "not_found"],
  persistent: ["rate_limited", "rate_limited", "not_found"],
  alternate: ["rate_limited", "rate_limited", "ok"],
  partial: ["partial", "partial", "not_found"],
};

function fixture(t, scenario, digest) {
  const directory = mkdtempSync(join(tmpdir(), "release-inventory-"));
  t.after(() => rmSync(directory, { force: true, recursive: true }));
  return setupInventory({ directory, scenario, ...query, digest });
}

function calls(config, requests) {
  const rpc = [
    {
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        clientInfo: { name: "test", version: "1" },
        capabilities: {},
      },
    },
    { method: "notifications/initialized" },
    { id: 2, method: "tools/list" },
    ...requests.map(([name, args = query], index) => ({
      id: index + 3,
      method: "tools/call",
      params: { name, arguments: args },
    })),
  ];
  const { command, args } = config.codex.mcp_servers.service_records;
  const child = spawnSync(command, args, {
    encoding: "utf8",
    input:
      rpc.map((req) => JSON.stringify({ jsonrpc: "2.0", ...req })).join("\n") +
      "\n",
  });
  assert.ifError(child.error);
  assert.equal(child.status, 0, child.stderr);
  const messages = child.stdout.trim().split("\n").map(JSON.parse);
  assert.equal(messages.length, requests.length + 2);
  assert.equal(messages[0].result.protocolVersion, "2025-03-26");
  assert.deepEqual(
    messages[1].result.tools.map((t) => t.name),
    [primary, archive],
  );
  return messages.slice(2).map((m) => m.result);
}

for (const scenario of scenarios) {
  test(`stdio release inventory journals the actual ${scenario} responses`, (t) => {
    const { config, journalPath, expected } = fixture(t, scenario);
    assert.match(expected.artifactDigest, /^sha256:[0-9a-f]{64}$/);
    assert(!JSON.stringify(config).includes(expected.artifactDigest));
    const requests = [[archive], [primary], [primary], [archive]];
    const responses = calls(config, requests);
    const log = readFileSync(journalPath, "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      log.map((r) => r.status),
      ["not_found", ...expectedStatuses[scenario]],
    );
    for (const [i, reply] of responses.entries()) {
      const { name, arguments: args, status, payload } = log[i];
      assert.equal(name, requests[i][0]);
      assert.deepEqual(args, query);
      assert.equal(reply.isError ?? false, status === "rate_limited");
      assert.deepEqual(reply.structuredContent, payload);
      assert.deepEqual(JSON.parse(reply.content[0].text), payload);
      if (status === "ok") assert.deepEqual(payload, expected);
      else assert(!JSON.stringify(reply).includes(expected.artifactDigest));
      if (status === "rate_limited") assert.equal(payload.code, 429);
      if (status === "partial") {
        assert.equal(payload.partial, true);
        assert.equal(payload.artifactDigest, undefined);
        assert.match(payload.message, /rate limit/);
      }
    }
  });
}

test("only a matching lookup consumes the transient failure and recovery survives a reconnect", (t) => {
  const { config, expected } = fixture(t, "transient");
  const [wrongService, wrongRevision, first] = calls(config, [
    [primary, { ...query, service: "other-worker" }],
    [primary, { ...query, revision: "b".repeat(40) }],
    [primary],
  ]);
  assert.equal(wrongService.structuredContent.found, false);
  assert.equal(wrongRevision.structuredContent.found, false);
  assert.equal(first.structuredContent.code, 429);
  assert.deepEqual(calls(config, [[primary]])[0].structuredContent, expected);
  const sibling = fixture(t, "transient", expected.artifactDigest);
  const [throttled, retried] = calls(sibling.config, [[primary], [primary]]);
  assert.equal(throttled.structuredContent.code, 429);
  assert.deepEqual(retried.structuredContent, expected);
});
