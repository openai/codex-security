import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [
    fileURLToPath(new URL("../src/model-catalog.ts", import.meta.url)),
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const {
  findCatalogModel,
  latestAvailableUpgrade,
  readModelCatalog,
  recommendedNonCyberModel,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const current = model("scan-current", {
  id: "current-id",
  hidden: true,
  upgrade: "scan-next",
});
const next = model("scan-next", { upgradeInfo: { model: "scan-newest" } });
const newest = model("scan-newest", { isDefault: true });
const catalog = [newest, current, next];
assert.equal(findCatalogModel("current-id", catalog), current);
assert.equal(latestAvailableUpgrade(current.model, catalog), newest);
assert.equal(latestAvailableUpgrade("unknown", catalog), undefined);
assert.equal(latestAvailableUpgrade(newest.model, catalog), undefined);
assert.equal(recommendedNonCyberModel(catalog), newest);

const hidden = model("hidden-successor", { hidden: true, upgrade: next.model });
const cyber = model("example-cyber", { upgrade: hidden.model });
assert.equal(
  latestAvailableUpgrade(cyber.model, [cyber, hidden, next, newest]),
  newest,
);
assert.equal(latestAvailableUpgrade(cyber.model, [cyber, hidden]), undefined);
assert.equal(latestAvailableUpgrade(current.model, [current, next]), next);
assert.equal(latestAvailableUpgrade(current.model, [current]), undefined);
assert.equal(recommendedNonCyberModel([current, next]), undefined);
assert.equal(
  recommendedNonCyberModel([model("astra-cyber", { isDefault: true })]),
  undefined,
);
const astra = model("astra-cyber");
assert.equal(
  latestAvailableUpgrade("old-cyber", [
    model("old-cyber", { upgrade: astra.model }),
    astra,
  ]),
  astra,
);
const nonCyberDefault = model("scan-default", {
  isDefault: true,
  upgrade: astra.model,
});
assert.equal(
  recommendedNonCyberModel([nonCyberDefault, astra]),
  nonCyberDefault,
);
assert.equal(
  recommendedNonCyberModel([
    model("example-cyber", { isDefault: true, upgrade: newest.model }),
    newest,
  ]),
  newest,
);
assert.equal(
  latestAvailableUpgrade("first", [
    model("first", { upgrade: "second" }),
    model("second", { upgrade: "first" }),
  ]),
  undefined,
);
assert.equal(
  latestAvailableUpgrade("first", [
    model("first", { upgrade: "stale", upgradeInfo: { model: newest.model } }),
    model("stale"),
    newest,
  ]),
  newest,
);
assert.equal(
  latestAvailableUpgrade("gpt-1", [
    model("gpt-1"),
    model("gpt-99", { isDefault: true }),
  ]),
  undefined,
  "A default or numerically greater name is not an explicit upgrade.",
);

await withFakeCodex(
  {
    pages: [
      { data: [current], nextCursor: "later-page" },
      { data: [next, newest], nextCursor: null },
    ],
  },
  async ({ options, callsPath, argvPath }) => {
    const result = await readModelCatalog(options);
    assert.deepEqual(result, [current, next, newest]);
    assert.equal(
      latestAvailableUpgrade(current.model, result).model,
      newest.model,
    );
    const calls = await readCalls(callsPath);
    assert.deepEqual(
      calls.map((call) => call.method),
      [
        "initialize",
        "initialized",
        "account/read",
        "config/read",
        "model/list",
        "model/list",
      ],
    );
    assert.equal(calls[0].params.clientInfo.name, "codex_security_deep_scan");
    assert.equal(calls[0].params.clientInfo.title, "Codex Security Deep Scan");
    assert.deepEqual(calls[2].params, { refreshToken: false });
    assert.deepEqual(calls[3].params, {
      cwd: options.cwd,
      includeLayers: false,
    });
    assert.deepEqual(calls[4].params, { includeHidden: true });
    assert.deepEqual(calls[5].params, {
      includeHidden: true,
      cursor: "later-page",
    });
    assert.deepEqual(JSON.parse(await readFile(argvPath, "utf8")), [
      "--config",
      'model_provider="openai"',
      "app-server",
      "--stdio",
    ]);
  },
);

for (const account of [null, { type: "apiKey" }, { type: "amazonBedrock" }]) {
  await withFakeCodex({ account }, async ({ options, callsPath }) => {
    assert.equal(await readModelCatalog(options), undefined);
    assert.deepEqual(
      (await readCalls(callsPath)).map((call) => call.method),
      ["initialize", "initialized", "account/read"],
    );
  });
}

for (const config of [
  { model_provider: "example-provider" },
  { model_catalog_json: "/fixture/models.json" },
  {
    profile: "selected",
    profiles: { selected: { model_provider: "example-provider" } },
  },
  {
    profile: "selected",
    profiles: { selected: { model_catalog_json: "/fixture/models.json" } },
  },
]) {
  await withFakeCodex({ config }, async ({ options, callsPath }) => {
    assert.equal(await readModelCatalog(options), undefined);
    assert.equal(
      (await readCalls(callsPath)).some((call) => call.method === "model/list"),
      false,
    );
  });
}

for (const scenario of [
  { pages: [{ data: null, nextCursor: null }] },
  { pages: [{ data: [{ model: "unverified" }], nextCursor: null }] },
  {
    pages: [
      {
        data: [model("bad-effort", { supportedReasoningEfforts: [null] })],
        nextCursor: null,
      },
    ],
  },
  {
    pages: [
      {
        data: [model("bad-upgrade", { upgradeInfo: { model: 3 } })],
        nextCursor: null,
      },
    ],
  },
  {
    pages: [
      { data: [], nextCursor: "repeat" },
      { data: [], nextCursor: "repeat" },
    ],
  },
]) {
  await withFakeCodex(scenario, async ({ options }) => {
    await assert.rejects(readModelCatalog(options));
  });
}

await withFakeCodex({ failAt: "model/list" }, async ({ options }) => {
  await assert.rejects(readModelCatalog(options), (error) => {
    assert.equal(error.name, "AppServerError");
    assert.deepEqual(error.failure, {
      kind: "rpc",
      method: "model/list",
      code: -32601,
    });
    assert.doesNotMatch(error.message, /Deep Scan|permission.profile/);
    return true;
  });
});

await withFakeCodex(
  { hangAt: "model/list" },
  async ({ options, controller, ready }) => {
    const reading = readModelCatalog(options);
    await ready;
    const reason = new Error("Fixture cancellation");
    controller.abort(reason);
    await assert.rejects(reading, (error) => error === reason);
  },
);

const canceled = new AbortController();
canceled.abort(new Error("Canceled before model discovery"));
await assert.rejects(
  readModelCatalog({
    codexPath: "/fixture/must-not-run",
    cwd: "/fixture",
    configOverrides: [],
    signal: canceled.signal,
  }),
);

function model(name, extra = {}) {
  return {
    id: name,
    model: name,
    hidden: false,
    isDefault: false,
    defaultReasoningEffort: "high",
    supportedReasoningEfforts: [
      { reasoningEffort: "high" },
      { reasoningEffort: "xhigh" },
    ],
    ...extra,
  };
}

async function withFakeCodex(scenario, callback) {
  const root = await mkdtemp(
    path.join(tmpdir(), "codex-security-model-catalog-"),
  );
  const scriptPath = path.join(root, "fake-codex.mjs");
  const callsPath = path.join(root, "calls.jsonl");
  const argvPath = path.join(root, "argv.json");
  await writeFile(
    scriptPath,
    fakeCodexSource({ ...scenario, callsPath, argvPath }),
    "utf8",
  );
  const controller = new AbortController();
  const options = {
    codexPath: process.execPath,
    cwd: root,
    configOverrides: ['model_provider="openai"'],
    signal: controller.signal,
  };
  const originalSpawn = childProcess.spawn;
  const children = [];
  let markReady;
  const ready = new Promise((resolve) => {
    markReady = resolve;
  });
  childProcess.spawn = (command, args, spawnOptions) => {
    assert.equal(
      command,
      process.platform === "win32"
        ? path.toNamespacedPath(process.execPath)
        : process.execPath,
    );
    const child = originalSpawn(command, [scriptPath, ...args], spawnOptions);
    children.push(child);
    child.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("fixture/waiting")) markReady();
    });
    return child;
  };
  syncBuiltinESMExports();
  try {
    await callback({ options, callsPath, argvPath, controller, ready });
    for (const child of children) {
      assert.ok(
        child.exitCode !== null || child.signalCode !== null,
        "Catalog subprocess must close.",
      );
    }
  } finally {
    controller.abort();
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
}

function fakeCodexSource(scenario) {
  return `
import { appendFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
const fixture = JSON.parse(${JSON.stringify(JSON.stringify(scenario))});
writeFileSync(fixture.argvPath, JSON.stringify(process.argv.slice(2)));
let page = 0;
const lines = createInterface({ input: process.stdin });
lines.on("line", (line) => {
  const request = JSON.parse(line);
  appendFileSync(fixture.callsPath, JSON.stringify(request) + "\\n");
  if (request.method === "initialized") return;
  if (fixture.hangAt === request.method) {
    process.stdout.write(JSON.stringify({ method: "fixture/waiting" }) + "\\n");
    return;
  }
  if (fixture.failAt === request.method) {
    process.stdout.write(JSON.stringify({ id: request.id, error: { code: -32601, message: "Unavailable" } }) + "\\n");
    return;
  }
  const result = request.method === "initialize" ? {}
    : request.method === "account/read" ? { account: Object.hasOwn(fixture, "account") ? fixture.account : { type: "chatgpt" } }
    : request.method === "config/read" ? { config: fixture.config ?? { model_provider: "openai" } }
    : request.method === "model/list" ? (fixture.pages?.[page++] ?? { data: [], nextCursor: null })
    : undefined;
  process.stdout.write(JSON.stringify({ id: request.id, result }) + "\\n");
});
lines.on("close", () => process.exit(0));
`;
}

async function readCalls(file) {
  return (await readFile(file, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}
