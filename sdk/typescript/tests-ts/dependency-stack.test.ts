import { expect, test } from "bun:test";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { parse as parseToml } from "smol-toml";
import { prepareStackPacket } from "../src/stack-packet.js";
import { stackPacketWorkItems } from "../src/dependency-stack-packet.js";
import { sqliteDatabaseOpener } from "../src/runtime.js";
import type { DependencyClaimReference } from "../src/dependency-stack-claims.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "../src/dependency-stack-run.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const cve = "CVE-2099-0001";
const condition = "Caller controls the decoder input.";
const callerEvidence = { path: "app.js", startLine: 1, endLine: 2 };
async function sample(
  root: string,
  bindSource: boolean,
  separateImage?: "same" | "other",
  callerSource = "export function request(bytes) {\n  return decode(bytes);\n}\n",
) {
  const repo = join(root, "target");
  await mkdir(repo);
  git(repo, "init", "--quiet");
  await writeFile(join(repo, "app.js"), callerSource);
  git(repo, "add", "app.js");
  git(
    repo,
    "-c",
    "commit.gpgSign=false",
    "commit",
    "--quiet",
    "-m",
    "Add sample caller",
  );
  const sha = git(repo, "rev-parse", "HEAD");
  const source = {
    id: "input",
    function: "request",
  };
  const sink = {
    id: "decode",
    function: "decode",
    package: "sample-codec",
    versionScheme: "semver",
    affectedVersions: ["<2.0.0"],
    preconditions: [condition],
  };
  const observation = {
    id: "call",
    stackHash: "sample",
    framesTruncated: false,
    sourceIndex: 1,
    sinkIndex: 0,
    sinkIds: [sink.id],
    bindings: [
      {
        package: sink.package,
        frameIndices: [0],
        version: "1.0.0",
        imageDigest: "sha256:" + "a".repeat(64),
        provenance: "sample process",
        ...(bindSource && { sourceSha: sha }),
      },
      ...(separateImage
        ? [
            {
              package: "sample-app",
              version: "1.0.0",
              provenance: "sample application",
              sourceSha: sha,
              imageDigest:
                "sha256:" + (separateImage === "same" ? "a" : "b").repeat(64),
            },
          ]
        : []),
    ],
    frames: [
      { name: "decode", type: "javascript", offset: "9007199254740993" },
      { name: "request", type: "javascript", location: "app.js", line: 2 },
    ],
  };
  const documents = {
    sources: { format: "codex-security.stack-sources/v1", sources: [source] },
    sinks: {
      format: "codex-security.stack-sinks/v1",
      cve,
      advisory: {
        url: "https://example.invalid/advisories/decoder",
        summary: "Sample decoder accepts an invalid length.",
      },
      sinks: [sink],
    },
    stacks: {
      format: "codex-security.sampled-stacks/v1",
      target: { repository: "example/decoder", sha },
      origin: { source: "test" },
      frameOrder: "leaf_first",
      queries: [
        {
          id: "request",
          scope: {
            service: "decoder",
            window: {
              start: "2026-01-01T00:00:00Z",
              end: "2026-01-02T00:00:00Z",
            },
          },
          selectors: {
            sources: [source.function],
            sinks: [sink.function],
          },
          groups: [
            {
              id: "example",
              status: "observed",
              truncated: false,
              observations: [observation],
            },
          ],
        },
      ],
    },
  };
  for (const [role, doc] of Object.entries(documents))
    await writeFile(join(root, role + ".json"), JSON.stringify(doc));
  return {
    repo,
    sourcesPath: join(root, "sources.json"),
    sinksPath: join(root, "sinks.json"),
    stacksPath: join(root, "stacks.json"),
  };
}

async function startProof(
  root: string,
  files: Awaited<ReturnType<typeof sample>>,
  legacyCapture = false,
) {
  const inputs = join(root, "packet"),
    state = join(root, "attempt.sqlite");
  await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  await executeStackRun("init", { state, repo: files.repo, inputs });
  if (legacyCapture) {
    // Packet-backed attempts created before run next supplied captures had no
    // protocol record; their claim receipts identify the read-stacks command.
    const db = sqliteDatabaseOpener()(state);
    try {
      db.exec(
        "DELETE FROM records WHERE kind = 'stack-protocol' AND id = 'capture-origin'",
      );
    } finally {
      db.close();
    }
  }
  const call = (command: string, input?: unknown) =>
    executeStackRun(command, { state, input });
  const { workItem, receiptId, rootFirstRawIndices } = (await call("next")) as {
    workItem: { id: string; observation: { bindings?: unknown[] } };
    receiptId: string;
    rootFirstRawIndices: number[];
  };
  const capture = { ...workItem, receiptId, rootFirstRawIndices };
  const write = {
    operationId: "proof",
    claims: [
      {
        id: "caller",
        scope: "sample caller",
        payload: "The caller supplies bytes to decode.",
        evidence: [callerEvidence],
        receiptSelections: (capture.observation.bindings ?? []).map(
          (_, index) => ({
            receiptId,
            textBlock: null,
            record: ["observation", "bindings", index],
          }),
        ),
      },
    ],
  };
  const { claims } = (await call("record-claims", write)) as {
    claims: DependencyClaimReference[];
  };
  const row = {
    workItemId: workItem.id,
    reason: "The caller supplies the decoder input.",
    verdict: "exploitable",
    supportingClaims: claims,
    attackerControlClaim: claims[0],
    use: {
      location: "decoder",
      component: "sample-codec",
      version: "1.0.0",
      deployment: "confirmed",
      verdict: "exploitable",
      reason: "The captured build accepts the input.",
      evidence: [
        {
          ...callerEvidence,
          supports: ["affected_copy", "affected_use", "running", "access"],
        },
      ],
      proof: {
        sink: { function: "decode", callSite: { path: "app.js", line: 2 } },
        conditions: [
          {
            label: condition,
            status: "met",
            explanation: "The parameter is passed to decode.",
            citations: [{ path: "app.js", line: 2 }],
          },
        ],
      },
    },
  };
  return { inputs, state, call, capture, claims, write, row };
}

test("an unchanged finalized packet with a legacy read-stacks receipt retains its report bytes", async () => {
  await using dir = await scopedTemporaryDirectory("stack-legacy-final-");
  const files = await sample(dir.path, true);
  const { state, call, claims, row } = await startProof(dir.path, files, true);
  const queried = (await call("query-claims", { ids: ["caller"] })) as {
    claims: { evidence: { receipts: { origin: { tool: string } }[] } }[];
  };
  expect(queried.claims[0]!.evidence.receipts[0]!.origin.tool).toBe(
    "read-stacks",
  );
  await call("record-assessments", { items: [row] });
  const original = await call("finalize");
  expect(original).toMatchObject({ claims });
  expect(original).not.toHaveProperty("effectiveInputDigest");
  const originalBytes = JSON.stringify(original);
  const savedBytes = () => {
    const db = sqliteDatabaseOpener()(state);
    try {
      const statement = db.prepare(
        "SELECT value FROM records WHERE kind = 'report' AND id = 'final'",
      );
      try {
        const [row] = statement.all() as { value: string }[];
        return row!.value;
      } finally {
        statement.finalize?.();
      }
    } finally {
      db.close();
    }
  };
  const saved = savedBytes();
  expect(JSON.stringify(await readFinalStackReport(state))).toBe(originalBytes);
  expect(JSON.stringify(await call("finalize"))).toBe(originalBytes);
  expect(savedBytes()).toBe(saved);
});

for (const [label, bindSource, separateImage, expectedPositive] of [
  ["source and version in one binding", true, undefined, true],
  ["source not recorded", false, undefined, false],
  ["source and version in the same image", false, "same", true],
  ["source and version in different images", false, "other", false],
] as const) {
  test("stack verdict with " + label, async () => {
    await using dir = await scopedTemporaryDirectory("stack-proof-");
    const files = await sample(dir.path, bindSource, separateImage);
    const { inputs, state, call, capture, claims, write, row } =
      await startProof(dir.path, files);
    expect(capture).toMatchObject({
      rootFirstRawIndices: [1, 0],
      observation: { frames: [{ offset: "9007199254740993" }, {}] },
    });
    expect(await call("record-claims", write)).toEqual({ claims });
    expect(await call("query-claims", { ids: ["caller"] })).toMatchObject({
      claims: [{ ...claims[0], state: "recorded" }],
    });
    if (!expectedPositive) {
      await expect(
        call("record-assessments", { items: [row] }),
      ).rejects.toThrow(/build-to-source binding/);
      await expect(call("finalize")).rejects.toThrow();
      return;
    }
    await call("record-assessments", { items: [row] });
    const report = await call("finalize");
    expect(report).toMatchObject({
      verdict: "exploitable",
      reviewPolicy: "single_agent",
      coverage: { total: 1, assessed: 1 },
    });
    expect(report).toEqual(await readFinalStackReport(state));
    await expect(
      call("record-evidence", {
        scope: "caller",
        question: "Who supplies bytes?",
        claim: "Caller supplied bytes.",
        evidence: [callerEvidence],
      }),
    ).rejects.toThrow(/finalized/);
    await chmod(join(inputs, "stacks.json"), 0o600);
    await writeFile(
      join(inputs, "stacks.json"),
      (await readFile(join(inputs, "stacks.json"), "utf8")) + "\n",
    );
    await expect(call("next")).rejects.toThrow();
  });
}

async function sampledCopies(
  root: string,
  bindings: readonly {
    version: string;
    frameIndices?: readonly number[];
    sourceBound?: boolean;
  }[],
  sinkFrames: readonly number[],
) {
  const files = await sample(root, true);
  const capture = JSON.parse(await readFile(files.stacksPath, "utf8"));
  const observation = capture.queries[0].groups[0].observations[0];
  observation.frames[0].location = "primary/decode.js";
  observation.frames.splice(1, 0, {
    name: "decode",
    type: "javascript",
    location: "secondary/decode.js",
  });
  observation.sourceIndex = 2;
  observation.sinkIndex = 1;
  observation.sinkIds = [];
  observation.sinkMatches = sinkFrames.map((rawIndex) => ({
    sinkId: "decode",
    rawIndex,
  }));
  observation.bindings = bindings.map(({ sourceBound = true, ...binding }) => ({
    ...binding,
    package: "sample-codec",
    imageDigest: "sha256:" + "a".repeat(64),
    ...(sourceBound && { sourceSha: capture.target.sha }),
    provenance: "loaded modules",
  }));
  await writeFile(files.stacksPath, JSON.stringify(capture));
  return startProof(root, files);
}

const fixedSink = { version: "2.1.0", frameIndices: [0] };
const fixedWrapper = { ...fixedSink, frameIndices: [1] };
const affectedSink = { version: "1.5.0", frameIndices: [0] };
const affectedWrapper = { ...affectedSink, frameIndices: [1] };
for (const [label, bindings, sinkFrames, ruledOut] of [
  ["unattributed version", [{ version: "2.1.0" }], [0], false],
  ["empty frame list", [{ version: "2.1.0", frameIndices: [] }], [0], false],
  ["queried wrapper only", [fixedWrapper], [0], false],
  ["conflicting sink versions", [fixedSink, affectedSink], [0], false],
  ["fixed sink and affected wrapper", [fixedSink, affectedWrapper], [0], true],
  ["partially covered sinks", [fixedSink], [0, 1], false],
  ["both sink frames covered", [fixedSink, fixedWrapper], [0, 1], true],
] as const) {
  test("version exclusion with " + label, async () => {
    await using dir = await scopedTemporaryDirectory("stack-copies-");
    const { call, row } = await sampledCopies(dir.path, bindings, sinkFrames);
    const item = {
      workItemId: row.workItemId,
      verdict: "ruled_out",
      reason: "The sampled decoder is fixed.",
      supportingClaims: row.supportingClaims,
    };
    const result = call("record-assessments", { items: [item] });
    if (ruledOut) {
      await result;
      expect(await call("finalize")).toMatchObject({ verdict: "ruled_out" });
    } else {
      await expect(result).rejects.toThrow();
      const unknown = {
        ...item,
        verdict: "unknown",
        reason: "Missing copy identity.",
        remainingQuestions: ["Which copy supplied the sink?"],
      };
      await call("record-assessments", { items: [unknown] });
      expect(await call("finalize")).toMatchObject({ verdict: "unknown" });
    }
  });
}

for (const sourceBound of [true, false]) {
  const label = sourceBound
    ? "both copies linked to source"
    : "only the fixed copy linked to source";
  test("an affected sink beside a fixed sink with " + label, async () => {
    await using dir = await scopedTemporaryDirectory("stack-peer-");
    const { call, row } = await sampledCopies(
      dir.path,
      [{ ...affectedSink, sourceBound }, fixedWrapper],
      [0, 1],
    );
    row.use.version = affectedSink.version;
    const result = call("record-assessments", { items: [row] });
    if (sourceBound) {
      await result;
      expect(await call("finalize")).toMatchObject({ verdict: "exploitable" });
    } else {
      await expect(result).rejects.toThrow();
    }
  });
}

for (const version of ["1.5.0", "2.1.0"]) {
  test("potential verdict with only a build selecting " + version, async () => {
    await using dir = await scopedTemporaryDirectory("stack-configured-");
    const source = `import { decode } from "npm:sample-codec@${version}";\nexport function request(bytes) { return decode(bytes); }\n`;
    const files = await sample(dir.path, false, undefined, source);
    const catalog = JSON.parse(await readFile(files.sinksPath, "utf8"));
    const earlier = {
      ...catalog.sinks[0],
      id: "decode-earlier",
      affectedVersions: ["<1.1.0"],
    };
    catalog.sinks.unshift(earlier);
    await writeFile(files.sinksPath, JSON.stringify(catalog));
    const capture = JSON.parse(await readFile(files.stacksPath, "utf8"));
    const observation = capture.queries[0].groups[0].observations[0];
    observation.sinkIds.unshift(earlier.id);
    delete observation.bindings;
    await writeFile(files.stacksPath, JSON.stringify(capture));
    const { call, row } = await startProof(dir.path, files);
    const verdict = "potentially_exploitable";
    const use = {
      ...row.use,
      version,
      verdict,
      deployment: "configured",
      evidence: row.use.evidence.map((range) => ({
        ...range,
        supports: ["affected_copy", "affected_use"],
      })),
    };
    const item = {
      ...row,
      use,
      verdict,
      remainingQuestions: ["Which build ran?"],
    };
    const result = call("record-assessments", { items: [item] });
    if (version === "1.5.0") {
      await result;
      expect(await call("finalize")).toMatchObject({ verdict });
    } else {
      await expect(result).rejects.toThrow(/affected range/);
      expect(await call("summarize-coverage")).toMatchObject({ assessed: 0 });
    }
  });
}

test("the stack process gets a private Codex home and can write only its workspace", async () => {
  await using dir = await scopedTemporaryDirectory("stack-process-");
  const home = join(dir.path, "user");
  const work = join(dir.path, "work");
  const target = join(dir.path, "target");
  await Promise.all([home, work, target].map((path) => mkdir(path)));
  git(target, "init", "--quiet");
  await writeFile(
    join(home, "config.toml"),
    [
      'model_provider = "sample"',
      "[model_providers.sample]",
      'name = "Sample"',
      'base_url = "https://example.invalid"',
      'env_key = "SAMPLE_PROVIDER_TOKEN"',
      "[mcp_servers.ambient]",
      'command = "unused"',
    ].join("\n"),
  );
  const stdout = capture(),
    stderr = capture();
  const script = `
    const fs = require("node:fs"), path = require("node:path");
    const home = process.env.CODEX_HOME, cfg = path.join(home, "config.toml");
    const result = {
      home, inherited: fs.existsSync(cfg) && fs.readFileSync(cfg, "utf8").includes("mcp_servers.ambient"),
      policy: process.argv.find(a => a.startsWith("permissions.dependency_investigation=")),
    };
    console.log(JSON.stringify({type:"item.completed",item:{id:"r",type:"agent_message",text:JSON.stringify(result)}}));
    console.log(JSON.stringify({type:"turn.completed"}));
  `;
  const status = await runCodexSkillCommand(
    ["-e", script, "--"],
    {
      command: "exploitability check",
      auth: "auto",
      stackTarget: target,
      directory: work,
      stdout: stdout.stream,
      stderr: stderr.stream,
    },
    { command: process.execPath },
    {
      PATH: process.env["PATH"],
      CODEX_HOME: home,
      SAMPLE_PROVIDER_TOKEN: "test",
    },
  );
  expect(status, stderr.text()).toBe(0);
  const observed = JSON.parse(stdout.text());
  expect(observed.home).not.toBe(home);
  expect(observed.inherited).toBe(false);
  expect(parseToml(observed.policy)).toMatchObject({
    permissions: {
      dependency_investigation: {
        network: { enabled: false },
        filesystem: {
          ":root": "read",
          [work]: { ".": "write" },
          [home]: { ".": "deny" },
          [observed.home]: { ".": "deny" },
        },
      },
    },
  });
});

test("the gated check gives one investigator a usable child CLI and publishes its verified report", async () => {
  await using dir = await scopedTemporaryDirectory("stack-cli-");
  const files = await sample(dir.path, false);
  const gate = "CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY";
  let calls = 0;
  const d = dependencies({
    currentDirectory: files.repo,
    async onCodex(argv, out, _env, prompt) {
      calls++;
      expect(argv[0]).toBe("exec");
      expect(argv).toContain("--ignore-user-config");
      expect(argv).toContain("mcp_servers={}");
      expect(out?.investigationServers).toEqual({});
      expect(argv).toContain('model_provider="sample"');
      expect(argv.some((arg) => arg.includes(gate))).toBe(true);
      const { state, command } = JSON.parse(
        prompt!.split("\n").find((line) => line.startsWith('{"command":'))!,
      );
      expect(command.slice(-2)).toEqual(["exploitability", "run"]);
      async function child(verb: string, input?: unknown) {
        const io = createCliTest(main);
        const deps = dependencies({ currentDirectory: files.repo });
        deps.environment[gate] = "1";
        if (input !== undefined)
          deps.recordsInput = Readable.from([JSON.stringify(input)]);
        const code = await io.runCli(
          [
            "exploitability",
            "run",
            verb,
            "--state",
            state,
            ...(input !== undefined ? ["--json-stdin"] : []),
          ],
          deps,
        );
        expect(code, io.stderr.text()).toBe(0);
        return JSON.parse(io.stdout.text());
      }
      const { workItem } = await child("next");
      await child("record-assessments", {
        items: [
          {
            workItemId: workItem.id,
            verdict: "unknown",
            reason: "Source identity is missing.",
            remainingQuestions: ["Which source commit ran?"],
          },
        ],
      });
      await child("finalize");
      out!.stdout.write("Investigation complete.\n");
      return 0;
    },
  });
  const configHome = join(dir.path, "user-config");
  await mkdir(configHome);
  await writeFile(
    join(configHome, "config.toml"),
    'model_provider="sample"\n[model_providers.sample]\nname="Sample"\nbase_url="https://example.invalid"\nwire_api="responses"\n[mcp_servers.ambient]\ncommand="unused"\n',
  );
  d.environment["CODEX_HOME"] = configHome;
  d.environment[gate] = "1";
  const io = createCliTest(main);
  const code = await io.runCli(
    [
      "exploitability",
      "check",
      cve,
      "--sources",
      files.sourcesPath,
      "--sinks",
      files.sinksPath,
      "--stacks",
      files.stacksPath,
      "--json",
    ],
    d,
  );
  expect(code, io.stderr.text()).toBe(0);
  expect(calls).toBe(1);
  expect(JSON.parse(io.stdout.text())).toMatchObject({
    verdict: "unknown",
    coverage: { assessed: 1 },
  });
});

test("an explicitly dated observation outside the requested window stays an unresolved scope conflict", async () => {
  await using dir = await scopedTemporaryDirectory("stack-window-");
  const files = await sample(dir.path, true);
  const original = JSON.parse(await readFile(files.stacksPath, "utf8"));
  original.queries[0].groups[0].observations[0].observedAt =
    "2026-01-02T00:00:00.000001Z";
  await writeFile(files.stacksPath, JSON.stringify(original));
  const inputs = join(dir.path, "inputs"),
    state = join(dir.path, "run.sqlite");
  const packet = await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  const [work] = stackPacketWorkItems(packet);
  expect(work!.scopeConflicts.join(" ")).toContain("outside the query window");
  await executeStackRun("init", { state, repo: files.repo, inputs });
  await expect(
    executeStackRun("record-assessments", {
      state,
      input: {
        items: [
          {
            workItemId: work!.id,
            verdict: "exploitable",
            reason: "Observed caller.",
          },
        ],
      },
    }),
  ).rejects.toThrow(/Conflicting capture scope/);
  await executeStackRun("record-assessments", {
    state,
    input: {
      items: [
        {
          workItemId: work!.id,
          verdict: "unknown",
          reason: "Observation fell outside the requested time.",
          remainingQuestions: ["Did this caller run in the requested window?"],
        },
      ],
    },
  });
  expect(await executeStackRun("finalize", { state })).toMatchObject({
    verdict: "unknown",
    coverage: { scopeConflicts: [work!.id] },
  });
});

test("claim identity and finalized reports retain every own key in opaque JSON evidence", async () => {
  await using dir = await scopedTemporaryDirectory("stack-json-");
  const files = await sample(dir.path, true);
  const inputs = join(dir.path, "inputs"),
    state = join(dir.path, "attempt.sqlite");
  await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  await executeStackRun("init", { state, repo: files.repo, inputs });
  const command = (name: string, input?: unknown) =>
    executeStackRun(name, { state, input });
  const { workItem, receiptId } = (await command("next")) as {
    workItem: { id: string };
    receiptId: string;
  };
  const payload = JSON.parse('{"sample":{"__proto__":{"enabled":true}}}');
  const record = (value: unknown) =>
    command("record-claims", {
      claims: [
        {
          id: "input",
          scope: "sample",
          payload: value,
          receiptIds: [receiptId],
        },
      ],
    });
  const { claims } = (await record(payload)) as {
    claims: DependencyClaimReference[];
  };
  await expect(record({ sample: {} })).rejects.toThrow();
  await command("record-assessments", {
    items: [
      {
        workItemId: workItem.id,
        verdict: "unknown",
        reason: "Missing input provenance.",
        remainingQuestions: ["Who controls the input?"],
        supportingClaims: claims,
      },
    ],
  });
  const result = (await command("finalize")) as {
    claims: { payload: unknown }[];
  };
  expect(JSON.stringify(result.claims[0]!.payload)).toEqual(
    JSON.stringify(payload),
  );
});

test("packet preparation and reopen preserve opaque endpoint and query metadata", async () => {
  await using dir = await scopedTemporaryDirectory("stack-metadata-");
  const files = await sample(dir.path, true);
  const labels = JSON.parse(
    '{"__proto__":{"enabled":true},"options":[null,false,{"weight":2}]}',
  );
  for (const [kind, path] of [
    ["sources", files.sourcesPath],
    ["sinks", files.sinksPath],
  ] as const) {
    const doc = JSON.parse(await readFile(path, "utf8"));
    doc[kind][0] = { ...doc[kind][0], ...labels };
    await writeFile(path, JSON.stringify(doc));
  }
  const capture = JSON.parse(await readFile(files.stacksPath, "utf8"));
  capture.queries[0].selectors = {
    sources: [labels, "example input"],
    sinks: [{ match: labels }, 17],
  };
  await writeFile(files.stacksPath, JSON.stringify(capture));
  const inputs = join(dir.path, "packet"),
    state = join(dir.path, "run.sqlite");
  const packet = await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  const ready = await executeStackRun("init", {
    state,
    inputs,
    repo: files.repo,
  });
  expect(ready).toMatchObject({ inputDigest: packet.manifest.inputDigest });
  expect(await readFile(join(inputs, "stacks.json"))).toEqual(
    await readFile(files.stacksPath),
  );
  const next = (await executeStackRun("next", { state })) as {
    workItem: { selectors: unknown };
    sources: unknown[];
    sinks: unknown[];
  };
  expect(JSON.stringify(next.workItem.selectors)).toBe(
    JSON.stringify(capture.queries[0].selectors),
  );
  const source = JSON.parse(await readFile(files.sourcesPath, "utf8")),
    sink = JSON.parse(await readFile(files.sinksPath, "utf8"));
  expect(JSON.stringify(next.sources)).toBe(JSON.stringify(source.sources));
  expect(JSON.stringify(next.sinks)).toBe(JSON.stringify(sink.sinks));
});
