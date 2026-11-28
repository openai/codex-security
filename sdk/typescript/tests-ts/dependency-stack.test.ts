import { expect, spyOn, test } from "bun:test";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { parse as parseToml } from "smol-toml";
import { DependencyAttemptStore } from "../src/dependency-attempt-store.js";
import {
  analyzeStackAdvisory,
  lookupDependencyAdvisory,
} from "../src/dependency-advisory.js";
import { sqliteDatabaseOpener } from "../src/runtime.js";
import {
  prepareStackPacket,
  readStackPacket,
  stackPacketWorkItems,
} from "../src/dependency-stack-packet.js";
import type { StackInvestigationReport } from "../src/dependency-stack-assessment.js";
import {
  dependencyClaimHash,
  type DependencyClaimReference,
} from "../src/dependency-stack-claims.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "../src/dependency-stack-run.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { requestMetadata } from "./support/request-metadata.js";
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

type Sample = Awaited<ReturnType<typeof sample>>;

function packetOptions(files: Sample, inputsDir: string) {
  return {
    cve,
    ...files,
    repository: files.repo,
    inputsDir,
    toolRevision: "test",
  };
}

async function startPacket(root: string, files: Sample) {
  const inputs = join(root, "packet");
  const state = join(root, "attempt.sqlite");
  const packet = await prepareStackPacket(packetOptions(files, inputs));
  const ready = await executeStackRun("init", {
    state,
    repo: files.repo,
    inputs,
  });
  const call = (command: string, input?: unknown) =>
    executeStackRun(command, { state, input });
  return { inputs, state, packet, ready, call };
}

async function startProof(root: string, files: Sample, legacyCapture = false) {
  const { inputs, state, call } = await startPacket(root, files);
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

test("trigger analysis checks quotations and addresses each supplied sink", async () => {
  const quote = "The decoder must accept a caller-supplied length.";
  const { advisories } = await lookupDependencyAdvisory(
    cve,
    undefined,
    async () => Response.json({ id: cve, details: quote }),
  );
  const sink = {
    function: "decode",
    package: "codec",
    versionScheme: "semver",
    affectedVersions: ["<2"],
    preconditions: [],
  };
  const input = {
    cve,
    advisoryDetails: advisories,
    sinks: [
      { ...sink, id: "decode" },
      { ...sink, id: "another" },
    ],
  };
  const condition = {
    label: "Caller controls length.",
    advisoryId: cve,
    quote,
  };
  const first = { sinkId: "decode", conditions: [condition] };
  const second = { sinkId: "another", conditions: [] };
  const analyze = (output: unknown) =>
    analyzeStackAdvisory(input, async () => JSON.stringify(output));
  expect(await analyze([first, second])).toEqual([first, second]);
  await expect(analyze([first])).rejects.toThrow(/Missing trigger analysis/);
  await expect(analyze([first, first])).rejects.toThrow(/repeated sink/);
  for (const changed of [
    { quote: "Only under an invented configuration." },
    { advisoryId: "other" },
  ]) {
    await expect(
      analyze([
        { ...first, conditions: [{ ...condition, ...changed }] },
        second,
      ]),
    ).rejects.toThrow(/exact quote/);
  }
});

test("a positive path must prove the supplied and derived conditions in the frozen worklist", async () => {
  await using dir = await scopedTemporaryDirectory("stack-criteria-");
  const files = await sample(dir.path, true);
  const quote = "The decoder must receive unvalidated bytes.";
  const { advisories: advisoryDetails } = await lookupDependencyAdvisory(
    cve,
    undefined,
    async () => Response.json({ id: cve, details: quote }),
  );
  const triggerAnalysis = [
    {
      sinkId: "decode",
      conditions: [{ label: quote, quote, advisoryId: cve }],
    },
  ];
  const catalog = JSON.parse(await readFile(files.sinksPath, "utf8"));
  await writeFile(
    files.sinksPath,
    JSON.stringify({ ...catalog, advisoryDetails, triggerAnalysis }),
  );
  const { call, row, state } = await startProof(dir.path, files);
  expect(await call("next")).toMatchObject({
    advisoryDetails,
    triggerAnalysis,
    openQuestions: [condition, quote],
    sinks: [{ id: "decode", preconditions: [condition, quote] }],
  });
  const original = row.use.proof.conditions[0]!;
  const derived = {
    ...original,
    label: quote,
    explanation: "The caller invokes decode without validation.",
  };
  for (const proof of [original, derived]) {
    row.use.proof.conditions = [proof];
    await expect(call("record-assessments", { items: [row] })).rejects.toThrow(
      /Each advisory precondition/,
    );
  }
  row.use.proof.conditions = [original, derived];
  await call("record-assessments", { items: [row] });
  const report = await call("finalize");
  expect(report).toMatchObject({
    advisoryDetails,
    triggerAnalysis,
    verdict: "exploitable",
  });
  expect(report).toEqual(await readFinalStackReport(state));
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
      receiptId: expect.stringMatching(/^capture-/),
      rootFirstRawIndices: [1, 0],
      observation: {
        frames: [
          { name: "decode", offset: "9007199254740993" },
          { name: "request" },
        ],
      },
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
      review: null,
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
  [
    "affected prerelease",
    [{ ...affectedSink, version: "1.5.0-beta.1" }],
    [0],
    false,
  ],
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
        questionChecks: [
          {
            question: "Which copy supplied the sink?",
            checked: "Compared the captured versions and their frame indices.",
            missingEvidence:
              "Unambiguous fixed-version attribution to every sink frame.",
            claims: row.supportingClaims,
          },
        ],
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

for (const [version, affected] of [
  ["1.5.0", true],
  ["1.5.0-beta.1", true],
  ["2.1.0", false],
] as const) {
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
    if (affected) {
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

test("the gated check preserves configured caller scope through review and two corrections of the challenged path", () =>
  reviewedStackCheck(
    "correct",
    'Assess the "import" worker.\nTreat uploaded records as caller-controlled.',
  ));

test("a combined check replays the frozen stack evidence alongside the repository report", () =>
  reviewedStackCheck("combined", "Assess only the decoder service."));

test("a third independent rejection exhausts the one-shot budget without publishing a report", () =>
  reviewedStackCheck("exhausted"));

test("a review that repeats one decision and omits another cannot publish a report", () =>
  reviewedStackCheck("duplicate"));

async function reviewedStackCheck(
  mode: "correct" | "combined" | "duplicate" | "exhausted",
  callerScope?: string,
) {
  await using dir = await scopedTemporaryDirectory("stack-cli-");
  const files = await sample(dir.path, false);
  const stacks = JSON.parse(await readFile(files.stacksPath, "utf8"));
  const { observations } = stacks.queries[0].groups[0];
  observations.push({ ...observations[0], id: "other", stackHash: "other" });
  await writeFile(files.stacksPath, JSON.stringify(stacks));
  const trigger =
    "The declared length must exceed the number of bytes supplied.";
  using lookup = spyOn(globalThis, "fetch").mockResolvedValue(
    Response.json({ id: cve, details: trigger }),
  );
  const triggerAnalysis = [
    {
      sinkId: "decode",
      conditions: [{ label: trigger, advisoryId: cve, quote: trigger }],
    },
  ];
  const combined = mode === "combined";
  const inputs = join(dir.path, "packet");
  const saved = combined
    ? await prepareStackPacket(
        { ...packetOptions(files, inputs), callerScope },
        {
          lookupCve: (id, signal) =>
            lookupDependencyAdvisory(id, signal, async () =>
              Response.json({ id, details: trigger }),
            ),
          analyze: async () => triggerAnalysis,
        },
      )
    : undefined;
  const gate = "CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY";
  const requests = [
    "Inspect the captured frames to see if the argument values are recorded.",
    "Check for a length guard before the call to decode.",
    "Trace the request constructor for upstream validation.",
  ];
  const checks = [
    "Read app.js. The argument is passed directly to decode.",
    "Checked source and captured frames: the caller passes the bytes but the capture records no argument values.",
    "Rechecked the caller: no length guard restricts the bytes, and the frames lack the actual values.",
  ];
  const missingEvidence = "The request payload for this captured call.";
  const destination = join(dir.path, "report.json");
  let calls = 0;
  const drafts: StackInvestigationReport[] = [];
  let originalState: string | undefined;
  const d = dependencies({
    currentDirectory: files.repo,
    async onCodex(argv, out, _env, prompt) {
      if (combined && !out?.stackTarget) {
        const payload = JSON.parse(
          (prompt ?? out?.appServer?.prompt)!.split("\n\n").at(-1)!,
        );
        out!.stdout.write(
          JSON.stringify(
            payload.claims
              ? {
                  decisions: payload.claims.map(
                    ({ id, revision, hash }: DependencyClaimReference) => ({
                      id,
                      revision,
                      hash,
                      approved: true,
                      evidenceKeys: [],
                      reason: "Checked coverage.",
                    }),
                  ),
                }
              : {
                  uses: [],
                  limitations: ["No matching dependency in this checkout."],
                },
          ),
        );
        return 0;
      }
      calls++;
      expect(argv[0]).toBe("exec");
      expect(requestMetadata(argv)).toMatchObject({
        codex_security_surface: "cli",
        codex_security_command: "exploitability check",
      });
      expect(argv).toContain("--ignore-user-config");
      expect(argv).toContain("mcp_servers={}");
      expect(out?.investigationServers).toEqual({});
      expect(argv).toContain('model_provider="sample"');
      expect(argv.some((arg) => arg.includes(gate))).toBe(true);
      if (!combined && calls === 1) {
        expect(prompt).toContain(trigger);
        expect(out?.readOnly).toBe(true);
        out!.stdout.write(JSON.stringify(triggerAnalysis));
        return 0;
      }
      if (out?.readOnly) {
        expect(argv).toContain('model_reasoning_effort="low"');
        expect(out.stackTarget).toBe(files.repo);
        const review = JSON.parse(prompt!.split("\n").at(-1)!);
        expect(review.callerScope).toBe(callerScope);
        const { reportFile, repo, inputs } = review;
        expect(repo).toBe(files.repo);
        const draft: StackInvestigationReport = JSON.parse(
          await readFile(reportFile, "utf8"),
        );
        const manifest = JSON.parse(
          await readFile(join(inputs, "manifest.json"), "utf8"),
        );
        expect(draft.inputDigest).toBe(manifest.inputDigest);
        expect(draft.review).toBeNull();
        expect(draft.assessments).toHaveLength(2);
        const round = drafts.length;
        expect(draft.assessments[0]?.questionChecks?.[0]?.checked).toBe(
          checks[round]!,
        );
        expect(draft.assessments[0]?.supportingClaims).toHaveLength(round + 1);
        if (round) {
          expect(draft.assessments[1]).toEqual(drafts[0]!.assessments[1]);
          expect(draft.assessments[0]!.supportingClaims.slice(0, -1)).toEqual(
            drafts[round - 1]!.assessments[0]!.supportingClaims,
          );
        }
        const challenge = round < 2 || mode === "exhausted";
        const decisions = draft.assessments.map(({ workItemId }, index) => ({
          workItemId,
          reason: "Checked the source and captured evidence.",
          followUp: challenge && index === 0 ? requests[round] : null,
        }));
        if (mode === "duplicate") decisions[1] = decisions[0]!;
        drafts.push(draft);
        out.stdout.write(JSON.stringify({ decisions }));
        return 0;
      }
      const investigation = JSON.parse(
        prompt!.split("\n").find((line) => line.startsWith('{"command":'))!,
      );
      expect(investigation.callerScope).toBe(callerScope);
      const { state, command } = investigation;
      expect(command.slice(-2)).toEqual(["exploitability", "run"]);
      async function child(verb: string, input?: unknown, error?: RegExp) {
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
        if (error) {
          expect(code).not.toBe(0);
          expect(io.stderr.text()).toMatch(error);
          return;
        }
        expect(code, io.stderr.text()).toBe(0);
        return JSON.parse(io.stdout.text());
      }
      const previousDraft = drafts.at(-1);
      if (previousDraft) {
        expect(state).toBe(originalState);
        const rejected = previousDraft.assessments[0]!;
        const { followUps } = JSON.parse(prompt!.split("\n").at(-1)!);
        expect(followUps).toMatchObject([
          {
            workItemId: rejected.workItemId,
            followUp: requests[drafts.length - 1],
          },
        ]);
        expect((await child("summarize-coverage")).outstanding).toEqual([
          rejected.workItemId,
        ]);
      } else originalState = state;
      for (let i = 0; i < (previousDraft ? 1 : observations.length); i++) {
        const previous = previousDraft?.assessments[i];
        const { workItem, receiptId, openQuestions, advisoryDetails } =
          await child("next");
        if (previous) expect(workItem.id).toBe(previous.workItemId);
        expect(openQuestions).toContain(condition);
        expect(openQuestions).toContain(trigger);
        expect(advisoryDetails[0].body).toBe(trigger);
        const question = "Which bytes did the request supply?";
        const row = {
          workItemId: workItem.id,
          verdict: "unknown",
          reason: previous
            ? "Neither the source nor the captured frames reveal the request bytes."
            : "The caller forwards bytes whose runtime values are unknown.",
          remainingQuestions: [question],
        };
        if (!previous && i === 0) {
          await child(
            "record-assessments",
            { items: [row] },
            /attempted check for each deciding question/,
          );
          expect((await child("next")).workItem.id).toBe(workItem.id);
        }
        const claim =
          drafts.length === 2
            ? {
                id: "length-guard",
                payload: "The caller has no length guard before decode.",
                evidence: [callerEvidence],
              }
            : previous
              ? {
                  id: "captured-arguments",
                  payload:
                    "The captured frames list locations, not argument values.",
                  receiptIds: [receiptId],
                }
              : {
                  id: "caller-input-" + i,
                  payload:
                    "The caller forwards request bytes directly to decode.",
                  evidence: [callerEvidence],
                };
        const { claims } = await child("record-claims", {
          claims: [{ ...claim, scope: "sample caller" }],
        });
        const supportingClaims = [
          ...(previous?.supportingClaims ?? []),
          ...claims,
        ];
        const check = {
          question,
          checked: checks[drafts.length],
          missingEvidence,
          claims: supportingClaims,
        };
        if (!previous && i === 0) {
          await child(
            "record-assessments",
            { items: [{ ...row, questionChecks: [check] }] },
            /supporting claim with verified source or capture evidence/,
          );
        }
        await child("record-assessments", {
          // Reuse the ID across rounds: the first receipt must not shadow the correction.
          operationId: "assess-" + i,
          items: [{ ...row, supportingClaims, questionChecks: [check] }],
        });
      }
      expect((await child("next")).workItem).toBeNull();
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
  const configPath = join(dir.path, "project.json");
  const progress = join(dir.path, "progress.jsonl");
  const configure = (scope?: string) =>
    writeFile(
      configPath,
      JSON.stringify({
        exploitability: {
          analyzers: combined
            ? undefined
            : { stacks: { input: mode === "correct" ? "." : "./unused" } },
          ...(scope && { scope: { instructions: scope } }),
        },
      }),
    );
  if (!combined) await configure(callerScope);
  const check = ["exploitability", "check", cve];
  if (!combined) check.push("--config", configPath);
  if (mode !== "correct")
    check.push("--analyzer-input", combined ? "stacks=../packet" : "stacks=..");
  const io = createCliTest(main);
  const code = await io.runCli(
    [
      ...check,
      ...(combined ? ["--progress-events", progress] : []),
      "--report-file",
      destination,
      "--json",
    ],
    d,
  );
  // A combined check only looks up the repository advisory. Stack review reuses its snapshot.
  expect(lookup).toHaveBeenCalledTimes(1);
  if (mode !== "duplicate") {
    expect(drafts, io.stderr.text() + io.stdout.text()).toHaveLength(3);
    expect(calls).toBe(combined ? 6 : 7); // Three investigator/reviewer pairs, plus analysis for raw captures.
  }
  if (mode === "exhausted" || mode === "duplicate") {
    expect(code).not.toBe(0);
    if (mode === "exhausted") {
      expect(io.stderr.text()).toContain(drafts[2]!.assessments[0]!.workItemId);
      expect(io.stderr.text()).toContain(requests[2]!);
    } else
      expect(io.stderr.text()).toContain("decide each work item exactly once");
    await expect(readFile(destination)).rejects.toMatchObject({
      code: "ENOENT",
    });
    return;
  }
  expect(code, io.stderr.text()).toBe(0);
  const output = JSON.parse(io.stdout.text());
  expect(JSON.parse(await readFile(destination, "utf8"))).toEqual(output);
  const report = combined ? output.analyzers.stacks : output;
  if (saved) {
    expect(output.analyzers.repository).toMatchObject({ cve, uses: [] });
    expect(report.inputDigest).toBe(saved.manifest.inputDigest);
    const events = (await readFile(progress, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    for (const analyzer of ["repository", "stacks"]) {
      expect(events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ analyzer, type: "investigation" }),
          expect.objectContaining({
            analyzer,
            type: "stage",
            stage: "investigate",
          }),
        ]),
      );
    }
    async function expectRejected(message: RegExp) {
      const retry = createCliTest(main);
      expect(
        await retry.runCli([...check, "--config", configPath], d),
      ).not.toBe(0);
      expect(retry.stderr.text()).toMatch(message);
      expect(lookup).toHaveBeenCalledTimes(1);
    }
    await configure("A different scope.");
    await expectRejected(/scope conflicts/i);
    await configure();
    const manifest = join(inputs, "manifest.json");
    await chmod(manifest, 0o600);
    await writeFile(
      manifest,
      JSON.stringify({ ...saved.manifest, inputDigest: "f".repeat(64) }),
    );
    await expectRejected(/manifest/i);
  }
  const approvedDraft = drafts[2]!;
  expect({ ...report, review: null }).toEqual(approvedDraft);
  expect(report).toMatchObject({
    callerScope,
    verdict: "unknown",
    coverage: { assessed: 2 },
    review: {
      draftDigest: dependencyClaimHash(approvedDraft),
      decisions: approvedDraft.assessments.map(({ workItemId }) => ({
        workItemId,
        followUp: null,
      })),
    },
    triggerAnalysis,
    advisoryDetails: [{ id: cve, body: trigger }],
  });
  for (const [index, assessment] of report.assessments.entries()) {
    expect(assessment.questionChecks).toEqual([
      {
        question: assessment.remainingQuestions[0],
        checked: index === 0 ? checks[2] : checks[0],
        missingEvidence,
        claims: assessment.supportingClaims,
      },
    ]);
  }
}

test("offline finalize renders the saved assessment and protects existing output", async () => {
  await using dir = await scopedTemporaryDirectory("stack-render-");
  const files = await sample(dir.path, false);
  const { state, call, row, claims } = await startProof(dir.path, files);
  const question = "Which source commit ran?";
  await call("record-assessments", {
    items: [
      {
        workItemId: row.workItemId,
        verdict: "unknown",
        reason: "Source identity is missing.",
        remainingQuestions: [question],
        supportingClaims: claims,
        questionChecks: [
          {
            question,
            checked: "Read the captured package binding and the pinned caller.",
            missingEvidence:
              "The source revision used to build the captured image.",
            claims,
          },
        ],
      },
    ],
  });
  await call("finalize");
  const readDeps = dependencies({ currentDirectory: files.repo });
  readDeps.environment["CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY"] = "1";
  const args = ["exploitability", "run", "finalize", "--state", state];
  const markdown = createCliTest(main);
  expect(await markdown.runCli([...args, "--format", "md"], readDeps)).toBe(0);
  expect(markdown.stdout.text()).toContain(cve);
  expect(markdown.stdout.text()).toContain("Source identity is missing.");
  expect(markdown.stdout.text()).not.toContain("[object Object]");
  const saved = createCliTest(main);
  const htmlPath = join(dir.path, "saved.html");
  expect(
    await saved.runCli(
      [...args, "--format=html", "--report-file", htmlPath],
      readDeps,
    ),
  ).toBe(0);
  expect(saved.stdout.text().trimEnd()).toEndWith(htmlPath);
  expect(saved.stdout.text()).not.toContain("<!doctype html>");
  expect(saved.stdout.text()).toContain("Next: Which source commit ran?");
  const html = await readFile(htmlPath, "utf8");
  expect(html).toStartWith("<!doctype html>");
  expect(html).toContain("Source identity is missing.");
  const duplicate = createCliTest(main);
  expect(
    await duplicate.runCli(
      [...args, "--format", "html", "--report-file", htmlPath],
      readDeps,
    ),
  ).not.toBe(0);
  expect(duplicate.stdout.text()).toBe("");
  expect(await readFile(htmlPath, "utf8")).toBe(html);
});

test("offline finalize rejects a stored unknown without question checks", async () => {
  await using dir = await scopedTemporaryDirectory("stack-finalize-question-");
  const files = await sample(dir.path, true);
  const { state, row, call } = await startProof(dir.path, files);
  const unknown = {
    workItemId: row.workItemId,
    verdict: "unknown",
    reason: "Missing input provenance.",
    remainingQuestions: ["Who supplies these bytes?"],
    supportingClaims: row.supportingClaims,
  };
  const error = /attempted check for each deciding question/;
  await expect(
    call("record-assessments", { items: [unknown] }),
  ).rejects.toThrow(error);
  // Finalization must verify even an assessment written outside the CLI.
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    store.set("stack-assessment", row.workItemId, unknown);
    await expect(call("finalize")).rejects.toThrow(error);
    expect(store.get("report", "final")).toBeUndefined();
  } finally {
    store.close();
  }
});

test("an explicitly dated observation outside the requested window stays an unresolved scope conflict", async () => {
  await using dir = await scopedTemporaryDirectory("stack-window-");
  const files = await sample(dir.path, true);
  const original = JSON.parse(await readFile(files.stacksPath, "utf8"));
  original.queries[0].groups[0].observations[0].observedAt =
    "2026-01-02T00:00:00.000001Z";
  await writeFile(files.stacksPath, JSON.stringify(original));
  const { packet, call } = await startPacket(dir.path, files);
  const [work] = stackPacketWorkItems(packet);
  expect(work!.scopeConflicts.join(" ")).toContain("outside the query window");
  await expect(
    call("record-assessments", {
      items: [
        {
          workItemId: work!.id,
          verdict: "exploitable",
          reason: "Observed caller.",
        },
      ],
    }),
  ).rejects.toThrow(/Conflicting capture scope/);
  await call("record-assessments", {
    items: [
      {
        workItemId: work!.id,
        verdict: "unknown",
        reason: "Observation fell outside the requested time.",
        remainingQuestions: ["Did this caller run in the requested window?"],
      },
    ],
  });
  expect(await call("finalize")).toMatchObject({
    verdict: "unknown",
    coverage: { scopeConflicts: [work!.id] },
  });
});

test("an indexed miss stays unknown and other capture groups can be assessed", async () => {
  await using dir = await scopedTemporaryDirectory("stack-indexed-miss-");
  const files = await sample(dir.path, true);
  const stacks = JSON.parse(await readFile(files.stacksPath, "utf8"));
  const [observed] = stacks.queries[0].groups;
  const indexedMiss = {
    id: "empty-index",
    status: "no_indexed_match",
    truncated: false,
    observations: [],
  };
  stacks.queries[0].groups = [indexedMiss, observed];
  await writeFile(files.stacksPath, JSON.stringify(stacks));

  const { packet, state, call } = await startPacket(dir.path, files);
  const [miss, captured] = stackPacketWorkItems(packet);
  expect(miss).toMatchObject({ status: "no_indexed_match", observation: null });
  expect(await call("next")).toMatchObject({
    workItem: { id: miss!.id, status: "no_indexed_match" },
  });

  await expect(
    call("record-assessments", {
      items: [
        {
          workItemId: miss!.id,
          verdict: "ruled_out",
          reason: "The index returned no stacks.",
        },
      ],
    }),
  ).rejects.toThrow(/requires a scoped unknown assessment/);

  await call("record-assessments", {
    items: [
      {
        workItemId: miss!.id,
        verdict: "unknown",
        reason: "The index returned no stacks for this scope.",
        remainingQuestions: ["Do profiles cover the requested window?"],
      },
    ],
  });
  const next = (await call("next")) as {
    receiptId: string;
    workItem: { id: string; status: string };
  };
  expect(next).toMatchObject({
    workItem: { id: captured!.id, status: "observed" },
  });
  const { claims } = (await call("record-claims", {
    claims: [
      {
        id: "captured-frame",
        scope: "sample caller",
        payload: "The sampled frames show a call to the decoder.",
        receiptIds: [next.receiptId],
      },
    ],
  })) as { claims: DependencyClaimReference[] };
  const question = "Was the decoder input caller-controlled?";
  await call("record-assessments", {
    items: [
      {
        workItemId: captured!.id,
        verdict: "unknown",
        reason: "The captured call has an unverified prerequisite.",
        supportingClaims: claims,
        remainingQuestions: [question],
        questionChecks: [
          {
            question,
            checked: "Read the supplied stack frames.",
            missingEvidence: "The sampled decoder argument and its origin.",
            claims,
          },
        ],
      },
    ],
  });
  const report = await call("finalize");
  expect(report).toMatchObject({
    verdict: "unknown",
    assessments: [
      { status: "no_coverage", verdict: "unknown", observation: null },
      { status: "observed", observation: { id: "call" } },
    ],
    coverage: {
      assessed: 2,
      observed: 1,
      noMatch: [],
      noCoverage: [miss!.id],
    },
  });
  expect(report).toEqual(await readFinalStackReport(state));
});

test("claim identity and finalized reports retain every own key in opaque JSON evidence", async () => {
  await using dir = await scopedTemporaryDirectory("stack-json-");
  const files = await sample(dir.path, true);
  const { call: command } = await startPacket(dir.path, files);
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
        questionChecks: [
          {
            question: "Who controls the input?",
            checked:
              "The captured stack identifies the caller but not its trust boundary.",
            missingEvidence: "The origin of the request bytes.",
            claims,
          },
        ],
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

test("a caller scope is frozen separately from imported endpoint metadata", async () => {
  await using dir = await scopedTemporaryDirectory("stack-caller-scope-");
  const files = await sample(dir.path, true);
  const catalog = JSON.parse(await readFile(files.sinksPath, "utf8"));
  catalog.sinks[0].callerScope = "An endpoint annotation.";
  await writeFile(files.sinksPath, JSON.stringify(catalog));
  const original = join(dir.path, "original");
  const options = {
    ...packetOptions(files, original),
    runId: "run",
    attemptId: "attempt",
  };
  const { manifest } = await prepareStackPacket(options);
  expect(manifest).not.toHaveProperty("callerScope");

  const callerScope = "Assess ordinary accounts.\nInclude delegated jobs.";
  const inputs = join(dir.path, "scoped");
  const scoped = await prepareStackPacket({
    ...options,
    inputsDir: inputs,
    callerScope,
  });
  expect(scoped.manifest.inputDigest).not.toBe(manifest.inputDigest);
  expect(scoped.manifest.files).toEqual(manifest.files);
  const state = join(dir.path, "run.sqlite");
  await executeStackRun("init", { inputs, repo: files.repo, state });
  expect(await executeStackRun("next", { state })).toMatchObject({
    callerScope,
    sinks: [{ callerScope: catalog.sinks[0].callerScope }],
  });
  await expect(
    executeStackRun("init", { inputs: original, repo: files.repo, state }),
  ).rejects.toThrow(/different investigation attempt/);
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
  const { inputs, packet, ready, call } = await startPacket(dir.path, files);
  expect(ready).toMatchObject({ inputDigest: packet.manifest.inputDigest });
  expect(await readFile(join(inputs, "stacks.json"))).toEqual(
    await readFile(files.stacksPath),
  );
  const next = (await call("next")) as {
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

test("a check freezes advisory evidence without rewriting the catalog and can replay it offline", async () => {
  await using dir = await scopedTemporaryDirectory("stack-advisory-");
  const files = await sample(dir.path, true);
  const original = await readFile(files.sinksPath, "utf8");
  const catalog = JSON.parse(original);
  const options = packetOptions(files, join(dir.path, "first"));
  const quote = "An invalid length must reach the decoder.";
  const id = "SAMPLE-1";
  const triggerAnalysis = [
    {
      sinkId: "decode",
      conditions: [{ label: quote, advisoryId: id, quote }],
    },
  ];
  let lookups = 0,
    analyses = 0;
  const host = {
    async lookupCve(subject: string, signal?: AbortSignal) {
      lookups++;
      expect(subject).toBe(cve);
      return lookupDependencyAdvisory(subject, signal, async (url) =>
        url.endsWith(cve)
          ? Response.json({
              id: cve,
              aliases: [id],
              affected: [{ versions: ["1.0.0"] }],
            })
          : Response.json({ id, aliases: [cve], details: quote }),
      );
    },
    async analyze() {
      analyses++;
      return triggerAnalysis;
    },
  };
  const { manifest } = await prepareStackPacket(options, host);
  expect(manifest.advisory).toEqual(catalog.advisory);
  expect(await readFile(join(options.inputsDir, "sinks.json"), "utf8")).toBe(
    original,
  );
  const { advisoryDetails } = manifest;
  expect(advisoryDetails?.[1]).toMatchObject({ id, body: quote });
  expect(
    (await readStackPacket(options.inputsDir, files.repo)).manifest,
  ).toEqual(manifest);
  // Changing even a well-quoted condition invalidates the frozen input identity.
  const manifestPath = join(options.inputsDir, "manifest.json");
  const edited = JSON.parse(await readFile(manifestPath, "utf8"));
  edited.triggerAnalysis[0].conditions[0].label = "A different condition.";
  await chmod(manifestPath, 0o600);
  await writeFile(manifestPath, JSON.stringify(edited));
  await expect(readStackPacket(options.inputsDir, files.repo)).rejects.toThrow(
    /Manifest does not match/,
  );
  const replay = { ...catalog, advisoryDetails, triggerAnalysis };
  await writeFile(files.sinksPath, JSON.stringify(replay));
  const second = await prepareStackPacket(
    { ...options, inputsDir: join(dir.path, "second") },
    host,
  );
  expect(second.manifest).toMatchObject({ advisoryDetails, triggerAnalysis });
  const invalid = { ...options, inputsDir: join(dir.path, "invalid") };
  await writeFile(
    files.sinksPath,
    JSON.stringify({ ...replay, cve: "CVE-2099-0002" }),
  );
  await expect(
    prepareStackPacket({ ...invalid, cve: "CVE-2099-0002" }, host),
  ).rejects.toThrow(/does not identify/);
  const modified = structuredClone(advisoryDetails!);
  Object.assign(modified[0]!.affected[0]!, { extra: true });
  await writeFile(
    files.sinksPath,
    JSON.stringify({ ...catalog, advisoryDetails: modified }),
  );
  await expect(prepareStackPacket(invalid, host)).rejects.toThrow(
    /Frozen advisoryDetails does not match/,
  );
  advisoryDetails![1]!.body = "Changed since lookup.";
  await writeFile(files.sinksPath, JSON.stringify(replay));
  await expect(prepareStackPacket(invalid, host)).rejects.toThrow(
    /Frozen advisory SHA-256 mismatch/,
  );
  expect({ lookups, analyses }).toEqual({ lookups: 1, analyses: 1 });
});

test("unavailable public advisories retain a visible catalog fallback, but cancellation is not a fallback", async () => {
  await using dir = await scopedTemporaryDirectory("stack-advisory-offline-");
  const files = await sample(dir.path, true);
  const options = packetOptions(files, join(dir.path, "inputs"));
  const events: string[] = [];
  const host = {
    async lookupCve(): Promise<never> {
      throw new Error("registry unavailable");
    },
    async analyze(): Promise<never> {
      throw new Error("unexpected model call");
    },
    emit: (type: string) => {
      events.push(type);
    },
  };
  const { manifest } = await prepareStackPacket(options, host);
  expect(manifest.advisoryLookupError).toBe("registry unavailable");
  expect(manifest.triggerAnalysis).toBeUndefined();
  expect(events).toContain("advisory_lookup_failed");
  const controller = new AbortController();
  await expect(
    prepareStackPacket(
      {
        ...options,
        inputsDir: join(dir.path, "abort"),
        signal: controller.signal,
      },
      {
        ...host,
        async lookupCve(): Promise<never> {
          controller.abort(new Error("cancelled"));
          throw new Error("registry unavailable");
        },
      },
    ),
  ).rejects.toThrow("cancelled");
});
