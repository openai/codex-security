import { expect, spyOn, test } from "bun:test";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { Readable } from "node:stream";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { parse as parseToml } from "smol-toml";
import { DependencyAttemptStore } from "../src/exploitability/attempt-store.js";
import {
  analyzeAdvisoryTriggers,
  lookupDependencyAdvisory,
} from "../src/exploitability/advisory.js";
import {
  prepareStackInput,
  prepareStackPacket,
  readStackPacket,
  stackPacketWorkItems,
} from "../src/exploitability/analyzers/stacks/packet.js";
import type { StackInvestigationReport } from "../src/exploitability/analyzers/stacks/assessment.js";
import {
  dependencyClaimHash,
  type DependencyClaimReference,
} from "../src/exploitability/analyzers/stacks/claims.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "../src/exploitability/analyzers/stacks/run.js";
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
  const stack = {
    labels: { service: "decoder" },
    frames: [
      {
        name: "decode",
        offset: "9007199254740993",
        package: {
          name: sink.package,
          version: "1.0.0",
          provenance: "sample process",
        },
        ...(bindSource && { sourceRevision: sha }),
      },
      { name: "request", location: "app.js", line: 2 },
    ],
  };
  const documents = {
    sources: { format: "codex-security.sources/v2", sources: [source] },
    sinks: {
      format: "codex-security.sinks/v2",
      cve,
      advisory: {
        url: "https://example.invalid/advisories/decoder",
        summary: "Sample decoder accepts an invalid length.",
      },
      sinks: [sink],
    },
    stacks: {
      format: "codex-security.stacks/v2",
      captures: [
        {
          origin: "debugger backtrace",
          query: {
            selectors: { function: sink.function },
            coverage: "complete",
            window: {
              start: "2026-01-01T00:00:00Z",
              end: "2026-01-02T00:00:00Z",
            },
          },
          stacks: [stack],
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

async function startProof(root: string, files: Sample) {
  const { inputs, state, call } = await startPacket(root, files);
  const { workItem, receiptId, rootFirstRawIndices } = (await call("next")) as {
    workItem: { id: string; stack: { frames: { package?: unknown }[] } };
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
        receiptSelections: capture.stack.frames.flatMap((frame, index) =>
          frame.package
            ? [
                {
                  receiptId,
                  textBlock: null,
                  record: ["stack", "frames", index],
                },
              ]
            : [],
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
    analyzeAdvisoryTriggers(input, async () => JSON.stringify(output));
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

for (const bindSource of [true, false]) {
  test(
    bindSource
      ? "a captured frame tied to this checkout can support a positive verdict"
      : "an installed package alone cannot prove which revision ran",
    async () => {
      await using dir = await scopedTemporaryDirectory("stack-proof-");
      const files = await sample(dir.path, bindSource);
      const { inputs, state, call, capture, claims, write, row } =
        await startProof(dir.path, files);
      expect(capture).toMatchObject({
        receiptId: expect.stringMatching(/^capture-/),
        rootFirstRawIndices: [1, 0],
        stack: {
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
      if (!bindSource) {
        await expect(
          call("record-assessments", { items: [row] }),
        ).rejects.toThrow(/frame source revision matching the checkout/);
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
    },
  );
}

for (const [secondVersion, expected] of [
  ["2.1.0", true],
  ["1.5.0", false],
  [undefined, false],
] as const) {
  test(
    "version exclusion checks each matching frame, second copy " +
      (secondVersion ?? "unattributed"),
    async () => {
      await using dir = await scopedTemporaryDirectory("stack-copies-");
      const files = await sample(dir.path, true);
      const raw = JSON.parse(await readFile(files.stacksPath, "utf8"));
      const frames = raw.captures[0].stacks[0].frames;
      frames[0].package.version = "2.1.0";
      const sibling = structuredClone(frames[0]);
      if (secondVersion) sibling.package.version = secondVersion;
      else delete sibling.package;
      frames.splice(1, 0, sibling);
      await writeFile(files.stacksPath, JSON.stringify(raw));
      const { call, row } = await startProof(dir.path, files);
      const decision = call("record-assessments", {
        items: [
          {
            workItemId: row.workItemId,
            verdict: "ruled_out",
            reason: "All decoder copies were fixed.",
            supportingClaims: row.supportingClaims,
          },
        ],
      });
      if (expected) {
        await decision;
        expect(await call("finalize")).toMatchObject({ verdict: "ruled_out" });
      } else await expect(decision).rejects.toThrow();
    },
  );
}

for (const [version, affected] of [
  ["1.5.0", true],
  ["2.1.0", false],
] as const) {
  test(
    "potential verdict requires an affected frame version " + version,
    async () => {
      await using dir = await scopedTemporaryDirectory("stack-configured-");
      const source = `import { decode } from "npm:sample-codec@${version}";\nexport function request(bytes) { return decode(bytes); }\n`;
      const files = await sample(dir.path, false, source);
      const catalog = JSON.parse(await readFile(files.sinksPath, "utf8"));
      const earlier = {
        ...catalog.sinks[0],
        id: "decode-earlier",
        affectedVersions: ["<1.1.0"],
      };
      catalog.sinks.unshift(earlier);
      await writeFile(files.sinksPath, JSON.stringify(catalog));
      const capture = JSON.parse(await readFile(files.stacksPath, "utf8"));
      capture.captures[0].stacks[0].frames[0].package.version = version;
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
    },
  );
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

test("a glob freezes identical files independently in lexical order and retains their source", () =>
  reviewedStackCheck("glob", "Assess the desktop viewer."));

test("a combined check replays the frozen stack evidence alongside the repository report", () =>
  reviewedStackCheck("combined", "Assess only the decoder service."));

test("a third independent rejection exhausts the one-shot budget without publishing a report", () =>
  reviewedStackCheck("exhausted"));

test("a review that repeats one decision and omits another cannot publish a report", () =>
  reviewedStackCheck("duplicate"));

async function reviewedStackCheck(
  mode: "correct" | "glob" | "combined" | "duplicate" | "exhausted",
  callerScope?: string,
) {
  await using dir = await scopedTemporaryDirectory("stack-cli-");
  const files = await sample(dir.path, false);
  const stacks = JSON.parse(await readFile(files.stacksPath, "utf8"));
  const glob = mode === "glob";
  const raw = mode === "correct" || glob;
  const combined = mode === "combined";
  const observations = stacks.captures[0].stacks;
  const rawDir = join(dir.path, "raw");
  const captured = join(dir.path, "captured");
  const replay = join(dir.path, "replay");
  if (raw) {
    // A debugger snapshot supplies its own frames and nothing else.
    delete stacks.captures[0].query;
    delete observations[0].frames[0].package;
    await mkdir(rawDir);
  }
  if (!glob) observations.push(structuredClone(observations[0]));
  const bytes = JSON.stringify(stacks) + "\n";
  if (glob) {
    for (const name of ["snap-z.json", "snap-a.json"])
      await writeFile(join(rawDir, name), bytes);
    await writeFile(join(rawDir, "unrelated.json"), "not a capture");
  } else if (raw) await writeFile(join(rawDir, "stacks.json"), bytes);
  else {
    await writeFile(files.stacksPath, bytes);
    if (!combined) {
      await mkdir(captured);
      for (const name of ["stacks.json", "sources.json", "sinks.json"])
        await rename(join(dir.path, name), join(captured, name));
    }
  }
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
      if (!raw && !combined && calls === 1) {
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
        if (glob && round === 0) await cp(inputs, replay, { recursive: true });
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
      for (let i = 0; i < (previousDraft ? 1 : 2); i++) {
        const previous = previousDraft?.assessments[i];
        const { workItem, receiptId, openQuestions, advisoryDetails } =
          await child("next");
        if (previous) expect(workItem.id).toBe(previous.workItemId);
        if (!raw) {
          expect(openQuestions).toContain(condition);
          expect(openQuestions).toContain(trigger);
        }
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
        if (!raw && !previous && i === 0) {
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
        if (!raw && !previous && i === 0) {
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
            : { stacks: { input: raw ? "./raw/stacks.json" : "./unused" } },
          ...(scope && { scope: { instructions: scope } }),
        },
      }),
    );
  if (!combined) await configure(callerScope);
  const check = ["exploitability", "check", cve];
  if (!combined) check.push("--config", configPath);
  if (mode !== "correct")
    check.push(
      "--analyzer-input",
      combined
        ? "stacks=../packet"
        : glob
          ? "stacks=../raw/snap-*.json"
          : "stacks=../captured",
    );
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
    expect(calls).toBe(combined || raw ? 6 : 7);
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
  if (glob) {
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const names = ["snap-a.json", "snap-z.json"];
    const frozen = await readStackPacket(replay, files.repo);
    expect(frozen.manifest.files.stacks.parts).toEqual(
      names.map((name) => ({
        name,
        captureCount: 1,
        sha256,
        byteLength: Buffer.byteLength(bytes),
      })),
    );
    for (const [index, name] of names.entries()) {
      expect(report.assessments[index]).toMatchObject({
        workItemId: `captures/${index}/stacks/0`,
        sourceFile: { index, name, captureIndex: 0, sha256 },
      });
      expect(await readFile(join(replay, `stacks-${index}.json`), "utf8")).toBe(
        bytes,
      );
    }
    const changed = join(replay, "stacks-1.json");
    await chmod(changed, 0o600);
    await writeFile(changed, bytes + " ");
    await expect(readStackPacket(replay, files.repo)).rejects.toThrow();
  }
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
    // Selecting raw files must not bypass the stored manifest and frozen scope.
    check[check.length - 1] = "stacks=../packet/stacks.json";
    await expectRejected(/replay the manifest/i);
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
    ...(!raw && { triggerAnalysis }),
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

test("bad files, symlinks and an empty glob fail before either analyzer starts", async () => {
  await using dir = await scopedTemporaryDirectory("stack-glob-");
  const { repo, stacksPath } = await sample(dir.path, false);
  const folder = join(dir.path, "captures");
  await mkdir(folder);
  await writeFile(join(folder, "batch-a.json"), await readFile(stacksPath));
  await writeFile(join(folder, "batch-broken.json"), "{");
  await symlink(stacksPath, join(folder, "link.json"));
  using lookup = spyOn(globalThis, "fetch").mockRejectedValue(
    new Error("unexpected network access"),
  );
  let calls = 0;
  const d = dependencies({
    currentDirectory: repo,
    async onCodex() {
      calls++;
      return 1;
    },
  });
  d.environment["CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY"] = "1";
  for (const [pattern, message] of [
    ["no-such-*.json", /no stack capture files/i],
    ["batch-*.json", /batch-broken.json/],
    ["link.json", /symlink|symbolic link|regular file/i],
  ] as const) {
    const io = createCliTest(main);
    const code = await io.runCli(
      [
        "exploitability",
        "check",
        cve,
        "--analyzer-input",
        "stacks=../captures/" + pattern,
      ],
      d,
    );
    expect(code).not.toBe(0);
    expect(io.stderr.text()).toMatch(message);
  }
  expect(calls).toBe(0);
  expect(lookup).not.toHaveBeenCalled();
});

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
  expect(
    await markdown.runCli([...args, "--format", "md"], readDeps),
    markdown.stderr.text(),
  ).toBe(0);
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
  original.captures[0].stacks[0].observedAt = "2026-01-02T00:00:00.000001Z";
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

test("two searches and a raw stack keep their own coverage and positions", async () => {
  await using dir = await scopedTemporaryDirectory("stack-multiple-");
  const files = await sample(dir.path, true);
  const doc = {
    format: "codex-security.stacks/v2",
    captures: [
      {
        query: { selectors: { function: "decode" }, coverage: "partial" },
        stacks: [{ frames: [{ name: "decode" }, { name: "open_file" }] }],
      },
      {
        query: { selectors: { function: "unpack" }, coverage: "complete" },
        stacks: [],
      },
      {
        origin: "crash dump",
        stacks: [{ frames: [{ name: "parse_header" }] }],
      },
    ],
  };
  await writeFile(files.stacksPath, JSON.stringify(doc));
  const { packet, call } = await startPacket(dir.path, files);
  const items = stackPacketWorkItems(packet);
  expect(items.map(({ id, status }) => [id, status])).toEqual([
    ["captures/0/stacks/0", "observed"],
    ["captures/1", "no_match"],
    ["captures/2/stacks/0", "observed"],
  ]);
  expect(items[0]).toMatchObject({
    sinkMatches: [],
    leads: [{ sinkId: "decode", rawIndex: 0 }],
  });
  expect(items[2]).not.toHaveProperty("query");
  for (const work of items) {
    if (work.status === "no_match")
      await expect(
        call("record-assessments", {
          items: [
            {
              workItemId: work.id,
              verdict: "ruled_out",
              reason: "No stacks returned.",
            },
          ],
        }),
      ).rejects.toThrow(/requires a scoped unknown assessment/);
    await call("record-assessments", {
      items: [
        {
          workItemId: work.id,
          verdict: "unknown",
          reason: "The capture cannot identify an affected copy.",
          remainingQuestions: ["Which build ran?"],
        },
      ],
    });
  }
  expect(await call("finalize")).toMatchObject({
    verdict: "unknown",
    coverage: {
      assessed: 3,
      observed: 2,
      noMatch: [items[1]!.id],
      incompleteSearch: [items[0]!.id],
    },
  });
});

test("an explicit empty sink list is rejected by directory input and live init", async () => {
  await using dir = await scopedTemporaryDirectory("stack-empty-sinks-");
  const { repo, sinksPath } = await sample(dir.path, false);
  const catalog = { format: "codex-security.sinks/v2", cve, sinks: [] };
  await writeFile(sinksPath, JSON.stringify(catalog));
  const message = /Supply at least one sink or omit sinks/;
  await expect(
    prepareStackInput({
      cve,
      repository: repo,
      input: dir.path,
      toolRevision: "test",
    }),
  ).rejects.toThrow(message);
  await expect(
    executeStackRun("init", {
      repo,
      state: join(dir.path, "run.sqlite"),
      input: { cve, sinks: [] },
    }),
  ).rejects.toThrow(message);
});

test("without a catalog, frozen OSV ranges can exclude an attributed copy, but a name alone stays a lead", async () => {
  await using dir = await scopedTemporaryDirectory("stack-implicit-osv-");
  const { repo, stacksPath } = await sample(dir.path, false);
  const frame = {
    name: "decode",
    package: {
      name: "sample-codec",
      version: "2.1.0",
      provenance: "loaded module",
    },
  };
  await writeFile(
    stacksPath,
    JSON.stringify({
      format: "codex-security.stacks/v2",
      captures: [
        { stacks: [{ frames: [frame] }, { frames: [{ name: "decode" }] }] },
      ],
    }),
  );
  const freeze = (inputsDir: string, packages: string[]) =>
    prepareStackPacket(
      { cve, repository: repo, stacksPath, inputsDir, toolRevision: "test" },
      {
        lookupCve: (id, signal) =>
          lookupDependencyAdvisory(id, signal, async () =>
            Response.json({
              id,
              details: "Vulnerable function: `decode`",
              affected: packages.map((name) => ({
                package: { name, ecosystem: "npm" },
                ranges: [
                  {
                    type: "SEMVER",
                    events: [{ introduced: "0" }, { fixed: "2.0.0" }],
                  },
                ],
              })),
            }),
          ),
        analyze: async () => {
          throw new Error("No supplied catalog needs trigger analysis.");
        },
      },
    );
  const ambiguous = await freeze(join(dir.path, "ambiguous"), [
    "sample-codec",
    "another-codec",
  ]);
  for (const item of stackPacketWorkItems(ambiguous))
    expect(item).toMatchObject({ sinkMatches: [], leads: [] });
  const frozen = join(dir.path, "frozen");
  const original = await freeze(frozen, ["sample-codec"]);
  expect(original.sinks).toEqual({ format: "codex-security.sinks/v2", cve });
  const replay = await prepareStackInput({
    cve,
    repository: repo,
    input: frozen,
    toolRevision: "test",
  });
  const inputs = join(dir.path, "replay");
  expect((await replay(inputs)).manifest.inputDigest).toBe(
    original.manifest.inputDigest,
  );
  const state = join(dir.path, "run.sqlite");
  await executeStackRun("init", { state, inputs, repo });
  const call = (command: string, input?: unknown) =>
    executeStackRun(command, { state, input });
  const first = (await call("next")) as {
    workItem: { id: string };
    receiptId: string;
  };
  expect(first).toMatchObject({
    workItem: { sinkMatches: [{ sinkId: "decode", rawIndex: 0 }], leads: [] },
    advisoryDetails: [{ vulnerableFunctions: ["decode"] }],
  });
  const { claims } = (await call("record-claims", {
    claims: [
      {
        id: "running",
        scope: "decoder",
        payload: "The frame is from 2.1.0.",
        receiptSelections: [
          {
            receiptId: first.receiptId,
            textBlock: null,
            record: ["stack", "frames", 0, "package"],
          },
        ],
      },
    ],
  })) as { claims: DependencyClaimReference[] };
  await call("record-assessments", {
    items: [
      {
        workItemId: first.workItem.id,
        verdict: "ruled_out",
        reason: "OSV fixes the package at 2.0.0.",
        supportingClaims: claims,
      },
    ],
  });
  const second = (await call("next")) as { workItem: { id: string } };
  expect(second).toMatchObject({
    workItem: { sinkMatches: [], leads: [{ sinkId: "decode", rawIndex: 0 }] },
  });
  await expect(
    call("record-assessments", {
      items: [
        {
          workItemId: second.workItem.id,
          verdict: "ruled_out",
          reason: "The function has the same name.",
          supportingClaims: claims,
        },
      ],
    }),
  ).rejects.toThrow();
  await call("record-assessments", {
    items: [
      {
        workItemId: second.workItem.id,
        verdict: "unknown",
        reason: "The frame does not identify a package.",
        remainingQuestions: ["Which package supplied this function?"],
      },
    ],
  });
  expect(await call("finalize")).toMatchObject({
    assessments: [{ verdict: "ruled_out" }, { verdict: "unknown" }],
  });
});

test("v1 captures and empty raw snapshots are rejected before investigation", async () => {
  await using dir = await scopedTemporaryDirectory("stack-invalid-");
  const files = await sample(dir.path, false);
  for (const invalid of [
    { format: "codex-security.sampled-stacks/v1", queries: [] },
    { format: "codex-security.stacks/v2", captures: [{ stacks: [] }] },
  ]) {
    await writeFile(files.stacksPath, JSON.stringify(invalid));
    await expect(
      prepareStackPacket(packetOptions(files, join(dir.path, "invalid"))),
    ).rejects.toThrow();
  }
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
  capture.captures[0].query.selectors = {
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
    workItem: { query: { selectors: unknown } };
    sources: unknown[];
    sinks: unknown[];
  };
  expect(JSON.stringify(next.workItem.query.selectors)).toBe(
    JSON.stringify(capture.captures[0].query.selectors),
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
