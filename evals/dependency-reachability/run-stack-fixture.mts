import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs, promisify } from "node:util";
import { dependencyClaimHash } from "../../sdk/typescript/dist/dependency-claims.js";
import { inventoryJsonField } from "../../sdk/typescript/dist/dependency-inventory.js";
import { readDependencyGitSource } from "../../sdk/typescript/dist/dependency-source-identity.js";
import {
  stackInvestigationReportSchema,
  type StackInvestigationReport,
} from "../../sdk/typescript/dist/dependency-stack-assessment.js";
import {
  prepareStackPacket,
  stackPacketWorkItems,
  stackSinkMatches,
  type StackPacket,
} from "../../sdk/typescript/dist/dependency-stack-packet.js";

const run = promisify(execFile);
const { values } = parseArgs({
  options: {
    model: { type: "string" },
    cli: { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});
const usage =
  "Usage: run-stack-fixture.mts --model MODEL [--cli /checkout/sdk/typescript/bin/codex-security.mjs]";
if (values.help) {
  console.log(usage);
  process.exit(0);
}
if (!values.model) throw new Error(usage);
const model = values.model;
const fixture = join(import.meta.dirname, "fixtures/stack-workflow");
const expected = JSON.parse(
  await readFile(join(fixture, "expected.json"), "utf8"),
);
const cli = await realpath(
  resolve(
    values.cli ??
      join(import.meta.dirname, "../../sdk/typescript/bin/codex-security.mjs"),
  ),
);
const cliRevision = (
  await run("git", ["rev-parse", "HEAD"], { cwd: dirname(cli) })
).stdout.trim();
const output = join(import.meta.dirname, "reports");
await mkdir(output, { recursive: true });
const directory = await mkdtemp(join(output, "stack-"));
console.log(`Eval artifacts: ${directory}`);
const controller = new AbortController();
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    process.exitCode = signal === "SIGINT" ? 130 : 143;
    controller.abort();
  });
}

type Variant = "fixed" | "unbound";
async function grade(
  report: StackInvestigationReport,
  packet: StackPacket,
  variant: Variant,
  repo: string,
) {
  const { manifest } = packet;
  const { format, cve, advisory, target, files } = manifest;
  assert.equal(
    report.inputDigest,
    dependencyClaimHash({
      format,
      cve,
      advisory,
      target,
      files,
      toolRevision: report.toolRevision,
    }),
    "report input digest",
  );
  assert.equal(
    report.toolRevision.split("+build.")[0],
    cliRevision,
    "reported CLI commit",
  );
  assert.deepEqual(report.target, target);
  assert.equal(report.cve, expected.cve);
  assert.deepEqual(report.coverage, {
    total: 1,
    assessed: 1,
    observed: 1,
    outstanding: [],
    noMatch: [],
    noCoverage: [],
    truncated: [],
    truncationUnknown: [],
    scopeConflicts: [],
  });
  const [item] = stackPacketWorkItems(packet);
  assert(item?.observation);
  const obs = item.observation;
  const [assessment] = report.assessments;
  assert.equal(report.assessments.length, 1);
  assert(assessment?.observation);
  assert.equal(assessment.workItemId, expected.workItemId);
  assert.equal(assessment.workItemId, item.id);
  assert.equal(assessment.queryId, item.queryId);
  assert.equal(assessment.groupId, item.groupId);
  assert.equal(assessment.status, item.status);
  assert.deepEqual(assessment.scope, item.scope);
  assert.deepEqual(assessment.queryScope, item.queryScope);
  assert.deepEqual(assessment.scopeConflicts, []);
  assert.equal(report.verdict, expected[variant].verdict);
  assert.equal(assessment.verdict, report.verdict);
  const cited = assessment.observation;
  assert.equal(cited.id, obs.id);
  assert.equal(cited.stackHash, obs.stackHash);
  assert.equal(cited.sourceIndex, obs.sourceIndex);
  assert.equal(cited.sinkIndex, obs.sinkIndex);
  assert.deepEqual(cited.sinkMatches, stackSinkMatches(obs));
  assert.deepEqual(
    cited.frames,
    obs.frames.map((frame, rawIndex) => ({ rawIndex, frame })),
    "original captured frames",
  );
  assert.deepEqual(cited.bindings, obs.bindings ?? []);

  const claims = new Map(report.claims.map((c) => [c.id, c]));
  const pending = [...assessment.supportingClaims];
  const selected = new Set<string>();
  while (pending.length) {
    const ref = pending.pop()!;
    const claim = claims.get(ref.id);
    assert(
      claim && claim.revision === ref.revision && ref.hash === claim.hash,
      "exact supporting claim",
    );
    if (selected.has(claim.id)) continue;
    selected.add(claim.id);
    pending.push(...claim.dependencies);
  }
  assert.equal(selected.size, report.claims.length, "cited claim closure");
  for (const claim of claims.values()) {
    for (const source of claim.sources) {
      assert.equal(source.commit, target.sha);
      const { bytes, identity } = await readDependencyGitSource(
        repo,
        target.sha,
        source.path,
      );
      assert.equal(source.blob, identity.blob);
      assert.equal(source.contentSha256, identity.contentSha256);
      const text = bytes.toString("utf8").replace(/\r\n/gu, "\n");
      const lines = text ? text.replace(/\n$/u, "").split("\n") : [];
      assert(
        source.startLine <= source.endLine && source.endLine <= lines.length,
      );
      assert.equal(
        source.text,
        lines.slice(source.startLine - 1, source.endLine).join("\n"),
      );
    }
    for (const receipt of claim.receipts) {
      assert.equal(receipt.server, "stack-packet");
      assert.equal(receipt.originalPayloadSha256, files.stacks.sha256);
      assert.deepEqual(receipt.origin, {
        tool: "read-stacks",
        arguments: {
          inputDigest: report.inputDigest,
          workItemId: item.id,
          queryId: item.queryId,
          groupId: item.groupId,
        },
      });
      assert.deepEqual(
        receipt.result,
        receipt.selection
          ? inventoryJsonField(item, receipt.selection.record)
          : item,
      );
    }
  }
  if (variant === "fixed") {
    const [binding] = obs.bindings ?? [];
    assert(
      binding?.evidence?.length &&
        binding.provenance === expected.fixed.decidingEvidence &&
        binding.version === "2.1.0" &&
        binding.package === "sample-codec",
    );
    const sources = report.claims.flatMap((c) => c.sources);
    const bySource = binding.evidence.every((range) => {
      for (let line = range.startLine; line <= range.endLine; line++) {
        if (
          !sources.some(
            (s) =>
              s.path === range.path && s.startLine <= line && line <= s.endLine,
          )
        )
          return false;
      }
      return true;
    });
    const byReceipt = report.claims.some((c) =>
      c.receipts.some(
        (r) =>
          JSON.stringify(r.selection?.record) ===
          JSON.stringify(["observation", "bindings", 0]),
      ),
    );
    assert(
      bySource || byReceipt,
      "A ruled-out path must cite the deployment version binding.",
    );
  } else {
    assert(
      assessment.remainingQuestions.some(
        (q) =>
          /\b(versions?|releases?)\b/i.test(q) ||
          (/\b(build|artifact|copy)\b/i.test(q) &&
            /\b(sample-codec|dependency|package)\b/i.test(q)),
      ),
      "Identify the missing deployed dependency version.",
    );
    assert(
      assessment.remainingQuestions.every((q) =>
        report.remainingQuestions.includes(q),
      ),
    );
  }
}

async function runVariant(variant: Variant) {
  const root = await mkdtemp(join(tmpdir(), "stack-eval-"));
  let fixtureDigest: string | undefined;
  let elapsedMs: number | undefined;
  let toolRevision: string | undefined;
  const reportFile = join(directory, variant + ".json");
  try {
    const inputs = join(root, "inputs");
    const repo = join(inputs, "target");
    await run(
      process.execPath,
      [join(fixture, "prepare.mjs"), inputs, variant],
      { signal: controller.signal },
    );
    const files = {
      cve: expected.cve as string,
      sourcesPath: join(inputs, "sources.json"),
      sinksPath: join(inputs, "sinks.json"),
      stacksPath: join(inputs, "stacks.json"),
    };
    const packet = await prepareStackPacket({
      ...files,
      inputsDir: join(root, "frozen"),
      repository: repo,
      toolRevision: "fixture",
      signal: controller.signal,
    });
    fixtureDigest = packet.manifest.inputDigest;
    const start = performance.now();
    try {
      const { stdout } = await run(
        process.execPath,
        [
          cli,
          "exploitability",
          "check",
          files.cve,
          "--sources",
          files.sourcesPath,
          "--sinks",
          files.sinksPath,
          "--stacks",
          files.stacksPath,
          "--model",
          model,
          "--report-file",
          reportFile,
          "--json",
        ],
        { cwd: repo, signal: controller.signal, maxBuffer: Infinity },
      );
      assert.deepEqual(
        JSON.parse(stdout as string),
        JSON.parse(await readFile(reportFile, "utf8")),
        "CLI stdout and saved report",
      );
    } finally {
      elapsedMs = Math.round(performance.now() - start);
    }
    const report = stackInvestigationReportSchema.parse(
      JSON.parse(await readFile(reportFile, "utf8")),
    );
    toolRevision = report.toolRevision;
    await grade(report, packet, variant, repo);
    return { variant, pass: true, fixtureDigest, elapsedMs, toolRevision };
  } catch (e) {
    return {
      variant,
      pass: false,
      fixtureDigest,
      elapsedMs,
      toolRevision,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
const results = [];
for (const variant of ["fixed", "unbound"] as const) {
  if (controller.signal.aborted) break;
  const result = await runVariant(variant);
  results.push(result);
  console.log(
    `${variant}: ${result.pass ? "PASS" : "FAIL"} (${result.elapsedMs ?? 0} ms)`,
  );
  if (result.error) console.error(result.error);
  await writeFile(
    join(directory, "report.json"),
    JSON.stringify({ model, cli, cliRevision, results }, null, 2) + "\n",
  );
}
if (results.length !== 2 || results.some((r) => !r.pass))
  process.exitCode ||= 1;
