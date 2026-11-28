import { expect, test } from "bun:test";
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import {
  assembleExploitabilityReport,
  stackAnalyzerBatch,
  runPreparedAnalyzers,
  withDependencyCheckOutput,
  writeDependencyReportFile,
} from "../src/exploitability/check-output.js";
import { stackInvestigationReportSchema } from "../src/exploitability/analyzers/stacks/assessment.js";
import { synthesizeVulnerabilityResult } from "../src/exploitability/report/synthesis.js";
import { renderDependencyReport } from "../src/exploitability/report/renderer.js";
import { renderDependencyReportMarkdown } from "../src/exploitability/report/text.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import {
  repositoryReport,
  repositoryBatch,
  reviewed,
  report,
} from "./support/dependency-report-fixtures.js";
import {
  stackReport,
  stacksReport,
} from "./support/dependency-stack-report-fixture.js";

const signal = new AbortController().signal;

test("a blocked analyzer preserves completed findings without publishing a complete report", async () => {
  await using dir = await scopedTemporaryDirectory("blocked-analyzer-");
  const completed = report([reviewed(1)]);
  const subject = completed.cve;
  const reportFile = join(dir.path, "report.json");
  const progressEvents = join(dir.path, "progress.jsonl");
  const result = await withDependencyCheckOutput(
    { subject, reportFile, progressEvents, signal, warn: () => {} },
    (emit) =>
      runPreparedAnalyzers(
        [
          {
            name: "repository",
            async run(progress) {
              progress("discovery", subject);
              return repositoryBatch(completed);
            },
          },
          {
            name: "stacks",
            async run() {
              throw new Error("capture unavailable");
            },
          },
        ],
        subject,
        emit,
        signal,
        {
          async synthesize() {
            throw Error("Incomplete results cannot be synthesized.");
          },
        },
      ),
  );
  expect(result).toMatchObject({
    status: "blocked",
    reason: expect.stringContaining("capture unavailable"),
    vulnerabilities: [
      {
        status: "blocked",
        result: null,
        analyses: [
          { analyzer: "repository", status: "complete" },
          {
            analyzer: "stacks",
            status: "blocked",
            reason: "capture unavailable",
          },
        ],
        findings: [{ analyzer: "repository", location: "Handler 1" }],
      },
    ],
  });
  expect(await readdir(dir.path)).toEqual(["progress.jsonl"]);
  const events = (await readFile(progressEvents, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(events).toContainEqual(
    expect.objectContaining({ type: "stage", analyzer: "repository" }),
  );
  expect(events.at(-1)).toMatchObject({ type: "finished", outcome: "blocked" });
});

test("synthesis combines complementary findings only for the same advisory and checkout", async () => {
  const stack = stackReport();
  const repo = {
    ...report([
      reviewed(1, {
        verdict: "potentially_exploitable",
        version: "1.0",
        reason:
          "The upload handler selects the affected mode and passes attacker bytes to decode.",
      }),
    ]),
    cve: stack.cve,
    target: stack.target,
  };
  const combine = (other: typeof stack) =>
    assembleExploitabilityReport(stack.cve, [
      repositoryBatch(repo),
      stackAnalyzerBatch(stackInvestigationReportSchema.parse(other)),
    ]);
  expect(() => combine({ ...stack, cve: "CVE-2099-44099" })).toThrow(
    /advisory/i,
  );
  expect(() =>
    combine({ ...stack, target: { ...stack.target, sha: "d".repeat(40) } }),
  ).toThrow(/checkout/i);
  const output = combine(stack);
  const [combined] = output.vulnerabilities;
  expect(combined!.findings.map((f) => f.analyzer)).toEqual([
    "repository",
    "stacks",
  ]);
  const analysis = combined!.analyses.find((a) => a.analyzer === "stacks")!;
  expect(analysis.coverage?.items).toMatchObject([
    { status: "no_match", workItemId: "captures/1" },
  ]);
  const responses = [
    {
      verdict: "exploitable",
      reason: "The affected upload decoder receives attacker bytes.",
      questions: [],
      findingRefs: [0, 1],
    },
    {
      status: "approved",
      reason: "The upload evidence identifies the same affected copy.",
    },
  ];
  const verdict = await synthesizeVulnerabilityResult(combined!, {
    directory: ".",
    signal,
    runAgent: async () => JSON.stringify(responses.shift()),
  });
  expect(verdict).toMatchObject({
    verdict: "exploitable",
    findingRefs: [0, 1],
    review: { status: "approved" },
  });
  combined!.result = verdict;
  for (const render of [
    renderDependencyReport,
    renderDependencyReportMarkdown,
  ]) {
    const text = render(output);
    expect(text).toContain(verdict.reason);
    expect(text).toContain("Handler 1");
    expect(text).toContain("Which decoder mode ran?");
  }
});

test("synthesis cannot discard an exploitable finding or publish a rejected result", async () => {
  const native = report([reviewed(1, { verdict: "exploitable" })]);
  const entry = repositoryBatch(native).vulnerabilities[0]!;
  const proposal = {
    verdict: "exploitable",
    reason: "Attacker input reaches decode.",
    questions: [],
    findingRefs: [0],
  };
  for (const [verdict, reason] of [
    ["ruled_out", /contradicts/u],
    ["exploitable", /rejected.*Wrong copy/u],
  ] as const) {
    const responses = [
      { ...proposal, verdict },
      { status: "rejected", reason: "Wrong copy." },
    ];
    await expect(
      synthesizeVulnerabilityResult(entry, {
        directory: ".",
        signal,
        async runAgent(request) {
          expect(request.readOnly).toBe(true);
          expect(request.coordinator).toBe(false);
          return JSON.stringify(responses.shift());
        },
      }),
    ).rejects.toThrow(reason);
    expect(responses.length).toBe(verdict === "ruled_out" ? 1 : 0);
  }
});

test("failed rendering and concurrent saves do not replace another report", async () => {
  await using dir = await scopedTemporaryDirectory("report-files-");
  const path = join(dir.path, "report.html");
  const save = (data: unknown) =>
    writeDependencyReportFile(path, data, signal, "html");
  await expect(save({ wrong: "shape" })).rejects.toThrow();
  expect(await readdir(dir.path)).toEqual([]);
  const results = await Promise.allSettled(
    [repositoryReport(report([reviewed(1)])), stacksReport(stackReport())].map(
      save,
    ),
  );
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  const published = await readFile(path, "utf8");
  expect(published.trimEnd().endsWith("</html>")).toBe(true);
  if (process.platform !== "win32")
    expect((await stat(path)).mode & 0o077).toBe(0);
  expect(await readdir(dir.path)).toEqual(["report.html"]);
});

test("a deployed revision cannot stand in for the checkout in report headers", () => {
  const checkout = {
    repository: "example/document-preview",
    sha: "0123456789abcdef0123456789abcdef01234567",
  };
  const deployed = "a".repeat(40);
  const use = reviewed(1);
  use.place.revision = deployed;
  use.evidence[0]!.commit = deployed;
  const output = repositoryReport({ ...report([use]), target: checkout });
  const header = renderDependencyReport(output).match(
    /<header class="masthead">([\s\S]*?)<\/header>/u,
  )![1]!;
  const md = renderDependencyReportMarkdown(output).split("\n\n")[1]!;
  for (const text of [header, md]) {
    expect(text).toContain(checkout.repository);
    expect(text).toContain(checkout.sha);
    expect(text).not.toContain(deployed);
  }
});
