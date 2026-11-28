import {
  renderPreparedDependencyReportMarkdown,
  summarizeDependencyReport,
} from "../src/exploitability/report/text.js";
import { expect, test } from "bun:test";
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import {
  DependencyInvestigationBlockedError,
  runPreparedAnalyzers,
  withDependencyCheckOutput,
  writeDependencyReportFile,
} from "../src/exploitability/check-output.js";
import { prepareDependencyReport } from "../src/exploitability/report/model.js";
import { renderPreparedDependencyReport } from "../src/exploitability/report/renderer.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import {
  variantReport,
  reviewed,
  report,
} from "./support/dependency-report-fixtures.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

const signal = new AbortController().signal;

test("a blocked analyzer preserves earlier results and publishes no completed report", async () => {
  await using dir = await scopedTemporaryDirectory("blocked-analyzer-");
  const subject = "CVE-2099-1000";
  const reportFile = join(dir.path, "report.json");
  const progressEvents = join(dir.path, "progress.jsonl");
  const completed = { cve: subject, uses: [] };
  const investigation = withDependencyCheckOutput(
    { subject, reportFile, progressEvents, signal, warn: () => {} },
    (emit) =>
      runPreparedAnalyzers(
        [
          {
            name: "repository",
            async run(progress) {
              progress("discovery", subject);
              return completed;
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
      ),
  );
  const error = await investigation.catch((reason: unknown) => reason);
  expect(error).toBeInstanceOf(DependencyInvestigationBlockedError);
  expect((error as DependencyInvestigationBlockedError).outcome).toMatchObject({
    status: "blocked",
    pendingAnalyzers: [],
    analyzers: {
      repository: completed,
      stacks: { status: "blocked", reason: "capture unavailable" },
    },
  });
  expect(await readdir(dir.path)).toEqual(["progress.jsonl"]);
  const events = (await readFile(progressEvents, "utf8"))
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row));
  expect(events).toContainEqual(
    expect.objectContaining({ type: "stage", analyzer: "repository" }),
  );
  expect(events.at(-1)).toMatchObject({ type: "finished", outcome: "blocked" });
});

test.each([
  ["repository", variantReport()],
  ["sampled stacks", stackReport()],
] as const)("HTML reproduces the saved JSON for %s", async (_kind, result) => {
  await using dir = await scopedTemporaryDirectory("report-files-");
  const json = join(dir.path, "evidence.json"),
    html = join(dir.path, "report.html");
  await writeDependencyReportFile(json, result, signal);
  const saved = JSON.parse(await readFile(json, "utf8"));
  const model = JSON.parse(JSON.stringify(prepareDependencyReport(saved)));
  await writeDependencyReportFile(html, result, signal, "html");
  expect(await readFile(html, "utf8")).toBe(
    renderPreparedDependencyReport(model),
  );
  if (process.platform !== "win32")
    expect((await stat(html)).mode & 0o077).toBe(0);
  expect(JSON.parse(JSON.stringify(result))).toEqual(saved);
});

test("failed rendering and concurrent saves preserve file publication semantics", async () => {
  await using dir = await scopedTemporaryDirectory("report-files-");
  const path = join(dir.path, "report.html");
  const save = (data: unknown) =>
    writeDependencyReportFile(path, data, signal, "html");
  await expect(save({ wrong: "shape" })).rejects.toThrow();
  expect(await readdir(dir.path)).toEqual([]);
  const results = await Promise.allSettled(
    [variantReport(), stackReport()].map(save),
  );
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  const published = await readFile(path, "utf8");
  expect(published.trimEnd().endsWith("</html>")).toBe(true);
  await expect(save(variantReport())).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(published);
  expect(await readdir(dir.path)).toEqual(["report.html"]);
});

const checkout = {
  repository: "example/document-preview",
  sha: "0123456789abcdef0123456789abcdef01234567",
};
const otherRevision = "a".repeat(40);
function reviewedWithRuntimeRevision() {
  const use = reviewed(1);
  use.place.revision = otherRevision;
  use.evidence[0]!.commit = otherRevision;
  return report([use]);
}

test.each([
  ["checkout", reviewedWithRuntimeRevision()],
  ["sampled stacks", stackReport()],
  [
    "package with multiple advisories",
    {
      package: { ecosystem: "npm", name: "sample-codec" },
      checks: ["CVE-2099-44001", "CVE-2099-44002"].map((advisoryId) => {
        const { cve: _cve, ...check } = reviewedWithRuntimeRevision();
        return { ...check, advisoryId };
      }),
    },
  ],
  [
    "package without advisories",
    { package: { ecosystem: "npm", name: "sample-codec" }, checks: [] },
  ],
  [
    "blocked",
    { status: "blocked", code: "INVESTIGATION_BLOCKED", reason: "Unavailable" },
  ],
] as const)(
  "identifies the analyzed checkout once in the report header for %s",
  (_kind, data) => {
    const model = prepareDependencyReport({
      data: { ...data, target: checkout },
    });
    const html = renderPreparedDependencyReport(model);
    const header = html.match(
      /<header class="masthead">([\s\S]*?)<\/header>/u,
    )![1]!;
    const md = renderPreparedDependencyReportMarkdown(model).split("\n\n")[1]!;
    const summary = summarizeDependencyReport(model);
    expect(html.split(checkout.repository)).toHaveLength(2);
    for (const text of [header, md, summary]) {
      expect(text).toContain(checkout.repository);
      expect(text).toContain(checkout.sha);
    }
    expect(header).toContain(">" + checkout.sha.slice(0, 12) + "</code>");
    expect(header).not.toContain(otherRevision);
    expect(md).not.toContain(otherRevision);
  },
);

test("older reports preserve an unknown checkout even when evidence cites a commit", () => {
  const model = prepareDependencyReport(reviewedWithRuntimeRevision());
  expect(model.target).toBeUndefined();
  const html = renderPreparedDependencyReport(model);
  expect(html).toContain("Checkout not recorded");
  expect(renderPreparedDependencyReportMarkdown(model)).toContain(
    "Checkout not recorded",
  );
});
