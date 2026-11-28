import { expect, test } from "bun:test";
import {
  renderDependencyReportMarkdown,
  renderPreparedDependencyReportMarkdown,
  summarizeDependencyReport,
} from "../src/exploitability/report/text.js";
import { prepareDependencyReport } from "../src/exploitability/report/model.js";
import {
  variantReport,
  repositoryReport,
  report,
  unresolved,
} from "./support/dependency-report-fixtures.js";
import {
  stackReport,
  stacksReport,
} from "./support/dependency-stack-report-fixture.js";

test("Markdown attaches the missing check and scoped exclusion to their respective uses", () => {
  const report = prepareDependencyReport(repositoryReport(variantReport()));
  const output = renderPreparedDependencyReportMarkdown(report);
  const [overview, ...parts] = output.split(/^## /mu);
  expect(overview).toContain("linux/amd64");
  expect(overview).toContain("linux/arm64");
  const stable = parts.find((part) => part.includes("linux/amd64"))!;
  const canary = parts.find((part) => part.includes("linux/arm64"))!;
  expect(stable).toContain("src/handler-1.ts:2");
  expect(stable).toContain("Read the admitted worker setting");
  expect(stable).toContain("before credential validation");
  expect(stable).not.toContain("verified vendor backport");
  expect(canary).toContain("verified vendor backport");
  expect(canary).not.toContain("admitted worker setting");
  expect(
    parts.filter((p) => p.includes("Shared document helper")),
  ).toHaveLength(1);
  expect(output).toContain("enabled implementation has not been linked");
});

test("a grouped handoff counts once and keeps both candidate locations in JSON", () => {
  const locations = [
    { candidateId: "upload", path: "src/upload.ts", line: 3 },
    { candidateId: "import", path: "src/import.ts", line: 7 },
  ];
  const output = repositoryReport(report([], [unresolved(1, { locations })]));
  const json = JSON.parse(JSON.stringify(output));
  expect(
    json.vulnerabilities[0].analyses[0].coverage.dispositions[0].locations,
  ).toEqual(locations);
  const model = prepareDependencyReport(output);
  for (const render of [
    renderPreparedDependencyReportMarkdown,
    summarizeDependencyReport,
  ])
    expect(render(model)).toContain("1 unresolved coverage item");
});

test("a no-match keeps its search context but receives no sampled evidence", () => {
  const output = renderDependencyReportMarkdown(stacksReport(stackReport()));
  const [sampled, missing] = output.split("Search coverage records");
  expect(sampled).toContain("Which decoder mode ran?");
  expect(sampled).toContain("return decode(bytes);");
  expect(missing).toContain("scheduled-job");
  expect(missing).not.toContain("return decode(bytes);");
  expect(missing).not.toContain("Sampled copy 1.0");
  expect(output).not.toContain("RAW_RECEIPT_CONTENT");
});

test("Markdown annotates a caller only when its revision matches the cited code", () => {
  const raw = stackReport();
  const [sampled] = raw.assessments;
  const render = (sourceRevision: string) => {
    const frame = {
      name: "handle",
      location: "src/codec.ts:3",
      sourceRevision,
    };
    const stack = {
      ...sampled.stack,
      frames: [...sampled.stack.frames, { rawIndex: 2, frame }],
    };
    const output = renderDependencyReportMarkdown(
      stacksReport({
        ...raw,
        assessments: [{ ...sampled, stack }, raw.assessments[1]],
      }),
    );
    return output
      .split("**Captured stack**")[1]!
      .split("**Source review**")[0]!;
  };
  expect(render(raw.target.sha)).toContain("return decode(bytes);");
  expect(render("d".repeat(40))).not.toContain("return decode(bytes);");
});
