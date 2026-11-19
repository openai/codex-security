import { expect, test } from "bun:test";
import {
  renderDependencyReportMarkdown,
  renderPreparedDependencyReportMarkdown,
} from "../src/dependency-report-markdown.js";
import { prepareDependencyReport } from "../src/dependency-report-model.js";
import {
  variantReport,
  zeroReport,
} from "./support/dependency-report-fixtures.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

test("Markdown attaches the missing check and scoped exclusion to their respective uses", () => {
  const report = prepareDependencyReport(variantReport());
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
  expect(output).not.toContain("[object Object]");
});

test("stack Markdown explains sampled call, gaps and claims without borrowing evidence for a no-match", () => {
  const output = renderDependencyReportMarkdown(stackReport());
  const [decisions, evidence] = output.split(/^## Evidence$/mu);
  const [, sampled, missing] = decisions!.split(/^## /mu);
  const [, recorded, absent] = evidence!.split(/^### /mu);
  expect(output).not.toMatch(/<\/?(?:details|summary)\b/iu);
  expect(output.match(/\*\*Advisory conditions\*\*/gu)).toHaveLength(1);
  expect(recorded).toContain("sample-a");
  expect(absent).toContain("sample-b");
  expect(absent).not.toContain("Sampled copy 1.0");
  expect(output).toMatch(/single-agent/i);
  expect(output).not.toMatch(/reviewed uses/i);
  expect(sampled).toContain("src/codec.ts:3");
  expect(sampled).toContain("sample-codec 1.0");
  expect(sampled).toContain("Which decoder mode ran?");
  expect(sampled).toContain("return decode(bytes);");
  expect(recorded).toMatch(
    /Frame 4.*upload[\s\S]*3 intervening frames omitted[\s\S]*Frame 0.*decode/u,
  );
  expect(recorded).toContain("Sampled copy 1.0");
  expect(missing).toContain("scheduled-job");
  expect(missing).not.toContain("return decode(bytes);");
  expect(missing).not.toContain("Sampled copy 1.0");
  expect(output).not.toContain("RAW_RECEIPT_CONTENT");
  expect(output).not.toContain("[object Object]");
});

test("zero reviewed uses still retains unresolved handoffs", () => {
  const input = zeroReport();
  const output = renderDependencyReportMarkdown(input);
  expect(output).toContain("0 reviewed uses");
  expect(output).toContain(input.coverage[0]!.reason);
  expect(output).not.toContain("[object Object]");
});
