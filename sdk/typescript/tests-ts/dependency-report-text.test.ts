import { expect, test } from "bun:test";
import {
  renderDependencyReportMarkdown,
  renderPreparedDependencyReportMarkdown,
  summarizeDependencyReport,
} from "../src/exploitability/report/text.js";
import { prepareDependencyReport } from "../src/exploitability/report/model.js";
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
});

test("stack Markdown explains sampled call, gaps and claims without borrowing evidence for a no-match", () => {
  const output = renderDependencyReportMarkdown(stackReport());
  const [decisions, evidence] = output.split(/^## Evidence$/mu);
  const [, sampled, missing] = decisions!.split(/^## /mu);
  const [, recorded, absent] = evidence!.split(/^### /mu);
  expect(output).not.toMatch(/<\/?(?:details|summary)\b/iu);
  expect(output.match(/\*\*Advisory conditions\*\*/gu)).toHaveLength(1);
  expect(recorded).toContain("captures/0/stacks/0");
  expect(absent).toContain("captures/1");
  expect(absent).not.toContain("Sampled copy 1.0");
  expect(output).toContain("Finalized offline");
  expect(output).not.toMatch(/reviewed uses/i);
  expect(sampled).toContain("src/codec.ts:3");
  expect(sampled).toContain("sample-codec 1.0");
  expect(sampled).toContain("Which decoder mode ran?");
  expect(sampled).toContain(
    "**Captured stack** · caller first\n\n- `upload` · frame 4\n- … 3 intervening frames omitted\n- `decode` · matched sink, frame 0",
  );
  const [frames, review] = sampled!.split("**Source review**");
  expect(frames).not.toContain("return decode(bytes);");
  expect(review).toContain("return decode(bytes);");
  expect(recorded).not.toContain("intervening frames");
  expect(missing).not.toContain("**Captured stack**");
  expect(recorded).toContain("Sampled copy 1.0");
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
    const output = renderDependencyReportMarkdown({
      ...raw,
      assessments: [{ ...sampled, stack }, raw.assessments[1]],
    });
    return output
      .split("**Captured stack**")[1]!
      .split("**Source review**")[0]!;
  };
  expect(render(raw.target.sha)).toContain("return decode(bytes);");
  expect(render("d".repeat(40))).not.toContain("return decode(bytes);");
});

test("zero reviewed uses still retains unresolved handoffs", () => {
  const input = zeroReport();
  const output = renderDependencyReportMarkdown(input);
  expect(output).toContain("0 reviewed uses");
  expect(output).toContain(input.coverage[0]!.reason);
});

test("the short stack summary leads with decisions and questions scoped to each sampled use", () => {
  const report = stackReport();
  const output = summarizeDependencyReport(prepareDependencyReport(report));
  expect(output).toContain("2/2 stack items assessed");
  expect(output).toContain("Partial or unknown search coverage: 1");
  expect(output).toContain("No matching stack: 1");
  expect(output).toContain("Next: Which decoder mode ran?");
  expect(output).toContain("Next: Did the job run?");
  expect(output).not.toContain(report.assessments[0].reason);
});

test("distinguishes a blocked investigation from package advisories never started", () => {
  const blocked = {
    status: "blocked",
    code: "INVESTIGATION_BLOCKED",
    reason: "Missing inventory.",
  };
  const output = summarizeDependencyReport(
    prepareDependencyReport({
      ...blocked,
      package: { ecosystem: "npm", name: "sample-codec" },
      checks: [{ ...blocked, advisoryId: "CVE-2099-10001" }],
      pendingAdvisories: ["CVE-2099-10002"],
    }),
  );
  expect(output).toContain(
    "CVE-2099-10001\nInvestigation blocked · Missing inventory.",
  );
  expect(output).toContain("CVE-2099-10002\nNot investigated");
  expect(output).not.toContain("0 reviewed");
});
