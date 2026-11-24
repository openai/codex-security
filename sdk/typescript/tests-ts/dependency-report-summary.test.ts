import { expect, test } from "bun:test";
import { prepareDependencyReport } from "../src/dependency-report-model.js";
import { summarizeDependencyReport } from "../src/dependency-report-summary.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

test("the short stack summary leads with decisions and questions scoped to each sampled use", () => {
  const report = stackReport();
  const output = summarizeDependencyReport(prepareDependencyReport(report));
  expect(output).toContain("2/2 stack items assessed");
  expect(output).toContain("1 truncated");
  expect(output).toContain("1 without a match");
  expect(output).toContain("prod · uploader");
  expect(output).toContain("scheduled-job");
  expect(output).toContain("2099-02-01T00:00:00Z");
  expect(output).toContain(
    "Requires more information · decode at the upload handler · sample-codec@1.0 · stack-a",
  );
  expect(output).toContain("Call: src/codec.ts:3");
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
