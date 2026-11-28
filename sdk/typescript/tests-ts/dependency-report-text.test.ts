import { expect, test } from "bun:test";
import {
  renderDependencyReportMarkdown,
  renderPreparedDependencyReportMarkdown,
  summarizeDependencyReport,
} from "../src/dependency/report/text.js";
import { prepareDependencyReport } from "../src/dependency/report/model.js";
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
  expect(recorded).toContain("sample-a");
  expect(absent).toContain("sample-b");
  expect(absent).not.toContain("Sampled copy 1.0");
  expect(output).toContain("Finalized offline");
  expect(output).not.toMatch(/reviewed uses/i);
  expect(sampled).toContain("src/codec.ts:3");
  expect(sampled).toContain("sample-codec 1.0");
  expect(sampled).toContain("Which decoder mode ran?");
  expect(sampled).toContain(
    "**Sampled stack** · caller first\n\n- `upload` · source, frame 4\n- … 3 intervening frames omitted\n- `decode` · matched sink, frame 0",
  );
  const [frames, review] = sampled!.split("**Source review**");
  expect(frames).not.toContain("return decode(bytes);");
  expect(review).toContain("return decode(bytes);");
  expect(recorded).not.toContain("intervening frames");
  expect(missing).not.toContain("**Sampled stack**");
  expect(recorded).toContain("Sampled copy 1.0");
  expect(missing).toContain("scheduled-job");
  expect(missing).not.toContain("return decode(bytes);");
  expect(missing).not.toContain("Sampled copy 1.0");
  expect(output).not.toContain("RAW_RECEIPT_CONTENT");
});

test("Markdown puts the bound code at its sampled frame and shows locations even without source", () => {
  const raw = stackReport();
  const [sampled] = raw.assessments;
  const observation = {
    ...sampled.observation,
    framesTruncated: true,
    sinkMatches: [],
    frames: [
      {
        rawIndex: 0,
        frame: {
          name: "decode",
          type: "native",
          location: "decoder.c",
          line: 16,
        },
      },
      {
        rawIndex: 2,
        frame: {
          name: "handle",
          type: "function",
          location: "/app.runfiles/_main/src/codec.ts:3",
        },
      },
      {
        rawIndex: 4,
        frame: { name: "upload", type: "function", location: "upload.ts:9" },
      },
    ],
  };
  const render = (sha: string) =>
    renderDependencyReportMarkdown({
      ...raw,
      assessments: [
        {
          ...sampled,
          observation: {
            ...observation,
            bindings: [
              {
                package: raw.target.repository,
                version: sha,
                sourceSha: sha,
                provenance: "sampled build",
              },
            ],
          },
        },
        raw.assessments[1],
      ],
    })
      .split("**Sampled stack**")[1]!
      .split("**Advisory conditions**")[0]!;
  const stack = render(raw.target.sha);
  expect(stack).toContain("`upload` · `upload.ts:9` · source");
  expect(stack).toContain(
    "`handle` · `src/codec.ts:3` · call site, frame 2 · calls `decode`\n\n  ```ts\n  return decode(bytes);\n  ```",
  );
  expect(stack).toContain("`decode` · `decoder.c:16` · query sink");
  expect(stack).not.toContain("matched sink");
  expect(stack).toContain("Frames truncated.");
  expect(stack).not.toContain("stack-a");
  expect(stack.split("return decode(bytes);")).toHaveLength(2);
  const [stale, review] = render("d".repeat(40)).split("**Source review**");
  expect(stale).toContain("`/app.runfiles/_main/src/codec.ts:3`");
  expect(stale).not.toContain("return decode(bytes);");
  expect(review).toContain("return decode(bytes);");
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
