import { readJson, readJsonLines } from "./support/json.ts";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  gradeReducerPagingTrace,
  runReducerPagingEval,
} from "./support/reducer-paging/deep-reducer-paging.ts";
import { gradeReducerPagingResult } from "./support/reducer-paging/deep-reducer-paging-fixture.ts";

test("a reducer recovers from the real IPC frame limit and records all sources", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "deep-reducer-ipc-eval-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { report, fixture } = await runReducerPagingEval({ root });
  assert.equal(report.realIpcErrorObserved, true);
  assert.ok(report.actualOversizedResponseBytes! > report.ipcFrameLimitBytes);
  assert.ok(report.recoveryBudget < report.firstBudget);
  assert.ok(report.successfulPages > 1);
  assert.equal(report.referenceReads, 2);
  assert.equal(report.accountedSourceCount, 3);
  assert.equal(report.preservedOriginalCount, 3);
  assert.equal(report.previousIdentityPreserved, true);
  assert.equal(report.synthesizedHistoryPreserved, true);

  const trace = await readJsonLines(path.join(root, "tool-trace.jsonl"));
  const rootPages = trace.filter(
    (event) =>
      event.event === "request" &&
      event.tool === "get_codex_security_deep_reducer_inputs" &&
      event.input.findingRef === undefined,
  );
  const missingPage = rootPages[2].id;
  assert.throws(
    () =>
      gradeReducerPagingTrace(
        trace.filter(
          (event) => !(event.event === "response" && event.id === missingPage),
        ),
        report.ipcFrameLimitBytes,
      ),
    /read every assigned-input page/,
  );

  // Keeping every original is insufficient if distinct issues are collapsed.
  const result: {
    findings: {
      provenance: { sourceFindingIds: string[]; sourceFindings: unknown[] };
    }[];
  } = await readJson(fixture.resultPath);
  const previous = result.findings.find((finding) =>
    finding.provenance.sourceFindingIds.includes(
      fixture.expected.previousSourceId,
    ),
  );
  previous!.provenance.sourceFindingIds = result.findings.flatMap(
    (finding) => finding.provenance.sourceFindingIds,
  );
  previous!.provenance.sourceFindings = result.findings.flatMap(
    (finding) => finding.provenance.sourceFindings,
  );
  result.findings = [previous!];
  await writeFile(fixture.resultPath, JSON.stringify(result));
  await assert.rejects(
    gradeReducerPagingResult(fixture),
    /distinct|independent/,
  );
});
