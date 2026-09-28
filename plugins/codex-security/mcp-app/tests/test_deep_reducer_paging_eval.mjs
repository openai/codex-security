import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  gradeReducerPagingTrace,
  runReducerPagingEval,
} from "../evals/deep-reducer-paging.mjs";
import {
  createReducerPagingFixture,
  gradeReducerPagingResult,
} from "../evals/deep-reducer-paging-fixture.mjs";

test("a reducer recovers from the real IPC frame limit and records all sources", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "deep-reducer-ipc-eval-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const report = await runReducerPagingEval({ root });
  assert.equal(report.realIpcErrorObserved, true);
  assert.ok(report.actualOversizedResponseBytes > report.ipcFrameLimitBytes);
  assert.ok(report.recoveryBudget < report.firstBudget);
  assert.ok(report.successfulPages > 1);
  assert.equal(report.referenceReads, 2);
  assert.equal(report.accountedSourceCount, 3);
  assert.equal(report.preservedOriginalCount, 3);
  assert.equal(report.previousIdentityPreserved, true);
  assert.equal(report.synthesizedHistoryPreserved, true);

  const trace = (await readFile(path.join(root, "tool-trace.jsonl"), "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
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
  const fixture = await createReducerPagingFixture(root);
  const result = JSON.parse(await readFile(fixture.resultPath, "utf8"));
  const previous = result.findings.find((finding) =>
    finding.provenance.sourceFindingIds.includes(
      fixture.expected.previousSourceId,
    ),
  );
  previous.provenance.sourceFindingIds = result.findings.flatMap(
    (finding) => finding.provenance.sourceFindingIds,
  );
  previous.provenance.sourceFindings = result.findings.flatMap(
    (finding) => finding.provenance.sourceFindings,
  );
  result.findings = [previous];
  await writeFile(fixture.resultPath, JSON.stringify(result));
  await assert.rejects(
    gradeReducerPagingResult(fixture),
    /distinct|independent/,
  );
});
