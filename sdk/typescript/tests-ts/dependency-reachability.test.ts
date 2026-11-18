import { createDependencyVerdictProgress } from "../src/dependency-verdict-progress";
import { expect, test } from "bun:test";
import { z } from "zod";
import {
  dependencyCheckOutputSchema,
  readDependencyCheckOutput,
} from "../src/dependency-reachability";

test("keeps saved reports without advisory details valid and exposes the optional field", () => {
  const saved = {
    cve: "CVE-2000-1234",
    status: "unknown",
    uses: [],
    limitations: [],
    advisories: [],
    usage: null,
  };
  expect(dependencyCheckOutputSchema.safeParse(saved).success).toBe(false);
  const { status: _status, ...report } = saved;
  expect(readDependencyCheckOutput(saved)).toEqual({
    ...report,
    schemaVersion: 2,
    assumptions: [],
    searches: [],
  });
  expect(JSON.stringify(z.toJSONSchema(dependencyCheckOutputSchema))).toContain(
    '"advisoryDetails"',
  );
});

test("removes invalidated approvals before a coalesced verdict update", () => {
  const output: Record<string, unknown>[] = [];
  const progress = createDependencyVerdictProgress(
    "example",
    (type, subject, details) => output.push({ type, subject, ...details }),
  );
  function approve(
    id: string,
    line: number,
    verdict: "ruled_out" | "unknown" = "ruled_out",
  ) {
    const reason = "The wrapper validates input.";
    progress.update(id, {
      callSite: { path: "app.ts", line },
      use: {
        location: `app.ts:${line}`,
        component: "example",
        version: null,
        verdict,
        deployment: "unknown",
        reason,
        evidence: [
          { path: "app.ts", startLine: line, endLine: line, supports: [] },
        ],
        observations: [],
      },
      reason: `Reviewed ${id}. ${reason}`,
      evidenceKeys: [`excerpt:call-${line}`, "excerpt:wrapper"],
      sharedEvidenceKeys: ["excerpt:wrapper"],
    });
  }
  approve("first", 1);
  approve("second", 2);
  progress.update("second");
  progress.flush();
  expect(output).toHaveLength(1);
  approve("third", 3);
  approve("fourth", 4);
  progress.flush();
  expect(output[1]).toMatchObject({ type: "reviewed_group", callsites: 3 });
  approve("second", 2, "unknown");
  expect(output[2]).toMatchObject({
    type: "reviewed",
    location: "app.ts:2",
    previousVerdict: "ruled_out",
    verdict: "unknown",
  });
  progress.flush();
  expect(output).toHaveLength(3);

  const group = output[1];
  expect(group?.["type"]).toBe("reviewed_group");
  for (const id of ["first", "third", "fourth"]) progress.update(id);
  progress.flush();
  expect(output[3]).toMatchObject({
    type: "reviewed_group",
    groupId: group?.["groupId"],
    callsites: 0,
    assessments: 0,
  });
  approve("first", 1);
  const restored = output[4];
  expect(restored?.["type"]).toBe("reviewed");
  expect(restored?.["groupId"]).toBeDefined();
  expect(restored?.["groupId"]).not.toBe(group?.["groupId"]);
});
