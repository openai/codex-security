import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import type { DependencyAssessment } from "../src/dependency-reachability.js";
import { createDependencyReportSubmission } from "../src/dependency-report-submission.js";
import { runReadOnlyCodex } from "../src/scan-comparison.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const advisory = { cve: "CVE-2023-0001", advisories: [] };
const approved = {
  accepted: true,
  reason: "Supported by the selected source.",
};
const gap = { accepted: false, reason: "No cited loop covers every entry." };

interface ReviewPacket {
  items: {
    id: string;
    revision: number;
    kind: string;
    use?: { location: string; version?: unknown };
    excerptIds: string[];
    receiptIds: string[];
  }[];
  excerpts: Record<string, { text: string }>;
  receipts: Record<string, { result: unknown }>;
}

function reviewPacket(prompt: string): ReviewPacket {
  return JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
}

function reviewDecision(
  prompt: string,
  decision: { accepted: boolean; reason: string },
  citedVersion: string | null = "1.0",
) {
  return JSON.stringify({
    items: reviewPacket(prompt).items.map((item) => ({
      id: item.id,
      revision: item.revision,
      ...decision,
      citedVersion,
      evidenceIds: [...item.excerptIds, ...item.receiptIds],
    })),
  });
}

async function queueScopeGap(
  state: ReturnType<typeof createDependencyReportSubmission>,
  reason: string,
  endLine = 2,
) {
  expect(
    await state.queue({
      items: [
        {
          id: "scope",
          kind: "unresolved",
          candidateIds: [],
          reason,
          evidence: [
            { path: "worker.ts", startLine: 2, endLine, supports: [] },
          ],
          observations: [],
        },
      ],
    }),
  ).toMatchObject({ queued: true });
}

function draft(): DependencyAssessment {
  return {
    status: "ruled_out",
    limitations: [],
    uses: [
      {
        location: "worker",
        component: "library",
        version: "1.0",
        verdict: "ruled_out",
        deployment: "configured",
        reason: "Every entry is checked before processing.",
        evidence: [
          { path: "worker.ts", startLine: 2, endLine: 2, supports: [] },
        ],
        observations: [],
      },
    ],
  };
}

function graphItem(
  id: string,
  revision: number,
  pending: number,
  truncated = false,
) {
  return {
    id,
    type: "mcpToolCall",
    server: "codex_security_dependency",
    tool: "query_codex_security_graph",
    status: "completed",
    result: {
      structuredContent: {
        service_resolution: { revision, pending, truncated },
      },
    },
  };
}

test("an unconfirmed graph requires a fresh query and reopens changed accepted coverage", async () => {
  const state = createDependencyReportSubmission({
    advisory,
    repository: "/synthetic",
    review: async () => JSON.stringify({ items: [] }),
  });
  const report: DependencyAssessment = {
    status: "unknown",
    uses: [],
    limitations: ["Version unresolved."],
  };
  state.recordGraphEvent("item/started", graphItem("old", 1, 0));
  state.recordGraphEvent("item/completed", {
    ...graphItem("failed", 1, 0),
    status: "failed",
  });
  state.recordGraphEvent("item/completed", graphItem("old", 1, 0));
  expect((await state.submit(report)).accepted).toBe(false);
  state.recordGraphEvent("item/started", graphItem("new", 1, 0));
  state.recordGraphEvent("item/completed", graphItem("new", 1, 0));
  expect((await state.submit(report)).accepted).toBe(true);
  state.recordGraphEvent("item/completed", graphItem("new-work", 2, 1));
  expect(() => state.acceptedReport()).toThrow(
    "evidence changed after finalization",
  );
  expect(state.continuationPrompt()).toContain(
    "evidence changed after finalization",
  );
});

test("uncompleted service work can only yield a reviewed, explicitly partial assessment", async () => {
  await using repo = await scopedTemporaryDirectory("review-partial-");
  await writeFile(join(repo.path, "worker.ts"), "one\ntwo\n");
  for (const pending of [0, 2]) {
    let reviews = 0;
    const state = createDependencyReportSubmission({
      advisory,
      repository: repo.path,
      review: async (prompt) => {
        reviews++;
        expect(reviewPacket(prompt).items[0]!.use!.location).toBe("worker");
        return reviewDecision(prompt, approved);
      },
    });
    state.recordGraphEvent(
      "item/completed",
      graphItem("trace", 1, pending, true),
    );
    const report = draft();
    report.status = "unknown";
    if (pending) {
      for (let i = 0; i < 9; i++)
        expect((await state.submit(report)).accepted).toBe(false);
    }
    expect((await state.submit(report)).accepted).toBe(true);
    expect(reviews).toBe(1);
    const partial = state.acceptedReport();
    expect(partial.status).toBe("unknown");
    expect(partial.limitations.join(" ")).toContain("graph reached its limit");
    if (pending)
      expect(partial.limitations.join(" ")).toContain(
        "2 pending service lookups",
      );
  }
});

test("returns scoped feedback to the investigator and publishes only the approved revision", async () => {
  await using repo = await scopedTemporaryDirectory("review-submit-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "unrelated\nfor (const entry of entries) {\n  check(entry);\n}\n",
  );
  const packets: string[] = [];
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      packets.push(prompt);
      return reviewDecision(prompt, packets.length === 1 ? gap : approved);
    },
  });
  const original = draft();
  const rejection = await submission.submit(original);
  expect(rejection.accepted).toBe(false);
  for (const feedback of [
    rejection.feedback,
    submission.continuationPrompt(),
  ]) {
    expect(feedback).toContain(gap.reason);
    expect(feedback).toContain("Attempts remaining: 9");
    expect(feedback).toMatch(
      /Correct unsupported claims[^\n]*deciding evidence/,
    );
    expect(feedback).toContain("preserve genuine uncertainty");
    expect(feedback).toContain("Reuse item IDs for revisions");
  }
  expect(() => submission.acceptedReport()).toThrow(gap.reason);
  expect(packets[0]).toContain("for (const entry of entries)");
  expect(packets[0]).not.toContain("check(entry);");
  const corrected = draft();
  corrected.uses[0]!.evidence[0]!.endLine = 3;
  expect((await submission.submit(corrected)).accepted).toBe(true);
  expect(packets[1]).toContain("check(entry);");
  expect(packets[1]).not.toContain(gap.reason);
  expect(submission.acceptedReport()).toEqual(corrected);
  expect((await submission.submit(original)).accepted).toBe(false);
  original.uses[0]!.reason = "Unrelated assertion";
  expect(submission.acceptedReport()).toEqual(corrected);
  expect(packets).toHaveLength(2);
});

test("reviews an explicitly cited search lead and requires a disposition for a later graph candidate", async () => {
  await using repo = await scopedTemporaryDirectory("review-search-lead-");
  await writeFile(
    join(repo.path, "worker.ts"),
    'load("library@1.0");\nfor (const entry of entries) { check(entry); }\n',
  );
  const candidates = await createDependencyCandidates(repo.path);
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    review: async (prompt) => {
      expect(prompt).toContain("check(entry);");
      return reviewDecision(prompt, approved);
    },
  });
  const report = draft();
  const use = report.uses[0]!;
  use.evidence[0]!.startLine = 1;
  const item = { id: "worker", kind: "use", use };
  const final = { ...report, reviewItemIds: [item.id] };
  await candidates.observeGraph("trace_codex_security_code", {
    textMatches: [{ source: "worker.ts", text: "check", lines: [2] }],
  });
  expect(
    await state.queue({ items: [{ ...item, candidateIds: [] }] }),
  ).toMatchObject({
    queued: true,
  });
  expect((await state.submit(final)).accepted).toBe(true);

  const [call] = await candidates.observeGraph("query_codex_security_graph", {
    paths: [{ relation: "candidate_call", source: "worker.ts", line: 2 }],
  });
  expect(await state.submit(final)).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(call!.id),
  });
  expect(
    await state.queue({ items: [{ ...item, candidateIds: [call!.id] }] }),
  ).toMatchObject({ queued: true });
  expect((await state.submit(final)).accepted).toBe(true);
  expect(state.acceptedReport()).toEqual(report);
});

test("reviews each package declared on the same manifest line under its own identity", async () => {
  await using repo = await scopedTemporaryDirectory(
    "review-manifest-packages-",
  );
  const path = "package.json";
  await writeFile(
    join(repo.path, path),
    '{"dependencies":{"decoder":"1","encoder":"2"}}\n',
  );
  const packages = [
    { name: "decoder", scope: path },
    { name: "encoder", scope: path },
  ];
  const candidates = await createDependencyCandidates(repo.path);
  const traced = [];
  for (const target of packages) {
    traced.push(
      ...(await candidates.observeGraph("trace_codex_security_code", {
        trace: [
          {
            relation: "depends_on",
            to: { kind: "package", ...target },
            evidence: [{ source: path, lines: [1] }],
          },
        ],
      })),
    );
  }
  const identities = traced.map(({ id, package: target }) => ({
    id,
    package: target,
  }));
  expect(identities.map((entry) => entry.package)).toEqual(packages);
  expect(new Set(traced.map(({ id }) => id)).size).toBe(2);

  const queried = await candidates.observeGraph("query_codex_security_graph", {
    evidence: packages.map((target, i) => ({
      relation: "depends_on",
      to: { kind: "package", ...target, id: `node_${i + 1}` },
      source: path,
      line: 1,
    })),
  });
  expect(
    queried.map(({ id, package: target }) => ({ id, package: target })),
  ).toEqual(identities);

  const reviewed: ReviewPacket["items"] = [];
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    review: async (prompt) => {
      reviewed.push(...reviewPacket(prompt).items);
      return reviewDecision(prompt, approved, null);
    },
  });
  const page = state.readStatus({ candidates: {} }).candidatePage!;
  expect(page.candidates).toMatchObject(identities);
  const items = traced.map((candidate) => ({
    id: candidate.package!.name,
    kind: "unresolved",
    candidateIds: [candidate.id],
    reason: "The manifest does not establish a deployed version.",
    evidence: [{ path, startLine: 1, endLine: 1, supports: [] }],
    observations: [],
  }));
  expect(await state.queue({ items })).toMatchObject({ queued: true });
  const report = { status: "unknown", uses: [], limitations: [] };
  expect(
    await state.submit({ ...report, reviewItemIds: [items[0]!.id] }),
  ).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(traced[1]!.id),
  });
  expect(
    (
      await state.submit({
        ...report,
        reviewItemIds: items.map(({ id }) => id),
      })
    ).accepted,
  ).toBe(true);
  expect(reviewed).toMatchObject(
    packages.map((target) => ({
      id: target.name,
      candidates: [{ path, line: 1, package: target }],
    })),
  );
});

test("compares the version with an independent reading of the same use's citations", async () => {
  await using repo = await scopedTemporaryDirectory("review-version-");
  const literal = "1:2.0-r2+vendor.3";
  await writeFile(
    join(repo.path, "worker.ts"),
    "record\nrelease " + literal + "\n",
  );
  const report = draft();
  const use = report.uses[0]!;
  use.version = literal + " (local backport)";
  let citedVersion: string | null = literal;
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      const packet = reviewPacket(prompt);
      const item = packet.items[0]!;
      expect(item.use).not.toHaveProperty("version");
      expect(packet.excerpts[item.excerptIds[0]!]!.text).toContain(literal);
      return reviewDecision(prompt, approved, citedVersion);
    },
  });
  expect((await submission.submit(report)).feedback).toContain(literal);
  use.version = null;
  expect((await submission.submit(report)).accepted).toBe(false);
  use.version = literal;
  citedVersion = null;
  expect((await submission.submit(report)).accepted).toBe(false);
  citedVersion = literal;
  // An unchanged rejected packet keeps its decision. Add the missing context.
  expect((await submission.submit(report)).accepted).toBe(false);
  use.evidence[0]!.startLine = 1;
  expect((await submission.submit(report)).accepted).toBe(true);
  expect(submission.acceptedReport().uses[0]!.version).toBe(literal);
});

test("each use needs its own deciding citation, even when both appear in the same report", async () => {
  await using repo = await scopedTemporaryDirectory("review-siblings-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "config\nfirst worker\nsecond worker\nshared receipt\n",
  );
  const assessment = draft();
  const first = assessment.uses[0]!;
  first.location = "one";
  const second = structuredClone(first);
  second.location = "two";
  second.evidence[0]!.startLine = second.evidence[0]!.endLine = 3;
  const receipt = { path: "worker.ts", startLine: 4, endLine: 4, supports: [] };
  second.evidence.push(receipt);
  second.observations.push({
    server: "inventory",
    record: "unit 2",
    supports: ["running"],
  });
  assessment.uses.push(second);
  const reviewedLocations: string[][] = [];
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      const packet = reviewPacket(prompt);
      reviewedLocations.push(packet.items.map((item) => item.use!.location));
      return JSON.stringify({
        items: packet.items.map((item) => {
          const text = item.excerptIds
            .map((id) => packet.excerpts[id]!.text)
            .join("\n");
          const inventory = JSON.stringify(
            item.receiptIds.map((id) => packet.receipts[id]),
          );
          expect(item.use).not.toHaveProperty("version");
          let decision = approved;
          if (item.use!.location === first.location) {
            expect(text).toContain("first worker");
            expect(text).not.toContain("second worker");
            expect(inventory).not.toContain("second unit inventory");
            decision = text.includes("shared receipt") ? approved : gap;
          } else {
            expect(text).not.toContain("first worker");
            expect(text).toContain("second worker");
            expect(text).toContain("shared receipt");
            expect(inventory).toContain("second unit inventory");
          }
          return {
            id: item.id,
            revision: item.revision,
            ...decision,
            citedVersion: "1.0",
            evidenceIds: [...item.excerptIds, ...item.receiptIds],
          };
        }),
      });
    },
  });
  submission.recordInventory("inventory", { text: "second unit inventory" });
  expect(await submission.submit(assessment)).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(gap.reason),
  });
  expect(reviewedLocations).toEqual([["one", "two"]]);
  first.evidence.push(receipt);
  expect((await submission.submit(assessment)).accepted).toBe(true);
  // Its unchanged sibling keeps approval while the corrected item is reviewed.
  expect(reviewedLocations).toEqual([["one", "two"], ["one"]]);
});

test("verifies the inventory claim against actual results from cited inventory servers", async () => {
  await using repo = await scopedTemporaryDirectory("review-inventory-");
  await writeFile(join(repo.path, "worker.ts"), "one\ntwo\n");
  const prompts: string[] = [];
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      prompts.push(prompt);
      return reviewDecision(prompt, approved);
    },
  });
  const report = draft();
  report.uses[0]!.observations.push({
    server: "inventory",
    record: "release-1",
    supports: ["running"],
  });
  expect((await submission.submit(report)).accepted).toBe(false);
  expect(prompts).toHaveLength(0);
  submission.recordInventory("inventory", {
    row: "release-1",
    runningRevision: "xyz",
  });
  submission.recordInventory("other", {
    diagnostic: "UNCITED_INVENTORY_RESULT",
  });
  expect((await submission.submit(report)).accepted).toBe(true);
  expect(prompts[0]).toContain('"runningRevision":"xyz"');
  expect(prompts[0]).not.toContain("UNCITED_INVENTORY_RESULT");
});

test("ten rejected submissions exhaust the budget and preserve the cached review", async () => {
  await using repo = await scopedTemporaryDirectory("review-budget-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "manifest\nversion unresolved\nno selected lockfile\n",
  );
  const report: DependencyAssessment = {
    status: "unknown",
    uses: [],
    limitations: ["Dependency version unavailable."],
  };
  const prompts: string[] = [];
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      prompts.push(prompt);
      return reviewDecision(
        prompt,
        { ...gap, reason: "Unresolved fact on draft 1" },
        null,
      );
    },
  });
  await queueScopeGap(submission, report.limitations[0]!);
  expect(() => submission.acceptedReport()).toThrow(
    "No verified dependency report was submitted",
  );
  for (let i = 1; i < 10; i++) {
    const reply = await submission.submit(report);
    expect(reply.accepted).toBe(false);
    expect(reply.feedback).toContain(`Attempts remaining: ${10 - i}`);
    expect(submission.continuationPrompt()).toContain(
      "Unresolved fact on draft 1",
    );
  }
  const message =
    /after 10 attempts: scope \(revision 1\): Unresolved fact on draft 1/;
  await expect(submission.submit(report)).rejects.toThrow(message);
  await expect(submission.submit(report)).rejects.toThrow(message);
  expect(() => submission.continuationPrompt()).toThrow(message);
  expect(prompts).toHaveLength(1);
  expect(() => submission.acceptedReport()).toThrow(message);
});

test("a turn without a submission costs one attempt and the final attempt can still succeed", async () => {
  await using repo = await scopedTemporaryDirectory("review-last-attempt-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "manifest\nversion unresolved\nno selected lockfile\n",
  );
  const report: DependencyAssessment = {
    status: "unknown",
    uses: [],
    limitations: ["Dependency version unavailable."],
  };
  let reviews = 0;
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      reviews++;
      return reviewDecision(prompt, reviews === 1 ? gap : approved, null);
    },
  });
  await queueScopeGap(submission, report.limitations[0]!);
  await submission.submit(report);
  expect(submission.continuationPrompt()).toContain("Attempts remaining: 9");
  for (let remaining = 8; remaining >= 1; remaining--) {
    const prompt = submission.continuationPrompt();
    expect(prompt).toContain(`Attempts remaining: ${remaining}`);
    expect(prompt).toContain(gap.reason);
  }
  await queueScopeGap(submission, report.limitations[0]!, 3);
  expect((await submission.submit(report)).accepted).toBe(true);
  expect(submission.continuationPrompt()).toBeUndefined();
  expect(submission.acceptedReport()).toEqual({
    ...report,
    limitations: [
      ...report.limitations,
      expect.stringContaining("worker.ts:2-3"),
    ],
  });
  expect(reviews).toBe(2);
});

test("a final turn missing its submission preserves the last evidence gap", async () => {
  await using repo = await scopedTemporaryDirectory("review-missing-final-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "manifest\nversion unresolved\nno selected lockfile\n",
  );
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => reviewDecision(prompt, gap, null),
  });
  await queueScopeGap(submission, "Dependency version unavailable.");
  await submission.submit({
    status: "unknown",
    uses: [],
    limitations: ["Dependency version unavailable."],
  });
  for (let i = 1; i < 10; i++) submission.continuationPrompt();
  expect(() => submission.continuationPrompt()).toThrow(
    /after 10 attempts: The turn ended without a final report submission.[\s\S]*No cited loop/,
  );
});

test("an incomplete, malformed or failed verifier never approves a report", async () => {
  await using repo = await scopedTemporaryDirectory("review-incomplete-");
  await writeFile(join(repo.path, "worker.ts"), "one\ntwo\n");
  const reviews = [
    async () => JSON.stringify({ items: [] }),
    async () =>
      JSON.stringify({
        items: [
          {
            id: "unrequested",
            revision: 1,
            citedVersion: "1.0",
            ...approved,
            evidenceIds: ["e1"],
          },
        ],
      }),
    async () => "not JSON",
    async () => {
      throw new Error("Verifier unavailable");
    },
  ];
  for (const review of reviews) {
    let calls = 0;
    const submission = createDependencyReportSubmission({
      repository: repo.path,
      advisory,
      review: async () => {
        calls++;
        return review();
      },
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      const reply = await submission.submit(draft());
      expect(reply.accepted).toBe(false);
      expect(reply.feedback).toContain("Review failed:");
      expect(() => submission.acceptedReport()).toThrow("Review failed:");
    }
    // Failed reviews remain retryable, but never create approval.
    expect(calls).toBe(2);
    await submission.close();
  }
});

test("returns an unsupported positive for correction before invoking the reviewer", async () => {
  await using repo = await scopedTemporaryDirectory("review-verdict-");
  await writeFile(join(repo.path, "worker.ts"), "one\ntwo\n");
  let calls = 0;
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      calls++;
      return reviewDecision(prompt, approved);
    },
  });
  const report = draft();
  report.status = "exploitable";
  const use = report.uses[0]!;
  use.verdict = report.status;
  use.evidence[0]!.supports = ["affected_copy", "affected_use"];
  const result = await submission.submit(report);
  expect(result.accepted).toBe(false);
  expect(result.feedback).toContain("affected revision running");
  expect(calls).toBe(0);
  report.status = "potentially_exploitable";
  use.verdict = report.status;
  use.reason =
    "The checked-out copy is affected; the running revision and access are unknown.";
  expect((await submission.submit(report)).accepted).toBe(true);
  expect(submission.acceptedReport()).toEqual(report);
  expect(calls).toBe(1);
});

test("accounts for the independent review turn even when it rejects a draft", async () => {
  const usage = {
    input_tokens: 14,
    cached_input_tokens: 3,
    cache_write_input_tokens: 0,
    output_tokens: 6,
    reasoning_output_tokens: 2,
  };
  const raw = JSON.stringify({
    items: [
      { id: "scope", revision: 1, ...gap, citedVersion: null, evidenceIds: [] },
    ],
  });
  const received: (typeof usage)[] = [];
  expect(
    await runReadOnlyCodex(
      "review the draft",
      {},
      {
        codex: {
          startThread: () => ({
            run: async () => ({ finalResponse: raw, usage }),
          }),
        },
        onUsage: (value) => received.push(value),
      },
      {
        surface: "cli",
        command: "exploitability check",
        threadSource: CODEX_SECURITY_THREAD_SOURCES.scan,
      },
    ),
  ).toBe(raw);
  expect(received).toEqual([usage]);
});
