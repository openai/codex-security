import { expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import type { DependencyUseProof } from "../src/dependency-report-proof.js";
import type { DependencyAssessment } from "../src/dependency-reachability.js";
import { reviewedDependencyCheckSchema } from "../src/dependency-reachability.js";
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
  callerScope?: string;
  items: {
    id: string;
    revision: number;
    kind: string;
    classification?: string;
    candidates?: { path: string; line?: number; testCandidate?: true }[];
    use?: {
      location: string;
      version?: unknown;
      proof?: DependencyUseProof;
    };
    excerptIds: string[];
    receiptIds: string[];
  }[];
  excerpts: Record<string, { text: string }>;
  receipts: Record<
    string,
    { result: unknown; origin: { tool?: string }; outcome?: string }
  >;
  inventoryServers?: Record<string, string[]>;
  catalogServerNames?: string[];
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

function finalize(
  submission: ReturnType<typeof createDependencyReportSubmission>,
  limitations: string[],
  ids: string[] = [],
) {
  const { candidateGeneration, items } = submission.readStatus();
  return submission.submit({
    reviewItems: ids.map((id) => {
      const selected = items.find((item) => item.id === id);
      if (!selected) throw new Error(`No queued assessment for ${id}`);
      return { id, revision: selected.revision };
    }),
    candidateGeneration,
    limitations,
  });
}

function queueUse(
  submission: ReturnType<typeof createDependencyReportSubmission>,
  use: DependencyAssessment["uses"][number],
  id = "worker",
) {
  return submission.queue({
    items: [{ id, kind: "use", candidateIds: [], use }],
  });
}

test("distinguishes default scope from an explicit deployment assumption", async () => {
  await using repo = await scopedTemporaryDirectory("review-caller-scope-");
  await writeFile(join(repo.path, "worker.ts"), "start\nchecked entry\n");
  const callerScope =
    "Assess the service and assume the worker is not deployed.";
  const use: DependencyAssessment["uses"][number] = {
    ...draft().uses[0]!,
    place: {
      kind: "job",
      environment: null,
      revision: null,
      artifact: null,
      observationWindow: null,
      deploymentBasis: "assumed_not_deployed",
      deploymentDetail: "assume the worker is not deployed",
      dependencySelection: null,
      patch: null,
      unresolvedQuestions: [],
    },
  };
  const run = async (callerScopeIsDefault?: true) => {
    const reviewed: unknown[] = [];
    const submission = createDependencyReportSubmission({
      repository: repo.path,
      advisory,
      callerScope,
      ...(callerScopeIsDefault && { callerScopeIsDefault }),
      review: async (prompt) => {
        reviewed.push(reviewPacket(prompt));
        return reviewDecision(prompt, approved);
      },
    });
    try {
      const acknowledgment = await queueUse(submission, use);
      if (!callerScopeIsDefault) {
        expect(await finalize(submission, [], ["worker"])).toMatchObject({
          accepted: true,
        });
        expect(submission.publicReport().assumptions).toEqual([callerScope]);
        expect(reviewed).toEqual([expect.objectContaining({ callerScope })]);
      } else {
        expect(reviewed).toEqual([]);
      }
      return acknowledgment;
    } finally {
      await submission.close();
    }
  };
  expect(await run(true)).toMatchObject({
    queued: false,
    feedback: expect.stringContaining("explicit"),
  });
  expect(await run()).toMatchObject({ queued: true });
});

test("requires a current generation and re-reviews changed source before finalizing", async () => {
  await using repo = await scopedTemporaryDirectory("review-changed-source-");
  const file = join(repo.path, "worker.ts");
  await writeFile(file, "start\nchecked entry\n");
  let reviews = 0;
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      reviews++;
      return reviewDecision(prompt, approved);
    },
  });
  try {
    const acknowledgment = await queueUse(submission, draft().uses[0]!);
    expect(acknowledgment).toEqual({
      queued: true,
      items: [{ id: "worker", revision: 1 }],
      feedback: expect.any(String),
    });
    expect(
      await submission.submit({
        reviewItems: [{ id: "worker", revision: 1 }],
        candidateGeneration: 1,
        limitations: [],
      }),
    ).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("candidate generation changed"),
    });
    await writeFile(file, "start\nupdated entry\n");
    expect(await finalize(submission, [], ["worker"])).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining(
        "Evidence changed for worker (revision 2)",
      ),
    });
    expect(await finalize(submission, [], ["worker"])).toMatchObject({
      accepted: true,
    });
    expect(
      submission.readStatus({ assessmentIds: ["worker"] }).assessmentItems?.[0]
        ?.revision,
    ).toBe(2);
    expect(reviews).toBeGreaterThan(0);
  } finally {
    await submission.close();
  }
});

test("findings queued during final review cannot disappear from the report", async () => {
  await using repo = await scopedTemporaryDirectory("review-late-use-");
  await writeFile(join(repo.path, "worker.ts"), "start\nchecked entry\n");
  const reviewing = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      reviewing.resolve();
      await release.promise;
      return reviewDecision(prompt, approved);
    },
  });
  try {
    const [use] = draft().uses;
    expect((await queueUse(submission, use!)).queued).toBe(true);
    const finalizing = finalize(submission, [], ["worker"]);
    await reviewing.promise;
    expect(
      (await queueUse(submission, { ...use!, location: "second" }, "second"))
        .queued,
    ).toBe(true);
    release.resolve();
    expect(await finalizing).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("changed during finalization"),
    });
    expect(await finalize(submission, [], ["worker", "second"])).toMatchObject({
      accepted: true,
    });
    expect(
      submission.acceptedReport().uses.map(({ location }) => location),
    ).toEqual(["worker", "second"]);
  } finally {
    release.resolve();
    await submission.close();
  }
});

test("starts queued review promptly, coalesces items and preserves reviewer concurrency without finalization", async () => {
  await using repo = await scopedTemporaryDirectory("review-dispatch-");
  await writeFile(join(repo.path, "worker.ts"), "const value = 1;\n");
  const release = Promise.withResolvers<void>();
  const batches: string[][] = [];
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      batches.push(reviewPacket(prompt).items.map(({ id }) => id));
      await release.promise;
      return reviewDecision(prompt, approved, null);
    },
  });
  const item = (id: string) => ({
    id,
    kind: "unresolved",
    candidateIds: [],
    reason: "The selected source does not establish the runtime choice.",
    evidence: [{ path: "worker.ts", startLine: 1, endLine: 1, supports: [] }],
    observations: [],
  });
  const dispatched = () =>
    new Promise<void>((resolve) => setImmediate(resolve));
  try {
    await submission.queue({ items: [item("first")] });
    await dispatched();
    expect(batches).toEqual([["first"]]);

    await submission.queue({ items: [item("second"), item("third")] });
    await dispatched();
    expect(batches).toEqual([["first"], ["second", "third"]]);

    await submission.queue({ items: [item("fourth")] });
    await dispatched();
    expect(batches).toHaveLength(2);

    release.resolve();
    await dispatched();
    expect(batches).toEqual([["first"], ["second", "third"], ["fourth"]]);
  } finally {
    release.resolve();
    await submission.close();
  }
});

test("keeps reviewed source exclusions in the final report", async () => {
  await using repo = await scopedTemporaryDirectory("reported-exclusion-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "export const output = 'png';\n",
  );
  const candidates = await createDependencyCandidates(repo.path);
  const [candidate] = await candidates.observeGraph("trace", {
    trace: [
      {
        relation: "candidate_call",
        evidence: [{ source: "worker.ts", lines: [1, 1] }],
      },
    ],
  });
  const exclusion = {
    kind: "dismissed" as const,
    reason: "The selected output operation does not use the affected format.",
    evidence: [{ path: "worker.ts", startLine: 1, endLine: 1, supports: [] }],
    observations: [],
  };
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    review: async (prompt) => reviewDecision(prompt, approved, null),
  });
  try {
    expect(
      await submission.queue({
        items: [
          { id: "output-scope", candidateIds: [candidate!.id], ...exclusion },
        ],
      }),
    ).toMatchObject({ queued: true });
    expect(
      await finalize(
        submission,
        ["The assessment covers the selected output operation."],
        ["output-scope"],
      ),
    ).toMatchObject({ accepted: true });
    expect(submission.acceptedReport()).toHaveProperty("coverage", [exclusion]);
    expect(submission.acceptedReport().uses).toEqual([]);
    expect(submission.acceptedReport().status).toBe("unknown");
  } finally {
    await submission.close();
  }
});

test("accounts for exact test-only candidates in one reviewed production-scope dismissal", async () => {
  await using repo = await scopedTemporaryDirectory("review-test-scope-");
  const testOne = "tests/test_one.py";
  const testTwo = "tests/test_two.py";
  const mixed = "tests/helper.py";
  await mkdir(join(repo.path, "tests"));
  for (const file of [testOne, testTwo, mixed])
    await writeFile(join(repo.path, file), "def run():\n    sink()\n");
  await writeFile(
    join(repo.path, "app.py"),
    "from tests.helper import run\nrun()\n",
  );
  await writeFile(
    join(repo.path, "BUILD"),
    'testonly_targets = ["tests/test_one.py", "tests/test_two.py"]\nselected_image_files = ["app.py", "tests/helper.py"]\n',
  );
  const candidates = await createDependencyCandidates(repo.path);
  const [one, two, helper] = await candidates.observeGraph("trace", {
    trace: [testOne, testTwo, mixed].map((source) => ({
      relation: "candidate_call",
      evidence: [{ source, lines: [2] }],
    })),
  });
  const [manifest] = await candidates.observeGraph("trace", {
    trace: [{ relation: "depends_on", evidence: [{ source: "BUILD" }] }],
  });
  const classification = "test_only_outside_scope";
  const callerScope =
    "Configured production image listed by selected_image_files in BUILD.";
  const grouped = {
    id: "test-fixtures",
    kind: "dismissed",
    classification,
    reason: `${callerScope} The selected production image includes app.py and tests/helper.py. The cited calls belong to test targets.`,
    candidateIds: [one!.id, two!.id],
    evidence: [testOne, testTwo, "BUILD"].map((path) => ({
      path,
      startLine: 1,
      endLine: 2,
      supports: [],
    })),
    observations: [],
  };
  const withoutScope = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    review: async () => {
      throw new Error("No out-of-scope review should be started.");
    },
  });
  try {
    expect(await withoutScope.queue({ items: [grouped] })).toMatchObject({
      queued: false,
      feedback: expect.stringContaining("explicit caller scope"),
    });
  } finally {
    await withoutScope.close();
  }
  let groupReviews = 0;
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    callerScope,
    review: async (prompt) => {
      expect(reviewPacket(prompt).callerScope).toBe(callerScope);
      return JSON.stringify({
        items: reviewPacket(prompt).items.map((item) => {
          if (item.classification === classification) {
            groupReviews++;
            expect(
              item.candidates?.every((candidate) => candidate.testCandidate),
            ).toBe(true);
            expect(item.candidates?.map((candidate) => candidate.path)).toEqual(
              [testOne, testTwo],
            );
            expect(
              item.excerptIds
                .map((id) => reviewPacket(prompt).excerpts[id]!.text)
                .join("\n"),
            ).toContain("selected_image_files");
          }
          return {
            id: item.id,
            revision: item.revision,
            ...approved,
            citedVersion: null,
            evidenceIds: item.excerptIds,
          };
        }),
      });
    },
  });
  try {
    expect(
      await submission.queue({
        items: [{ ...grouped, candidateIds: [manifest!.id] }],
      }),
    ).toMatchObject({
      queued: false,
      feedback: expect.stringContaining("source line"),
    });
    expect(
      await submission.queue({
        items: [
          {
            ...grouped,
            evidence: grouped.evidence.filter(({ path }) => path !== testTwo),
          },
        ],
      }),
    ).toMatchObject({
      queued: false,
      feedback: expect.stringContaining(testTwo),
    });
    await submission.queue({ items: [grouped] });
    expect(
      submission.readStatus({ candidates: {} }).candidatePage?.candidates,
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: helper!.id,
          path: mixed,
          testCandidate: true,
        }),
      ]),
    );
    const unresolved = {
      id: "mixed",
      kind: "unresolved",
      candidateIds: [helper!.id],
      reason:
        "The production launcher calls this helper; the selected dependency instance remains unknown.",
      evidence: [{ path: "app.py", startLine: 1, endLine: 2, supports: [] }],
      observations: [],
    };
    await submission.queue({
      items: [
        {
          ...unresolved,
          id: "build",
          candidateIds: [manifest!.id],
          reason: "Retain the manifest for ordinary dependency analysis.",
        },
        unresolved,
      ],
    });
    expect(
      await finalize(
        submission,
        ["The selected production image scope is explicit."],
        [grouped.id, "build", unresolved.id],
      ),
    ).toMatchObject({ accepted: true });
    expect(groupReviews).toBe(1);
    expect(submission.acceptedReport().coverage?.[0]).toMatchObject({
      classification,
      reason: grouped.reason,
      locations: [
        { candidateId: one!.id, path: testOne, line: 2 },
        { candidateId: two!.id, path: testTwo, line: 2 },
      ],
    });
    const renderedInput = reviewedDependencyCheckSchema.parse({
      ...submission.publicReport(),
      advisories: [],
      usage: null,
    });
    expect(renderedInput.coverage?.[0]).toEqual(
      submission.acceptedReport().coverage?.[0],
    );
    expect(submission.acceptedReport().status).toBe("unknown");
  } finally {
    await submission.close();
  }
});

test("a scoped reviewer can reject a test dismissal for an explicitly included CI caller", async () => {
  await using repo = await scopedTemporaryDirectory("review-ci-test-scope-");
  const path = "test_connector.py";
  await writeFile(join(repo.path, path), "def run_ci_probe():\n    sink()\n");
  const candidates = await createDependencyCandidates(repo.path);
  const [source] = await candidates.observeGraph("trace", {
    trace: [
      { relation: "candidate_call", evidence: [{ source: path, lines: [2] }] },
    ],
  });
  const callerScope =
    "Assess the deployment and its CI connector including test_connector.py.";
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    candidates,
    callerScope,
    review: async (prompt) => {
      const { items } = reviewPacket(prompt);
      expect(reviewPacket(prompt).callerScope).toBe(callerScope);
      expect(items[0]?.classification).toBe("test_only_outside_scope");
      return reviewDecision(
        prompt,
        {
          accepted: false,
          reason: "The supplied caller scope includes this CI connector.",
        },
        null,
      );
    },
  });
  try {
    const item = {
      id: "ci",
      kind: "dismissed",
      classification: "test_only_outside_scope",
      reason: "This is a test.",
      candidateIds: [source!.id],
      evidence: [{ path, startLine: 1, endLine: 2, supports: [] }],
      observations: [],
    };
    expect(await submission.queue({ items: [item] })).toMatchObject({
      queued: true,
    });
    expect(
      await finalize(
        submission,
        ["The requested caller scope includes CI."],
        [item.id],
      ),
    ).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("includes this CI connector"),
    });
  } finally {
    await submission.close();
  }
});

test.each(["dismissed", "use"] as const)(
  "passes the test-only scope rule to the reviewer for a generic %s",
  async (kind) => {
    await using repo = await scopedTemporaryDirectory(
      "review-generic-test-scope-",
    );
    const path = "test_image.py";
    await writeFile(
      join(repo.path, path),
      'def test_image():\n    image.save("out.png", format="PNG")\n',
    );
    const candidates = await createDependencyCandidates(repo.path);
    const [source] = await candidates.observeGraph("trace", {
      trace: [
        {
          relation: "candidate_call",
          evidence: [{ source: path, lines: [2] }],
        },
      ],
    });
    const evidence = [{ path, startLine: 2, endLine: 2, supports: [] }];
    const makeUse = (reason: string) => ({
      ...draft().uses[0]!,
      reason,
      evidence,
    });
    const testOnly =
      "The call is outside the investigation because the file is a test.";
    const ordinaryExclusion =
      "The selected PNG format does not invoke the TIFF writer.";
    const callerScope =
      "Assess this checkout including its CI jobs and test sources.";
    const state = createDependencyReportSubmission({
      repository: repo.path,
      advisory,
      candidates,
      callerScope,
      review: async (prompt) => {
        expect(prompt).toContain(
          "Reject an unclassified dismissal or a ruled_out use that relies on that claim.",
        );
        expect(prompt).toContain(
          "Independently proved operation, mode, copy or control exclusions still stand for test sources.",
        );
        const packet = reviewPacket(prompt);
        expect(packet.callerScope).toBe(callerScope);
        const [item] = packet.items;
        expect(item?.classification).toBeUndefined();
        expect(packet.excerpts[item!.excerptIds[0]!]!.text).toContain(
          'format="PNG"',
        );
        return item!.revision === 1
          ? reviewDecision(
              prompt,
              {
                accepted: false,
                reason: "Test status cannot exclude this requested scope.",
              },
              kind === "use" ? "1.0" : null,
            )
          : reviewDecision(prompt, approved);
      },
    });
    const identity = { id: "image", candidateIds: [source!.id] };
    const first =
      kind === "use"
        ? { ...identity, kind, use: makeUse(testOnly) }
        : { ...identity, kind, reason: testOnly, evidence, observations: [] };
    const submit = () =>
      finalize(
        state,
        ["The implicated test call is within requested scope."],
        [identity.id],
      );
    try {
      expect(await state.queue({ items: [first] })).toMatchObject({
        queued: true,
      });
      expect(await submit()).toMatchObject({
        accepted: false,
        feedback: expect.stringContaining("Test status cannot exclude"),
      });
      const use = makeUse(ordinaryExclusion);
      expect(
        await state.queue({ items: [{ ...identity, kind: "use", use }] }),
      ).toMatchObject({ queued: true });
      expect(await submit()).toMatchObject({ accepted: true });
    } finally {
      await state.close();
    }
  },
);

test("reviews structured sink and condition claims and preserves only the approved proof", async () => {
  await using repo = await scopedTemporaryDirectory("review-use-proof-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "import library;\nlibrary.decode(input, {mode: 'safe'});\n",
  );
  const report = draft();
  const use = report.uses[0]!;
  use.reason = "This call selects safe mode, excluding the affected operation.";
  use.proof = {
    sink: {
      function: "library.decode",
      callSite: { path: "worker.ts", line: 2 },
    },
    conditions: [
      {
        label: "Unsafe mode is selected",
        status: "ruled_out",
        explanation: "The caller explicitly selects safe mode.",
        citations: [{ path: "worker.ts", line: 2 }],
      },
    ],
  };
  let reviews = 0;
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      reviews++;
      expect(prompt).toContain("When use.proof is supplied, validate");
      const packet = reviewPacket(prompt);
      const item = packet.items[0]!;
      expect(item.use!.proof!.sink).toEqual(use.proof!.sink);
      expect(packet.excerpts[item.excerptIds[0]!]!.text).toContain(
        "mode: 'safe'",
      );
      return reviewDecision(
        prompt,
        item.use!.proof!.conditions[0]!.status === "ruled_out"
          ? approved
          : {
              accepted: false,
              reason:
                "worker.ts selects safe mode, contradicting the met condition.",
            },
      );
    },
  });
  const queue = (value: typeof use) =>
    submission.queue({
      items: [{ id: "decoder", kind: "use", candidateIds: [], use: value }],
    });
  const final = (revision: number) =>
    submission.submit({
      candidateGeneration: 0,
      limitations: report.limitations,
      reviewItems: [{ id: "decoder", revision }],
    });
  try {
    expect(await queue(use)).toMatchObject({ queued: true });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(submission.status().items[0]).toMatchObject({
      revision: 1,
      status: "accepted",
    });
    expect(reviews).toBe(1);

    const changed = structuredClone(use);
    changed.proof!.conditions[0]!.status = "met";
    changed.proof!.conditions[0]!.explanation =
      "The caller selects unsafe mode.";
    expect(await queue(changed)).toMatchObject({
      queued: true,
      items: [{ id: "decoder", revision: 2 }],
    });
    expect(await final(1)).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("changed from revision 1 to 2"),
    });
    expect(await final(2)).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("contradicting the met condition"),
    });
    expect(submission.status().items[0]).toMatchObject({
      revision: 2,
      status: "rejected",
    });
    expect(reviews).toBe(2);

    expect(await queue(use)).toMatchObject({ queued: true });
    expect(await final(3)).toMatchObject({ accepted: true });
    expect(reviews).toBe(2);
    expect(submission.acceptedReport().uses[0]!.proof).toEqual(use.proof);
  } finally {
    await submission.close();
  }
});

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
  expect((await finalize(state, report.limitations)).accepted).toBe(false);
  state.recordGraphEvent("item/started", graphItem("new", 1, 0));
  state.recordGraphEvent("item/completed", graphItem("new", 1, 0));
  expect((await finalize(state, report.limitations)).accepted).toBe(true);
  state.recordGraphEvent("item/completed", graphItem("new-work", 2, 1));
  expect(() => state.acceptedReport()).toThrow(
    "evidence changed after finalization",
  );
  expect(state.continuationPrompt()).toContain(
    "evidence changed after finalization",
  );
});

test("a sibling source finding reopens the report while duplicate note reads preserve acceptance", async () => {
  const state = createDependencyReportSubmission({
    advisory,
    repository: "/synthetic",
    review: async () => JSON.stringify({ items: [] }),
  });
  const report: DependencyAssessment = {
    status: "unknown",
    uses: [],
    limitations: ["Dependency copy unresolved."],
  };
  function sourceNotes(count: number) {
    const item = graphItem(`notes-${count}`, 1, 0);
    return {
      ...item,
      result: {
        structuredContent: {
          ...item.result.structuredContent,
          source_evidence_count: count,
        },
      },
    };
  }
  try {
    state.recordGraphEvent("item/completed", sourceNotes(0));
    expect((await finalize(state, report.limitations)).accepted).toBe(true);
    state.recordGraphEvent("item/completed", sourceNotes(1));
    expect(() => state.acceptedReport()).toThrow(
      "evidence changed after finalization",
    );
    expect((await finalize(state, report.limitations)).accepted).toBe(true);
    state.recordGraphEvent("item/completed", sourceNotes(1));
    expect(state.acceptedReport()).toEqual(report);
  } finally {
    await state.close();
  }
});

test.each(["native", "resource", "failed resource", "empty resource"])(
  "late unbound %s evidence reopens an accepted report",
  async (kind) => {
    const state = createDependencyReportSubmission({
      advisory,
      repository: "/synthetic",
      review: async () => JSON.stringify({ items: [] }),
    });
    const uri = "fixture://collections/sample-1";
    const parentReceiptId = state.recordInventory(
      "inventory",
      { structuredContent: { graph_evidence: { uri } } },
      { tool: "profiles.stacks", arguments: { service: "worker" } },
    );
    const report: DependencyAssessment = {
      status: "unknown",
      uses: [],
      limitations: ["Runtime evidence is incomplete."],
    };
    try {
      expect((await finalize(state, report.limitations)).accepted).toBe(true);
      if (kind === "native") {
        state.recordInventory(
          "inventory",
          { structuredContent: { samples: 1 } },
          { tool: "profiles.stacks", arguments: { service: "another-worker" } },
        );
      } else {
        state.recordInventory(
          "inventory",
          kind === "failed resource"
            ? { error: "Fixture resource read failed" }
            : {
                contents:
                  kind === "empty resource"
                    ? []
                    : [{ uri, text: JSON.stringify({ observations: [] }) }],
              },
          {
            tool: "mcpServer/resource/read",
            arguments: { uri },
            parentReceiptId,
            ...(kind === "failed resource"
              ? { outcome: "failed" as const }
              : kind === "empty resource"
                ? { outcome: "empty" as const }
                : {}),
          },
        );
      }
      expect(() => state.acceptedReport()).toThrow(
        "evidence changed after finalization",
      );
      expect(state.continuationPrompt()).toContain(
        "evidence changed after finalization",
      );
      expect((await finalize(state, report.limitations)).accepted).toBe(true);
      expect(state.acceptedReport()).toEqual(report);
    } finally {
      await state.close();
    }
  },
);

test("duplicate inventory preserves acceptance and new evidence preserves unchanged item approvals", async () => {
  await using repo = await scopedTemporaryDirectory(
    "review-inventory-generation-",
  );
  await writeFile(join(repo.path, "worker.ts"), "manifest\nchecked entry\n");
  let reviews = 0;
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      reviews++;
      return reviewDecision(prompt, approved);
    },
  });
  const original = { structuredContent: { samples: 1 } };
  const metadata = {
    tool: "profiles.stacks",
    arguments: { service: "worker" },
  };
  const receiptId = state.recordInventory("inventory", original, metadata);
  const report = draft();
  try {
    await queueUse(state, report.uses[0]!);
    expect(
      (await finalize(state, report.limitations, ["worker"])).accepted,
    ).toBe(true);
    expect(
      state.recordInventory("inventory", structuredClone(original), metadata),
    ).toBe(receiptId);
    expect(state.acceptedReport()).toEqual(report);
    expect(state.continuationPrompt()).toBeUndefined();
    state.recordInventory(
      "inventory",
      { structuredContent: { samples: 2 } },
      metadata,
    );
    expect(() => state.acceptedReport()).toThrow(
      "evidence changed after finalization",
    );
    expect(
      (await finalize(state, report.limitations, ["worker"])).accepted,
    ).toBe(true);
    expect(state.acceptedReport()).toEqual(report);
    expect(reviews).toBe(1);
  } finally {
    await state.close();
  }
});

test("inventory arriving during final review rejects the stale report without repeating unchanged review", async () => {
  await using repo = await scopedTemporaryDirectory(
    "review-inventory-arrival-",
  );
  await writeFile(join(repo.path, "worker.ts"), "manifest\nchecked entry\n");
  const reviewStarted = Promise.withResolvers<void>();
  const releaseReview = Promise.withResolvers<void>();
  let reviews = 0;
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    review: async (prompt) => {
      reviews++;
      reviewStarted.resolve();
      await releaseReview.promise;
      return reviewDecision(prompt, approved);
    },
  });
  try {
    const report = draft();
    await queueUse(state, report.uses[0]!);
    const finalizing = finalize(state, report.limitations, ["worker"]);
    await reviewStarted.promise;
    state.recordInventory(
      "inventory",
      { contents: [{ uri: "fixture://late", text: '{"observations":[]}' }] },
      { tool: "mcpServer/resource/read", arguments: { uri: "fixture://late" } },
    );
    releaseReview.resolve();
    expect(await finalizing).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining(
        "inventory, or selected assessments changed during finalization",
      ),
    });
    expect(() => state.acceptedReport()).toThrow("changed during finalization");
    expect(
      (await finalize(state, report.limitations, ["worker"])).accepted,
    ).toBe(true);
    expect(state.acceptedReport()).toEqual(report);
    expect(reviews).toBe(1);
  } finally {
    releaseReview.resolve();
    await state.close();
  }
});

test.each(["exclusion", "unknown use", "scope gap"])(
  "a catalog nonmapping preserves the reviewed %s verdict",
  async (kind) => {
    await using repo = await scopedTemporaryDirectory("review-nonmapping-");
    await writeFile(
      join(repo.path, "worker.ts"),
      "read(input);\ncheck(input);\n",
    );
    let reviews = 0;
    const state = createDependencyReportSubmission({
      advisory,
      repository: repo.path,
      callerScope: "The selected historical job and its recorded artifact.",
      review: async (prompt) => {
        reviews++;
        const packet = reviewPacket(prompt);
        expect(packet.callerScope).toBe(
          "The selected historical job and its recorded artifact.",
        );
        return JSON.stringify({
          items: packet.items.map((item) => ({
            id: item.id,
            revision: item.revision,
            ...approved,
            citedVersion: item.kind === "use" ? "1.0" : null,
            evidenceIds: [...item.excerptIds, ...item.receiptIds],
          })),
        });
      },
    });
    try {
      const item = graphItem("trace", 1, 0);
      state.recordGraphEvent("item/completed", {
        ...item,
        result: {
          structuredContent: {
            service_resolution: { revision: 1, pending: 0, unresolved: 1 },
          },
        },
      });
      const report = draft();
      if (kind === "unknown use") {
        report.status = report.uses[0]!.verdict = "unknown";
        report.uses[0]!.reason =
          "The selected artifact's patch state is unknown.";
      } else if (kind === "scope gap") {
        report.status = "unknown";
        report.uses = [];
        await queueScopeGap(state, "A selected caller handoff is unverified.");
      }
      if (report.uses.length) await queueUse(state, report.uses[0]!);
      expect(
        await finalize(state, report.limitations, [
          kind === "scope gap" ? "scope" : "worker",
        ]),
      ).toMatchObject({ accepted: true });
      expect(reviews).toBeGreaterThan(0);
      expect(state.acceptedReport()).toMatchObject({
        status: kind === "exclusion" ? "ruled_out" : "unknown",
        uses: report.uses,
        limitations: [
          expect.stringContaining("1 service lookup remains unresolved"),
          ...(kind === "scope gap" ? [expect.any(String)] : []),
        ],
      });
    } finally {
      await state.close();
    }
  },
);

test("uncompleted service work can only yield a reviewed, explicitly partial assessment", async () => {
  await using repo = await scopedTemporaryDirectory("review-partial-");
  await writeFile(join(repo.path, "worker.ts"), "one\ntwo\n");
  for (const [pending, truncated, failed] of [
    [0, true, false],
    [2, true, false],
    [2, false, false],
    [0, false, true],
  ] as const) {
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
    state.recordGraphEvent("item/completed", {
      ...graphItem("trace", 1, pending, truncated),
      ...(failed ? { status: "failed" } : {}),
    });
    const report = draft();
    await queueUse(state, report.uses[0]!);
    if (pending || failed) {
      for (let i = 0; i < 9; i++)
        expect(
          (await finalize(state, report.limitations, ["worker"])).accepted,
        ).toBe(false);
    }
    expect(
      (await finalize(state, report.limitations, ["worker"])).accepted,
    ).toBe(true);
    expect(reviews).toBe(1);
    const partial = state.acceptedReport();
    expect(partial.status).toBe("unknown");
    if (truncated)
      expect(partial.limitations.join(" ")).toContain(
        "graph reached its limit",
      );
    if (pending)
      expect(partial.limitations.join(" ")).toContain(
        "2 pending service lookups",
      );
    if (failed)
      expect(partial.limitations.join(" ")).toContain(
        "graph did not return current service resolution coverage",
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
  await queueUse(submission, original.uses[0]!);
  const rejection = await finalize(submission, original.limitations, [
    "worker",
  ]);
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
  await queueUse(submission, corrected.uses[0]!);
  expect(
    (await finalize(submission, corrected.limitations, ["worker"])).accepted,
  ).toBe(true);
  expect(packets[1]).toContain("check(entry);");
  expect(packets[1]).not.toContain(gap.reason);
  expect(submission.acceptedReport()).toEqual(corrected);
  expect(
    (await finalize(submission, original.limitations, ["worker"])).accepted,
  ).toBe(false);
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
  const final = () => finalize(state, report.limitations, [item.id]);
  await candidates.observeGraph("trace_codex_security_code", {
    textMatches: [{ source: "worker.ts", text: "check", lines: [2] }],
  });
  expect(
    await state.queue({ items: [{ ...item, candidateIds: [] }] }),
  ).toMatchObject({
    queued: true,
  });
  expect((await final()).accepted).toBe(true);

  const [call] = await candidates.observeGraph("query_codex_security_graph", {
    paths: [{ relation: "candidate_call", source: "worker.ts", line: 2 }],
  });
  expect(await final()).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(call!.id),
  });
  expect(
    await state.queue({ items: [{ ...item, candidateIds: [call!.id] }] }),
  ).toMatchObject({ queued: true });
  expect((await final()).accepted).toBe(true);
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
  expect(await finalize(state, [], [items[0]!.id])).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(traced[1]!.id),
  });
  expect(
    (
      await finalize(
        state,
        [],
        items.map(({ id }) => id),
      )
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
  const submit = async () => {
    await queueUse(submission, use);
    return finalize(submission, report.limitations, ["worker"]);
  };
  expect((await submit()).feedback).toContain(literal);
  use.version = null;
  expect((await submit()).accepted).toBe(false);
  use.version = literal;
  citedVersion = null;
  expect((await submit()).accepted).toBe(false);
  citedVersion = literal;
  // An unchanged rejected packet keeps its decision. Add the missing context.
  expect((await submit()).accepted).toBe(false);
  use.evidence[0]!.startLine = 1;
  expect((await submit()).accepted).toBe(true);
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
  await submission.queue({
    items: [first, second].map((use) => ({
      id: use.location,
      kind: "use",
      candidateIds: [],
      use,
    })),
  });
  expect(
    await finalize(submission, assessment.limitations, ["one", "two"]),
  ).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(gap.reason),
  });
  expect(reviewedLocations).toEqual([["one", "two"]]);
  first.evidence.push(receipt);
  await queueUse(submission, first, "one");
  expect(
    (await finalize(submission, assessment.limitations, ["one", "two"]))
      .accepted,
  ).toBe(true);
  // Its unchanged sibling keeps approval while the corrected item is reviewed.
  expect(reviewedLocations).toEqual([["one", "two"], ["one"]]);
});

test("reads the exact shared item for an in-place citation repair", async () => {
  await using repo = await scopedTemporaryDirectory("review-citation-repair-");
  const path = "worker.ts";
  await writeFile(
    join(repo.path, path),
    "route\nwrapper\nsibling\nversion 1.0\npatched body\n",
  );
  const candidates = await createDependencyCandidates(repo.path);
  const [route, wrapper, sibling] = await candidates.observeGraph("trace", {
    paths: [1, 2, 3].map((line) => ({
      relation: "candidate_call",
      source: path,
      line,
    })),
  });
  const first = draft().uses[0]!;
  const other = draft().uses[0]!;
  other.location = "sibling";
  other.evidence = [{ path, startLine: 3, endLine: 5, supports: [] }];
  const routeIds = [route!.id, wrapper!.id];
  const callerScope = "Inspect the configured route and its selected decoder.";
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    callerScope,
    candidates,
    review: async (prompt) => {
      const packet = reviewPacket(prompt);
      expect(packet.callerScope).toBe(callerScope);
      return JSON.stringify({
        items: packet.items.map((item) => {
          const hasPatch = item.excerptIds.some((id) =>
            packet.excerpts[id]!.text.includes("patched body"),
          );
          return {
            id: item.id,
            revision: item.revision,
            ...(hasPatch
              ? approved
              : {
                  accepted: false,
                  reason:
                    "The selected use needs its own installed version and patch evidence.",
                }),
            citedVersion: "1.0",
            evidenceIds: item.excerptIds,
          };
        }),
      });
    },
  });
  const item = {
    id: "route",
    kind: "use" as const,
    candidateIds: routeIds,
    use: first,
  };
  expect(await state.queue({ items: [item] })).toMatchObject({
    queued: true,
  });
  expect(
    await state.queue({
      items: [
        { id: "sibling", kind: "use", candidateIds: [sibling!.id], use: other },
      ],
    }),
  ).toMatchObject({ queued: true });
  const id = "route";
  expect(await finalize(state, [], ["sibling", id])).toMatchObject({
    accepted: false,
    feedback: expect.stringContaining(
      "needs its own installed version and patch evidence",
    ),
  });
  expect(state.readStatus()).not.toHaveProperty("assessmentItems");
  expect(state.readStatus({ assessmentIds: [id] }).assessmentItems).toEqual([
    {
      revision: 1,
      item: { ...item, id },
    },
  ]);
  expect(() => state.readStatus({ assessmentIds: ["missing"] })).toThrow(
    "Unknown assessment ID",
  );
  const target = state.readStatus({ assessmentIds: [id] }).assessmentItems![0]!
    .item;
  if (target.kind !== "use") throw new Error("Expected a use");
  target.use.evidence.push({
    path,
    startLine: 4,
    endLine: 5,
    supports: ["affected_copy"],
  });
  expect(
    state.readStatus({ assessmentIds: [id] }).assessmentItems![0]!.item,
  ).toEqual({ ...item, id });
  expect(await state.queue({ items: [target] })).toMatchObject({
    queued: true,
  });
  expect(await finalize(state, [], ["sibling", id])).toMatchObject({
    accepted: true,
  });
  expect(state.acceptedReport().uses).toEqual([other, target.use]);
  const compact = state.readStatus();
  expect(compact.items.map((entry) => entry.id)).toEqual([id, "sibling"]);
  expect(compact).not.toHaveProperty("assessmentPage");
  const page = state.readStatus({ assessments: { limit: 1 } }).assessmentPage!;
  expect(page).toEqual({
    items: [
      {
        id,
        revision: 2,
        kind: "use",
        status: "accepted",
        location: first.location,
        component: first.component,
        version: first.version,
        verdict: first.verdict,
        deployment: first.deployment,
      },
    ],
    nextAfter: id,
  });
  expect(
    state.readStatus({ assessments: { after: page.nextAfter! } })
      .assessmentPage,
  ).toMatchObject({
    items: [{ id: "sibling" }],
    nextAfter: null,
  });
  expect(state.readStatus({ assessments: {} }).assessmentPage).toMatchObject({
    items: [{ id }, { id: "sibling" }],
    nextAfter: null,
  });
  expect(() => state.readStatus({ assessments: { after: "missing" } })).toThrow(
    "Unknown or out-of-scope assessment cursor",
  );
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
  expect((await queueUse(submission, report.uses[0]!)).queued).toBe(false);
  expect(prompts).toHaveLength(0);
  submission.recordInventory("inventory", {
    row: "release-1",
    runningRevision: "xyz",
  });
  submission.recordInventory("other", {
    diagnostic: "UNCITED_INVENTORY_RESULT",
  });
  await queueUse(submission, report.uses[0]!);
  expect(
    (await finalize(submission, report.limitations, ["worker"])).accepted,
  ).toBe(true);
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
    const reply = await finalize(submission, report.limitations, ["scope"]);
    expect(reply.accepted).toBe(false);
    expect(reply.feedback).toContain(`Attempts remaining: ${10 - i}`);
    expect(submission.continuationPrompt()).toContain(
      "Unresolved fact on draft 1",
    );
  }
  const message =
    /after 10 attempts: scope \(revision 1\): Unresolved fact on draft 1/;
  await expect(
    finalize(submission, report.limitations, ["scope"]),
  ).rejects.toThrow(message);
  await expect(
    finalize(submission, report.limitations, ["scope"]),
  ).rejects.toThrow(message);
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
  await finalize(submission, report.limitations, ["scope"]);
  expect(submission.continuationPrompt()).toContain("Attempts remaining: 9");
  for (let remaining = 8; remaining >= 1; remaining--) {
    const prompt = submission.continuationPrompt();
    expect(prompt).toContain(`Attempts remaining: ${remaining}`);
    expect(prompt).toContain(gap.reason);
  }
  await queueScopeGap(submission, report.limitations[0]!, 3);
  expect(
    (await finalize(submission, report.limitations, ["scope"])).accepted,
  ).toBe(true);
  expect(submission.continuationPrompt()).toBeUndefined();
  expect(submission.acceptedReport()).toEqual({
    ...report,
    coverage: [
      {
        kind: "unresolved",
        reason: report.limitations[0]!,
        evidence: [
          { path: "worker.ts", startLine: 2, endLine: 3, supports: [] },
        ],
        observations: [],
      },
    ],
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
  await finalize(submission, ["Dependency version unavailable."], ["scope"]);
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
      await queueUse(submission, draft().uses[0]!);
      const reply = await finalize(submission, [], ["worker"]);
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
  const result = await queueUse(submission, use);
  expect(result.queued).toBe(false);
  expect(result.feedback).toContain("affected revision running");
  expect(calls).toBe(0);
  report.status = "potentially_exploitable";
  use.verdict = report.status;
  use.reason =
    "The checked-out copy is affected; the running revision and access are unknown.";
  await queueUse(submission, use);
  expect(
    (await finalize(submission, report.limitations, ["worker"])).accepted,
  ).toBe(true);
  expect(submission.acceptedReport()).toEqual(report);
  expect(calls).toBe(1);
});

test("reviews a release recipe with the bound source and provenance receipts", async () => {
  await using repo = await scopedTemporaryDirectory("review-release-recipe-");
  await writeFile(
    join(repo.path, "worker.ts"),
    'import { read } from "library";\nread(input);\n',
  );
  await writeFile(
    join(repo.path, "release.build"),
    'image("worker", "worker.ts")\nlink("worker", "library", "1.0", "fix.diff")\n',
  );
  await writeFile(join(repo.path, "fix.diff"), "+check(input);\n");
  const imageDigest = `sha256:${"1".repeat(64)}`;
  const running = { imageDigest, platform: "linux/amd64" };
  const provenance = { ...running, sourceRevision: "a".repeat(40) };
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    inventoryServers: { inventory: ["running_image", "provenance"] },
    review: async (prompt) => {
      expect(prompt).toContain(
        "A release recipe can also establish the packaged copy",
      );
      const packet = reviewPacket(prompt);
      const item = packet.items[0]!;
      expect(item.receiptIds.map((id) => packet.receipts[id]?.result)).toEqual(
        expect.arrayContaining([running, provenance]),
      );
      expect(item.excerptIds.map((id) => packet.excerpts[id]?.text)).toEqual(
        expect.arrayContaining([
          expect.stringContaining(
            'link("worker", "library", "1.0", "fix.diff")',
          ),
          "+check(input);",
        ]),
      );
      return reviewDecision(prompt, approved);
    },
  });
  try {
    const runtimeReceipt = submission.recordInventory("inventory", running, {
      tool: "running_image",
    });
    const provenanceReceipt = submission.recordInventory(
      "inventory",
      provenance,
      { tool: "provenance" },
    );
    const report = draft();
    const use = report.uses[0]!;
    use.deployment = "confirmed";
    use.reason = "The running image's release recipe links the fixed library.";
    use.evidence.push(
      {
        path: "release.build",
        startLine: 1,
        endLine: 2,
        supports: ["affected_copy"],
      },
      {
        path: "fix.diff",
        startLine: 1,
        endLine: 1,
        supports: ["affected_copy"],
      },
    );
    use.observations = [
      {
        server: "inventory",
        record: "running image and its verified release source",
        supports: ["running", "affected_copy"],
      },
    ];
    expect(
      await submission.queue({
        items: [
          {
            id: "worker",
            kind: "use",
            use,
            candidateIds: [],
            receiptIds: [runtimeReceipt, provenanceReceipt],
          },
        ],
      }),
    ).toMatchObject({ queued: true });
    expect(
      await finalize(submission, report.limitations, ["worker"]),
    ).toMatchObject({ accepted: true });
    expect(submission.acceptedReport()).toEqual(report);
  } finally {
    await submission.close();
  }
});

test("requires the reviewer to cite the receipt that identifies the affected deployed copy", async () => {
  await using repo = await scopedTemporaryDirectory("review-shipped-copy-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "import library\nlibrary.read(input)\n",
  );
  for (const citeBuild of [false, true]) {
    const submission = createDependencyReportSubmission({
      repository: repo.path,
      advisory,
      inventoryServers: {
        builds: ["running_build"],
        access: ["caller_access"],
      },
      review: async (prompt) => {
        const packet = reviewPacket(prompt);
        const decision = JSON.parse(reviewDecision(prompt, approved));
        if (!citeBuild)
          decision.items[0].evidenceIds = decision.items[0].evidenceIds.filter(
            (id: string) =>
              packet.receipts[id]?.origin.tool !== "running_build",
          );
        return JSON.stringify(decision);
      },
    });
    try {
      const build = submission.recordInventory(
        "builds",
        {
          service: "worker",
          revision: "rev1",
          package: "library",
          version: "1.0",
          patches: [],
        },
        { tool: "running_build", arguments: { service: "worker" } },
      );
      const access = submission.recordInventory(
        "access",
        {
          service: "worker",
          revision: "rev1",
          caller: "fixture-client",
          allowed: true,
        },
        { tool: "caller_access", arguments: { service: "worker" } },
      );
      const report = draft();
      const use = report.uses[0]!;
      report.status = use.verdict = "exploitable";
      use.deployment = "confirmed";
      use.reason =
        "The fixture caller reaches worker rev1, which shipped library 1.0 without patches.";
      use.evidence[0]!.supports = ["affected_use"];
      use.observations = [
        {
          server: "builds",
          record: "worker rev1 build",
          supports: ["affected_copy", "running"],
        },
        {
          server: "access",
          record: "fixture-client access to worker rev1",
          supports: ["access"],
        },
      ];
      expect(
        await submission.queue({
          items: [
            {
              id: "worker",
              kind: "use",
              candidateIds: [],
              use,
              receiptIds: [build, access],
            },
          ],
        }),
      ).toMatchObject({ queued: true });
      const result = await finalize(submission, report.limitations, ["worker"]);
      expect(result.accepted).toBe(citeBuild);
      if (citeBuild) expect(submission.acceptedReport()).toEqual(report);
      else
        expect(result.feedback).toContain(
          "cite a successful inventory receipt from builds",
        );
    } finally {
      await submission.close();
    }
  }
});

test("a runtime-only provider does not force a receipt for a source-backed use without a native target", async () => {
  await using repo = await scopedTemporaryDirectory("review-runtime-only-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "import library\nlibrary.read(input)\n",
  );
  const inventoryServers = { artifacts: ["read_artifact"] };
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    inventoryServers,
    catalogServerNames: [],
    review: async (prompt) => {
      expect(reviewPacket(prompt)).toMatchObject({
        inventoryServers,
        catalogServerNames: [],
        receipts: {},
      });
      return reviewDecision(prompt, approved);
    },
  });
  try {
    const report = draft();
    const use = report.uses[0]!;
    report.status = use.verdict = "potentially_exploitable";
    use.evidence[0]!.supports = ["affected_copy", "affected_use"];
    use.reason =
      "Source selects the affected copy. There is no observed artifact ID to check.";
    const item = { id: "worker", kind: "use", candidateIds: [], use };
    expect(await submission.queue({ items: [item] })).toMatchObject({
      queued: true,
    });
    expect(
      await finalize(submission, report.limitations, ["worker"]),
    ).toMatchObject({ accepted: true });
  } finally {
    await submission.close();
  }
});

test("requires inventory lookups for each potentially exploitable use when a catalog is configured", async () => {
  await using repo = await scopedTemporaryDirectory("review-runtime-attempt-");
  await writeFile(join(repo.path, "worker.ts"), "one\ntwo\n");
  const inventoryServers = {
    inventory: ["find_service", "running_build", "caller_access"],
  };
  const submission = createDependencyReportSubmission({
    repository: repo.path,
    advisory,
    inventoryServers,
    catalogServerNames: ["inventory"],
    review: async (prompt) => {
      const packet = reviewPacket(prompt);
      expect(packet.inventoryServers).toEqual(inventoryServers);
      expect(packet.catalogServerNames).toEqual(["inventory"]);
      const receipts = Object.values(packet.receipts);
      if (receipts.every((receipt) => receipt.origin.tool === "find_service")) {
        return reviewDecision(prompt, {
          accepted: false,
          reason: "Check the running build and caller access for worker.",
        });
      }
      expect(receipts).toContainEqual(
        expect.objectContaining({
          outcome: "failed",
          origin: { tool: "running_build", arguments: { service: "worker" } },
        }),
      );
      return reviewDecision(prompt, approved);
    },
  });
  try {
    const report = draft();
    const use = report.uses[0]!;
    report.status = use.verdict = "potentially_exploitable";
    use.evidence[0]!.supports = ["affected_copy", "affected_use"];
    use.reason = "The deployed build and caller access are unresolved.";
    const item = { id: "worker", kind: "use", candidateIds: [], use };
    expect(await submission.queue({ items: [item] })).toMatchObject({
      queued: false,
      feedback: expect.stringContaining("Use the configured inventory tools"),
    });
    expect(
      submission.recordInventory(
        "other",
        { build: "a" },
        { tool: "running_build" },
      ),
    ).toBeUndefined();

    const identity = submission.recordInventory(
      "inventory",
      { name: "worker" },
      { tool: "find_service" },
    );
    use.observations = [
      { server: "inventory", record: "worker catalog entry", supports: [] },
    ];
    expect(
      await submission.queue({ items: [{ ...item, receiptIds: [identity] }] }),
    ).toMatchObject({ queued: true });
    expect(
      await finalize(submission, report.limitations, ["worker"]),
    ).toMatchObject({
      accepted: false,
      feedback: expect.stringContaining("caller access for worker"),
    });

    const lookup = submission.recordInventory(
      "inventory",
      { error: "build lookup timed out" },
      {
        tool: "running_build",
        arguments: { service: "worker" },
        outcome: "failed",
      },
    );
    expect(
      submission.readStatus({ inventoryReceipts: true }).inventoryReceipts,
    ).toContainEqual(
      expect.objectContaining({ id: lookup, outcome: "failed" }),
    );
    use.reason =
      "The running build lookup for worker timed out. Without a deployment to scope caller access to, access remains unresolved.";
    use.observations = [
      {
        server: "inventory",
        record: "worker running_build timed out",
        supports: ["running"],
      },
    ];
    use.deployment = "confirmed";
    expect(
      await submission.queue({ items: [{ ...item, receiptIds: [lookup] }] }),
    ).toMatchObject({
      queued: false,
      feedback: expect.stringContaining("require a successful result"),
    });

    use.observations[0]!.supports = [];
    use.deployment = "unknown";
    expect(
      await submission.queue({ items: [{ ...item, receiptIds: [lookup] }] }),
    ).toMatchObject({ queued: true });
    expect(
      await finalize(submission, report.limitations, ["worker"]),
    ).toMatchObject({ accepted: true });
    expect(submission.acceptedReport().status).toBe("potentially_exploitable");
    submission.recordInventoryStartup(
      "inventory",
      "failed",
      "connection failed",
    );
    const unavailable = submission
      .readStatus({ inventoryReceipts: true })
      .inventoryReceipts?.find((receipt) => receipt.outcome === "unavailable");
    expect(unavailable).toBeDefined();
    submission.recordInventoryStartup("inventory", "ready", null);
    expect(
      submission.readStatus({ inventoryReceipts: true }).inventoryReceipts,
    ).not.toContainEqual(unavailable);
  } finally {
    await submission.close();
  }
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
