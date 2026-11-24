import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DependencyAttemptStore,
  dependencyRecordHash,
} from "../src/dependency-attempt-store";
import {
  createPremiseQueue,
  currentApproval,
  premiseKey,
  type PremiseRef,
} from "../src/dependency-review-queue";
import { evidencePreviews } from "../src/dependency-investigation-session";
import { affectedByFrozenVersion } from "../src/dependency-advisory-version";
import { dependencyCheckOutputSchema } from "../src/dependency-reachability";
import { withDependencyCheckOutput } from "../src/dependency-check-output";
import {
  approveDependencyClaims,
  reviewScopes,
  reference,
  reportedUse,
  verifyProposedUse,
  type Claim,
  type Proposal,
} from "../src/dependency-reviewed-claims";
import {
  DependencyInvestigationBlockedError,
  runReviewedDependencyCheck,
} from "../src/dependency-reviewed-check";
import {
  createDependencyEvidenceCapture,
  investigationServer,
  type DependencyEvidenceRecord,
} from "../src/dependency-evidence-sources";
import {
  discoverDependencyRepository,
  type RepositoryDiscovery,
} from "../src/dependency-discovery";

type ReviewClaim = PremiseRef & { availableEvidenceKeys: string[] };

function approvedReview(claims: ReviewClaim[]) {
  return JSON.stringify({
    decisions: claims.map((claim) => ({
      ...reference(claim),
      approved: true,
      reason: "Verified.",
      evidenceKeys: claim.availableEvidenceKeys,
    })),
  });
}

const signal = new AbortController().signal;
async function fixture(extraFiles: Record<string, string> = {}) {
  const path = await mkdtemp(join(tmpdir(), "dependency-reviewed-test-"));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", path, ...args], { encoding: "utf8" }).trim();
  await writeFile(
    join(path, "app.js"),
    'import parse from "fixture-parser";\nparse(request.body);\n',
  );
  await writeFile(join(path, "package-lock.json"), '{"version":"1.0.0"}\n');
  await writeFile(
    join(path, "secondary.js"),
    'import parse from "fixture-parser";\nparse(other.body);\n',
  );
  for (const [name, contents] of Object.entries(extraFiles))
    await writeFile(join(path, name), contents);
  git("init", "-q");
  git("add", ".");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-q",
    "-m",
    "fixture",
  );
  const revision = git("rev-parse", "HEAD");
  const pkg = { ecosystem: "npm", name: "fixture-parser" };
  const discovery: RepositoryDiscovery = {
    revision,
    package: pkg,
    manifests: [],
    callers: [{ path: "app.js", line: 2 }],
    buildFiles: [],
    dependencyFiles: ["package-lock.json"],
    traces: [],
    runtime: [],
    coverage: {
      status: "partial",
      gaps: ["The running deployment is unknown."],
    },
  };
  const use: Proposal["uses"][number] = {
    scope: "1.1",
    location: "example",
    verdict: "potentially_exploitable",
    version: "1.0.0",
    reason: "A caller passes the submitted body to the affected parser.",
    evidence: [
      {
        path: "app.js",
        startLine: 1,
        endLine: 2,
        supports: ["affected_use", "attacker_control"],
      },
      {
        path: "package-lock.json",
        startLine: 1,
        endLine: 1,
        supports: ["affected_copy"],
      },
    ],
    observations: [],
    proof: {
      sink: { function: "parse", callSite: { path: "app.js", line: 2 } },
      conditions: [
        {
          label: "Input reaches the parser",
          status: "met",
          explanation: "The request body is passed directly to parse.",
          citations: [{ path: "app.js", line: 2 }],
        },
      ],
    },
    remainingQuestions: ["Which revision is running?"],
  };
  return {
    path,
    pkg,
    revision,
    discovery,
    use,
    packageOptions: { directory: path, subject: "npm:fixture-parser", signal },
    [Symbol.asyncDispose]: () => rm(path, { recursive: true, force: true }),
  };
}

test("binds each argument frame to its reviewed source and pins the published revision", async () => {
  await using f = await fixture();
  const scope = reviewScopes([f.discovery])[0]!;
  f.use.trace = [
    {
      kind: "source",
      label: "Request body",
      site: { path: "secondary.js", line: 2 },
      argument: "request.body",
    },
  ];
  f.use.proof.sink!.argument = "request.body";
  await expect(
    verifyProposedUse(f.path, scope, f.use, signal, true),
  ).rejects.toThrow(/trace/u);
  f.use.trace[0] = {
    kind: "source",
    label: "Request body",
    site: { path: "app.js", line: 2 },
    argument: "request.body",
  };
  const verified = await verifyProposedUse(f.path, scope, f.use, signal, true);
  const key = dependencyRecordHash(
    verified.evidence.find((s) => s.path === "app.js")!,
  );
  expect(verified.findingEvidence).toContainEqual({
    field: "trace[0].site",
    keys: [key],
  });
  const claim = {
    id: "use-1",
    revision: 1,
    hash: "a".repeat(64),
    value: { kind: "use" as const, use: verified },
  };
  const published = reportedUse(verified, claim, [key]);
  expect(published.trace?.[0]).toMatchObject({
    site: { commit: f.revision },
    argument: "request.body",
  });
  expect(published.proof.sink?.callSite.commit).toBe(f.revision);
});

test("repository investigators share pinned source notes without promoting assertions to reviewed claims", async () => {
  const captured = 'export const selectedMode = "archive";';
  await using f = await fixture({ "modes.js": captured + "\n" });
  execFileSync(
    "git",
    ["remote", "add", "origin", "git@example.invalid:team/parser.git"],
    { cwd: f.path },
  );
  const tool = "update_codex_security_graph";
  const graph = "query_codex_security_graph";
  const assertion = {
    question: "Which mode is configured?",
    scope: "parser",
    claim: "The checkout selects an archive mode.",
  };
  const range = { path: "modes.js", startLine: 1, endLine: 1 };
  const input = { ...assertion, evidence: [range] };
  let noteId = "";
  let reviewerRead = false;
  const result = await runReviewedDependencyCheck(
    { ...f.packageOptions, vulnDescription: "Parser issue" },
    {
      discover: async ({ revision }) => {
        expect(revision).toBe(f.revision);
        execFileSync(
          "git",
          [
            "-c",
            "user.name=Example",
            "-c",
            "user.email=example@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-qm",
            "Advance checkout",
          ],
          { cwd: f.path },
        );
        return f.discovery;
      },
      async runAgent(req) {
        const tools = await req.investigationTools!();
        if (!req.coordinator) {
          const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
          expect(tools.definitions.some((d) => d.name === tool)).toBe(false);
          await expect(tools.call(tool, { note: input })).rejects.toThrow();
          expect(
            await tools.call(graph, { note: { id: noteId } }),
          ).toMatchObject({
            note: {
              id: noteId,
              investigator_assertion: assertion,
              excerpts: [{ ...range, commit: f.revision, text: captured }],
            },
          });
          reviewerRead = true;
          return approvedReview(packet.claims);
        }
        const other = await req.investigationTools!();
        const query = (note: unknown) => other.call(graph, { note });
        await writeFile(
          join(f.path, "modes.js"),
          "export const selectedMode = null;\n",
        );
        const written = (await tools.call(tool, { note: input })) as {
          note: { id: string };
        };
        noteId = written.note.id;
        expect(await other.call(tool, { note: input })).toEqual(written);
        for (const bad of [
          { ...range, commit: "0".repeat(40) },
          { ...range, path: "../outside.js" },
        ]) {
          await expect(
            tools.call(tool, {
              note: { ...input, claim: "Unverified.", evidence: [range, bad] },
            }),
          ).rejects.toThrow();
        }
        const listing = { notes: [{ id: noteId, ...assertion }] };
        expect(await query({})).toMatchObject(listing);
        expect(await query({ search: "selectedMode" })).toMatchObject(listing);
        expect(await query({ id: noteId, search: "missing" })).toEqual({
          note: null,
        });
        expect(await other.call("query_dependency_claims", {})).toEqual([]);
        await expect(
          other.call("submit_dependency_assessments", {
            assessments: [
              {
                id: "unsupported",
                expectedRevision: 0,
                use: {
                  ...f.use,
                  premises: [
                    {
                      id: noteId,
                      revision: 1,
                      hash: noteId.slice("source-evidence-".length),
                    },
                  ],
                },
              },
            ],
          }),
        ).rejects.toThrow("currently approved premise");
        return JSON.stringify({ uses: [f.use], limitations: [] });
      },
    },
  );
  if (!("checks" in result)) throw Error("Expected a package check.");
  expect(result.target).toEqual({ repository: "team/parser", sha: f.revision });
  expect(reviewerRead).toBe(true);
  expect(result.checks[0]!.claims.map((c) => c.id).sort()).toEqual([
    "coverage",
    "use-1",
  ]);
});

for (const late of ["assessment", "candidate", "roster"] as const) {
  test(`rechecks coverage when a new ${late} arrives during final review`, async () => {
    await using f = await fixture({
      "package.json":
        '{"name":"example","dependencies":{"fixture-parser":"1.0.0"}}\n',
    });
    let arrive: () => Promise<void>;
    let coverageReviews = 0;
    const checked = await runReviewedDependencyCheck(
      {
        ...f.packageOptions,
        vulnDescription: "Check calls to the parser.",
        evidenceSources: [
          { server: "catalog", instructions: "Check deployed callers." },
        ],
      },
      {
        discover: async () => ({
          ...f.discovery,
          callers: f.discovery.callers.map((c) => ({
            ...c,
            manifest: "package.json",
          })),
          manifests:
            late === "candidate"
              ? [
                  {
                    path: "package.json",
                    name: "example",
                    project: ".",
                    requested: "1.0.0",
                    line: 1,
                  },
                ]
              : [],
        }),
        async runAgent(req) {
          const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
          if (req.coordinator) {
            const { call } = await req.investigationTools!();
            arrive = async () => {
              if (late === "assessment") {
                await call("submit_dependency_assessments", {
                  assessments: [
                    { id: "late-use", expectedRevision: 0, use: f.use },
                  ],
                });
              } else if (late === "roster") {
                await call("update_codex_security_graph", {
                  sourceWork: {
                    operation: "append_roster_page",
                    id: "remaining-imports",
                    owner: "search",
                    paths: ["secondary.js"],
                    declaredComplete: true,
                    search: "References to the parser",
                    sourceRefs: ["import-search"],
                    gaps: [],
                  },
                });
              } else {
                const record = {
                  server: investigationServer,
                  tool: "query_codex_security_graph",
                  arguments: {},
                  result: {
                    structuredContent: {
                      paths: [
                        {
                          relation: "candidate_call",
                          source: "secondary.js",
                          line: 2,
                        },
                      ],
                    },
                  },
                };
                req.onEvidence!({
                  ...record,
                  sha256: dependencyRecordHash(record),
                });
              }
            };
            const answer = JSON.stringify({
              uses: late === "candidate" ? [f.use] : [],
              limitations: [],
            });
            const correction = await req.onCoordinatorAnswer!(answer);
            expect(JSON.parse(correction!).feedback.reason).toContain(
              "changed during final review",
            );
            expect(await req.onCoordinatorAnswer!(answer)).toBeUndefined();
            return answer;
          }
          if (
            packet.claims.some((c: Claim) => c.id === "coverage") &&
            ++coverageReviews === 1
          )
            await arrive();
          return approvedReview(packet.claims);
        },
      },
    );
    if (!("checks" in checked)) throw Error("Expected package report");
    const report = checked.checks[0]!;
    expect(coverageReviews).toBe(2);
    if (late === "assessment")
      expect(report.uses.map((u) => u.conclusionClaim.id)).toEqual([
        "assessment:late-use",
      ]);
    else if (late === "roster")
      expect(
        report.limitations.some(
          (reason) =>
            reason.includes("remaining-imports") &&
            reason.includes("unassigned"),
        ),
      ).toBe(true);
    else
      expect(
        report.coverage?.some(
          (c) =>
            c.kind === "unresolved" &&
            c.evidence.some((ref) => ref.path === "secondary.js"),
        ),
      ).toBe(true);
  });
}

test.each(["incomplete", "complete"] as const)(
  "source-work partitions share checkpoints and report %s coverage",
  async (completion) => {
    await using f = await fixture();
    const paths = ["app.js", "package-lock.json", "secondary.js"];
    const tool = "update_codex_security_graph";
    let reviewedLimitations: string[] = [];
    const result = await runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Parser issue" },
      {
        discover: async () => f.discovery,
        async runAgent(req) {
          const { call, definitions } = await req.investigationTools!();
          if (!req.coordinator) {
            const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
            for (const claim of packet.claims) {
              if (claim.payload.kind !== "coverage") continue;
              reviewedLimitations = claim.payload.limitations;
              expect(definitions.some((d) => d.name === tool)).toBe(false);
              expect(
                await call("query_codex_security_graph", { sourceWork: {} }),
              ).toMatchObject({
                source_work: {
                  remainingFileCount: completion === "complete" ? 0 : 1,
                },
              });
            }
            return approvedReview(packet.claims);
          }
          const other = await req.investigationTools!();
          const record = (sourceWork: unknown) => call(tool, { sourceWork });
          const query = (sourceWork: unknown) =>
            other.call("query_codex_security_graph", { sourceWork });
          const roster = {
            operation: "append_roster_page",
            id: "imports",
            owner: "search",
            search: "Parser references",
            sourceRefs: ["checkout-search"],
          };
          await record({
            ...roster,
            paths,
            declaredComplete: false,
            gaps: [
              {
                id: "late-page",
                description: "Remaining import search timed out.",
              },
            ],
          });
          const view = {
            rosterId: "imports",
            page: { view: "unassigned", limit: 2 },
          };
          const first = (await query(view)) as {
            source_work: { page: { items: string[]; nextCursor: unknown } };
          };
          expect(first.source_work.page.items).toEqual(paths.slice(0, 2));
          const next = {
            ...view,
            page: { ...view.page, cursor: first.source_work.page.nextCursor },
          };
          expect(await query(next)).toMatchObject({
            source_work: { page: { items: paths.slice(2), nextCursor: null } },
          });
          await record({
            operation: "assign_partition",
            id: "first",
            owner: "reader",
            rosterId: "imports",
            paths: paths.slice(0, 2),
          });
          await expect(query(next)).rejects.toThrow(
            "changed since this cursor",
          );
          await record({
            operation: "record_examined",
            partitionId: "first",
            paths: [paths[0]],
          });
          expect(
            await query({
              partitionId: "first",
              page: { view: "remaining", limit: 10 },
            }),
          ).toMatchObject({
            source_work: {
              owner: "reader",
              page: { items: [paths[1]] },
            },
          });
          if (completion === "complete") {
            await record({
              ...roster,
              expectedRevision: 1,
              declaredComplete: true,
              paths: [],
              gaps: [],
              resolutions: [{ id: "late-page", sourceRef: "retried-search" }],
            });
            await record({
              operation: "assign_partition",
              id: "last",
              rosterId: "imports",
              owner: "search",
              paths: [paths[2]],
            });
            for (const [partitionId, path] of [
              ["first", paths[1]],
              ["last", paths[2]],
            ])
              await other.call(tool, {
                sourceWork: {
                  operation: "record_examined",
                  partitionId,
                  paths: [path],
                },
              });
          }
          return JSON.stringify({ uses: [f.use], limitations: [] });
        },
      },
    );
    if (!("checks" in result)) throw Error("Expected package report.");
    const report = result.checks[0]!;
    expect(report.uses[0]!.verdict).toBe(f.use.verdict);
    expect(report.limitations).toEqual(reviewedLimitations);
    if (completion === "complete") expect(reviewedLimitations).toEqual([]);
    else {
      const limitation = reviewedLimitations.find((line) =>
        line.includes('roster "imports"'),
      )!;
      expect(limitation).toContain("Remaining import search timed out.");
      expect(limitation).toContain('unassigned files ["secondary.js"]');
      expect(limitation).toContain(
        'partition "first" has unexamined files ["package-lock.json"]',
      );
      expect(limitation).toContain("checkout-search");
    }
  },
);

test("package checks freeze each advisory independently and verify exact source and review references", async () => {
  await using f = await fixture();
  const events: {
    type: string;
    subject?: string;
    fields?: Record<string, unknown>;
  }[] = [];
  const result = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      onProgress(type, subject, fields) {
        events.push({ type, subject, fields });
      },
    },
    {
      discover: async () => f.discovery,
      lookupPackage: async () =>
        ["CVE-2099-0001", "CVE-2099-0002"].map((id) => ({
          id,
          advisories: [],
        })),
      runAgent: async (req) => {
        expect(req.readOnly).toBe(true);
        const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        if (!input.claims)
          return JSON.stringify({ uses: [f.use], limitations: [] });
        expect(input.claims[0].payload.use.evidence[0].excerpt).toContain(
          "parse(request.body)",
        );
        expect(input.claims[0].payload.use.evidence[0].commit).toBe(f.revision);
        return approvedReview(input.claims);
      },
    },
  );
  if (!("checks" in result)) throw new Error("Missing package checks");
  expect(result.checks.map((c) => c.advisoryId)).toEqual([
    "CVE-2099-0001",
    "CVE-2099-0002",
  ]);
  const [use] = result.checks[0]!.uses;
  expect(use?.location).toBe("example");
  expect(use?.verdict).toBe("potentially_exploitable");
  const claim = result.checks[0]!.claims.find(
    (c) => c.id === use?.conclusionClaim.id,
  )!;
  expect(use?.conclusionClaim.hash).toBe(claim.hash);
  expect(claim.state).toBe("approved");
  expect(
    events
      .filter((event) =>
        ["advisory", "discovery", "investigation", "review"].includes(
          event.type,
        ),
      )
      .map((e) => e.type),
  ).toEqual([
    "advisory",
    "discovery",
    "investigation",
    "review",
    "discovery",
    "investigation",
    "review",
  ]);
  expect(events.find((e) => e.type === "advisories_loaded")?.fields).toEqual({
    count: 2,
  });
  expect(
    events
      .filter((e) => e.type === "activity_started")
      .map((e) => e.fields?.["id"]),
  ).toEqual([1, 2]);
  expect(
    events.filter((e) => e.type === "activity_finished").map((e) => e.fields),
  ).toEqual(
    [1, 2].map((id) => ({
      id,
      activity: "source_search",
      scope: { symbol: "fixture-parser" },
      outcome: "partial",
    })),
  );
  for (const advisoryId of ["CVE-2099-0001", "CVE-2099-0002"]) {
    const details = (type: string) =>
      events.find((e) => e.subject === advisoryId && e.type === type)?.fields;
    expect(details("proposed_sink")).toEqual({
      function: "parse",
      origin: "discovered",
      path: "app.js",
      line: 2,
    });
    expect(details("reviewed")).toMatchObject({
      location: "app.js:2",
      locationKind: "sink",
      verdict: "potentially_exploitable",
      component: "fixture-parser",
      version: "1.0.0",
    });
    expect(details("assessment_finished")).toEqual({ uses: 1 });
  }
});

test("caller descriptions stay scoped and a source-only positive is blocked", async () => {
  await using f = await fixture();
  await expect(
    runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Incorrect length validation." },
      {
        lookupPackage: async () => {
          throw Error("Unexpected registry lookup");
        },
        discover: async () => f.discovery,
        runAgent: async ({ prompt }) => {
          expect(prompt).toContain("Incorrect length validation.");
          return JSON.stringify({
            uses: [
              { ...f.use, verdict: "exploitable", remainingQuestions: [] },
            ],
            limitations: [],
          });
        },
      },
    ),
  ).rejects.toThrow("running workload");
  await expect(
    runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Incorrect length validation." },
      {
        discover: async () => f.discovery,
        runAgent: async () => {
          throw Error("Model unavailable");
        },
      },
    ),
  ).rejects.toBeInstanceOf(DependencyInvestigationBlockedError);
});

test("a positive use requires an endpoint on each explicitly bounded side", async () => {
  await using f = await fixture();
  for (const boundary of [{ sources: [] }, { sinks: [] }]) {
    await expect(
      runReviewedDependencyCheck(
        {
          ...f.packageOptions,
          vulnDescription: "Incorrect length validation.",
          ...boundary,
        },
        {
          discover: async () => f.discovery,
          runAgent: async () =>
            JSON.stringify({ uses: [f.use], limitations: [] }),
        },
      ),
    ).rejects.toThrow("explicitly empty source or sink boundary");
  }
});

test("an exploratory scope explanation retains reviewed uses, open handoffs and observed callers", async () => {
  await using f = await fixture({
    "package.json": JSON.stringify({
      name: "example",
      dependencies: { "fixture-parser": "1.0.0" },
    }),
    "secondary.js":
      'import adapt from "fixture-adapter";\nadapt(other.body);\n',
  });
  const adapter = { ecosystem: "npm", name: "fixture-adapter" };
  const cve = "CVE-2099-0001";
  const affected = [f.pkg, adapter].map((pkg) => ({
    package: pkg,
    versions: ["1.0.0"],
  }));
  const advisory = {
    id: cve,
    url: "https://example.invalid/advisories/fixture",
    affected,
  };
  const observedCaller = { path: "secondary.js", line: 2 };
  const explanation = {
    scope: "2.1",
    reason: "No adapter manifest or selected version was found.",
  };
  const handoff = "Determine which adapter implementation this caller selects.";
  const result = dependencyCheckOutputSchema.parse(
    await runReviewedDependencyCheck(
      { directory: f.path, subject: cve, signal },
      {
        lookupCve: async () => ({
          cve,
          advisories: [{ ...advisory, sha256: dependencyRecordHash(advisory) }],
        }),
        discover: async ({ package: pkg }) =>
          pkg.name === adapter.name
            ? {
                ...f.discovery,
                package: adapter,
                callers: [observedCaller],
                dependencyFiles: [],
              }
            : {
                ...f.discovery,
                manifests: [
                  {
                    project: ".",
                    name: "example",
                    requested: "1.0.0",
                    path: "package.json",
                    line: 1,
                  },
                ],
                callers: [
                  { ...f.discovery.callers[0]!, manifest: "package.json" },
                ],
              },
        async runAgent(req) {
          const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
          if (!req.coordinator) {
            return approvedReview(packet.claims);
          }
          const submit = (outOfScope: { scope: string; reason: string }[]) =>
            req.onCoordinatorAnswer!(
              JSON.stringify({ uses: [], limitations: [], outOfScope }),
            );
          const feedback = async (
            scope: (typeof explanation)[],
            reason: string,
          ) =>
            expect(
              JSON.parse((await submit(scope))!).feedback.reason,
            ).toContain(reason);
          // A search explanation cannot account for the discovered parser manifest.
          await feedback(
            [explanation],
            "omitted a discovered dependency scope",
          );
          const { call } = await req.investigationTools!();
          await call("submit_dependency_assessments", {
            assessments: [
              { id: "parser", expectedRevision: 0, use: f.use },
              {
                id: "adapter",
                expectedRevision: 0,
                disposition: {
                  kind: "unresolved",
                  scope: explanation.scope,
                  reason: handoff,
                  locations: [],
                  evidence: [
                    {
                      path: observedCaller.path,
                      startLine: 1,
                      endLine: 2,
                      supports: ["context"],
                    },
                  ],
                  observations: [],
                },
              },
            ],
          });
          await feedback(
            [{ ...explanation, scope: "3.1" }],
            "Unknown dependency scope",
          );
          await feedback(
            [explanation, explanation],
            "Duplicate scope explanation",
          );
          await feedback(
            [{ ...explanation, scope: f.use.scope }],
            "assessed dependency scope",
          );
          expect(await submit([explanation])).toBeUndefined();
          return JSON.stringify({
            uses: [],
            limitations: [],
            outOfScope: [explanation],
          });
        },
      },
    ),
  );
  if (!("cve" in result)) throw Error("Expected a CVE report.");
  expect(result.target?.sha).toBe(f.revision);
  expect(result.uses).toMatchObject([
    { conclusionClaim: { id: "assessment:parser", revision: 1 } },
  ]);
  expect(
    result.limitations.some(
      (text) =>
        text.includes(adapter.name) && text.includes(explanation.reason),
    ),
  ).toBe(true);
  expect(result.coverage?.filter((row) => row.kind === "dismissed")).toEqual(
    [],
  );
  expect(result.coverage).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        kind: "unresolved",
        reason: handoff,
        conclusionClaim: expect.objectContaining({ id: "disposition:adapter" }),
      }),
      expect.objectContaining({
        kind: "unresolved",
        reason: expect.stringContaining("secondary.js:2"),
        evidence: [
          expect.objectContaining({
            path: observedCaller.path,
            startLine: 2,
            endLine: 2,
            commit: f.revision,
          }),
        ],
      }),
    ]),
  );
  expect(
    result.coverage?.some((row) => row.reason === explanation.reason),
  ).toBe(false);
});

test("independent approvals cannot be carried to a newer revision", async () => {
  await using f = await fixture();
  const store = new DependencyAttemptStore(join(f.path, "attempt.sqlite"));
  try {
    const first: Claim = store.recordClaim("coverage", {
      kind: "coverage",
      limitations: ["Original scope"],
    });
    store.recordClaim(
      "coverage",
      { kind: "coverage", limitations: ["Changed scope"] },
      first.revision,
    );
    expect(() =>
      approveDependencyClaims(
        store,
        [first],
        [
          {
            ...reference(first),
            evidenceKeys: [],
            approved: true,
            reason: "Original coverage only.",
          },
        ],
      ),
    ).toThrow("current claim revisions");
    expect(store.get("dependency-review", first.id)).toBeUndefined();
  } finally {
    store.close();
  }
});

test("replacing an approved premise invalidates transitive users and preserves independent siblings", async () => {
  const store = new DependencyAttemptStore(":memory:");
  const evidence = "a".repeat(64);
  const queue = createPremiseQueue({
    store,
    signal,
    directory: ".",
    revision: "fixture",
    records: new Map(),
    review: async () => {},
  });
  function submit(
    id: string,
    dependencies: PremiseRef[],
    receiptIds: string[],
    expectedRevision = 0,
  ) {
    return store.recordClaim<Claim["value"]>(
      "premise:" + id,
      {
        kind: "premise",
        scope: "fixture",
        statement: "Evidence for " + id + " at " + expectedRevision,
        sources: [],
        dependencies,
        receiptIds,
      },
      expectedRevision,
    );
  }
  function approve(c: Claim, evidenceKeys: string[]) {
    approveDependencyClaims(
      store,
      [c],
      [
        {
          ...reference(c),
          approved: true,
          reason: "Verified.",
          evidenceKeys,
        },
      ],
    );
  }
  try {
    const base = submit("binding", [], [evidence]);
    expect(() => approve(base, ["foreign-receipt"])).toThrow(
      "select the deciding evidence",
    );
    approve(base, [evidence]);

    const parent = submit("caller", [reference(base)], []);
    approve(parent, [premiseKey(base)]);
    const leaf = submit("service", [reference(parent)], []);
    approve(leaf, [premiseKey(parent)]);
    const sibling = submit("other-service", [], [evidence]);
    approve(sibling, [evidence]);
    expect(currentApproval(store, leaf)?.approved).toBe(true);
    const corrected = submit("binding", [], [evidence], base.revision);
    approve(corrected, [evidence]);
    expect(currentApproval(store, leaf)).toBeUndefined();
    expect(await queue.query({ ids: [parent.id, leaf.id] })).toMatchObject([
      { state: "stale" },
      { state: "stale" },
    ]);
    expect(currentApproval(store, sibling)?.approved).toBe(true);
    const rejected = submit("missing", [], [evidence]);
    expect(() =>
      approveDependencyClaims(
        store,
        [sibling, rejected],
        [sibling, rejected].map((c) => ({
          ...reference(c),
          approved: c.id === sibling.id,
          reason: "Check the scoped evidence.",
          evidenceKeys: [evidence],
        })),
      ),
    ).toThrow("Independent review rejected");
    expect(currentApproval(store, sibling)?.approved).toBe(true);
    expect(currentApproval(store, rejected)).toBeUndefined();
  } finally {
    store.close();
  }
});

test("publish a complete report once and keep progress separate from an unsuccessful report", async () => {
  await using f = await fixture();
  const reportFile = join(f.path, "report.json"),
    progressEvents = join(f.path, "progress.jsonl");
  const options = { reportFile, subject: "example", signal, warn: () => {} };
  const results = await Promise.allSettled(
    [1, 2].map((i) =>
      withDependencyCheckOutput(options, async () => ({ attempt: i })),
    ),
  );
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  const original = await readFile(reportFile, "utf8");
  expect([1, 2]).toContain(JSON.parse(original).attempt);
  await expect(
    withDependencyCheckOutput(options, async () => {
      throw Error("Should not run");
    }),
  ).rejects.toThrow("already exists");
  expect(await readFile(reportFile, "utf8")).toBe(original);
  const failed = join(f.path, "failed.json");
  await expect(
    withDependencyCheckOutput(
      { ...options, reportFile: failed, progressEvents },
      async (emit) => {
        emit("review");
        throw Error("unavailable");
      },
    ),
  ).rejects.toThrow("unavailable");
  expect(
    (await readFile(progressEvents, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line).type),
  ).toEqual(["started", "review", "stage", "failed", "finished"]);
  await expect(readFile(failed)).rejects.toMatchObject({ code: "ENOENT" });
});

test("host feedback repairs a bad citation and an independent rejection requires approval of a new revision", async () => {
  await using f = await fixture();
  let investigations = 0,
    reviews = 0;
  const report = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Untrusted input reaches the parser.",
    },
    {
      discover: async () => f.discovery,
      runAgent: async ({ prompt }) => {
        const input = JSON.parse(prompt.split("\n\n").at(-1)!);
        if (input.claims) {
          reviews++;
          return JSON.stringify({
            decisions: input.claims.map((claim: ReviewClaim) => ({
              evidenceKeys: claim.availableEvidenceKeys,
              ...reference(claim),
              approved: reviews > 1 || claim.id === "coverage",
              reason:
                reviews === 1
                  ? "Explain the observed data flow more precisely."
                  : "Checked the revised citation.",
            })),
          });
        }
        investigations++;
        const use = structuredClone(f.use);
        if (investigations === 1) use.proof.sink!.callSite.line = 3;
        if (investigations === 2)
          expect(input.feedback.reason).toContain("outside the citations");
        if (investigations === 3) {
          expect(input.feedback.reason).toContain(
            "Independent review rejected",
          );
          use.reason =
            "The handler passes request.body directly to parse on line 2.";
        }
        return JSON.stringify({ uses: [use], limitations: [] });
      },
    },
  );
  if (!("checks" in report)) throw new Error("Missing reviewed package report");
  expect(report.checks[0]!.uses[0]!.conclusionClaim.revision).toBe(2);
  expect([investigations, reviews]).toEqual([3, 2]);
});

test.each(["corrected", "exhausted"] as const)(
  "the same coordinator can correct an invalid final submission (%s)",
  async (mode) => {
    await using f = await fixture();
    let coordinatorStarts = 0;
    let submissions = 0;
    const result = runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Parser input" },
      {
        discover: async () => f.discovery,
        async runAgent(req) {
          if (!req.coordinator) {
            const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
            return approvedReview(input.claims);
          }
          coordinatorStarts++;
          // A persistent transport requests only the correction for its next turn.
          for (;;) {
            submissions++;
            const use = structuredClone(f.use);
            if (mode === "exhausted" || submissions < 4)
              use.proof.sink!.callSite.line = 3;
            const answer = JSON.stringify({ uses: [use], limitations: [] });
            const next = await req.onCoordinatorAnswer!(answer);
            if (next === undefined) return answer;
            const correction = JSON.parse(next);
            expect(Object.keys(correction)).toEqual(["feedback"]);
            expect(correction.feedback.reason).toContain(
              "outside the citations",
            );
            expect(correction.feedback).not.toHaveProperty("previousProposal");
            if (submissions >= 10)
              throw Error("An eleventh submission was requested");
          }
        },
      },
    );
    if (mode === "corrected") {
      const report = await result;
      if (!("checks" in report)) throw Error("Expected package report");
      expect(report.checks[0]!.uses[0]!.verdict).toBe(
        "potentially_exploitable",
      );
      expect(submissions).toBe(4);
    } else {
      await expect(result).rejects.toThrow("outside the citations");
      expect(submissions).toBe(10);
    }
    expect(coordinatorStarts).toBe(1);
  },
);

test("aliases of the same output cannot leave progress at the report destination", async () => {
  await using f = await fixture();
  const target = join(f.path, "actual"),
    alias = join(f.path, "alias");
  await mkdir(target);
  await symlink(
    target,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  const reportFile = join(target, "report.json");
  await expect(
    withDependencyCheckOutput(
      {
        subject: "sample",
        reportFile,
        progressEvents: join(alias, "report.json"),
        signal,
        warn: () => {},
      },
      async () => ({}),
    ),
  ).rejects.toThrow("different paths");
  await expect(readFile(reportFile)).rejects.toMatchObject({ code: "ENOENT" });
});

test("bind discovered owners to their own source and retain uncovered callers", async () => {
  await using f = await fixture();
  const initialGap =
    "The build or manifest that owns the caller in app.js is unresolved.";
  f.discovery.coverage.gaps = [initialGap];
  f.discovery.manifests = [
    {
      path: "package-lock.json",
      project: "notes",
      name: "notes",
      requested: "1.0.0",
      line: 1,
    },
  ];
  f.discovery.callers.push({
    path: "secondary.js",
    line: 2,
    manifest: "package-lock.json",
    project: "notes",
  });
  const report = await runReviewedDependencyCheck(
    { ...f.packageOptions, vulnDescription: "Parser failure." },
    {
      discover: async () => f.discovery,
      runAgent: async ({ prompt }) => {
        const input = JSON.parse(prompt.split("\n\n").at(-1)!);
        if (!input.claims)
          return JSON.stringify({
            uses: [{ ...f.use, location: "unrelated service" }],
            limitations: ["External ingress remains unknown."],
          });
        expect(input.discoveries[0].coverage.gaps).toContain(initialGap);
        const limitations = input.claims.find((c: Claim) => c.id === "coverage")
          .payload.limitations;
        expect(limitations).not.toContain(initialGap);
        expect(limitations).toContain(
          "Unassessed caller in notes: secondary.js:2.",
        );
        return approvedReview(input.claims);
      },
    },
  );
  if (!("checks" in report)) throw new Error("Missing package check");
  const check = report.checks[0]!;
  expect(check.searches[0]!.details).toContain(initialGap);
  expect(check.limitations).toContain("External ingress remains unknown.");
  expect(check.uses[0]!.location).toBe("notes");
  expect(check.coverage[0]).toMatchObject({
    kind: "unresolved",
    location: "notes",
    evidence: [{ path: "secondary.js", startLine: 2 }],
  });
});

function returnedEvidence(
  tool: string,
  text: string,
): DependencyEvidenceRecord {
  const record = {
    server: "deployments",
    tool,
    arguments: { selector: "only in request" },
    result: { content: [{ type: "text", text }] },
  };
  return { ...record, sha256: dependencyRecordHash(record) };
}

function deploymentFor(
  f: Awaited<ReturnType<typeof fixture>>,
  service: string,
) {
  const running = `Deployed ${service} at ${f.revision} with fixture-parser@1.0.0.`;
  const access = `An unauthenticated caller reached ${service} using its public route.`;
  const records = [
    returnedEvidence("running", running),
    returnedEvidence("access", access),
  ];
  const positive: Proposal["uses"][number] = {
    ...f.use,
    verdict: "exploitable",
    remainingQuestions: [],
    observations: [
      {
        server: "deployments",
        tool: "running",
        supports: ["running"],
        quote: running,
        reason: "The selected revision and copy are running.",
      },
      {
        server: "deployments",
        tool: "access",
        supports: ["access"],
        quote: access,
        reason: "The caller reached this service.",
      },
    ],
  };
  return { records, positive };
}

test("the reviewer corrects an omitted direct access citation without repeating the investigation", async () => {
  await using f = await fixture();
  const { records, positive } = deploymentFor(f, "example");
  const original = records[0]!;
  const structured = {
    server: original.server,
    tool: original.tool,
    arguments: original.arguments,
    result: {
      structured_content: {
        release: { message: positive.observations[0]!.quote },
      },
    },
  };
  records[0] = { ...structured, sha256: dependencyRecordHash(structured) };
  let reviews = 0;
  const result = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "A parser issue.",
      evidenceSources: [
        {
          server: "deployments",
          instructions: "Look up release details and external caller access.",
        },
      ],
    },
    {
      discover: async () => f.discovery,
      runAgent: async ({ prompt, onEvidence }) => {
        const input = JSON.parse(prompt.split("\n\n").at(-1)!);
        if (input.claims) {
          expect(onEvidence).toBeUndefined();
          expect(input.evidence).toEqual(records);
          expect(input.claims[0].payload.use.findingEvidence).toEqual([
            { field: "running build", keys: [records[0]!.sha256] },
            { field: "caller access", keys: [records[1]!.sha256] },
          ]);
          if (++reviews === 1) {
            const reply = JSON.parse(approvedReview(input.claims));
            reply.decisions[0].evidenceKeys = [records[0]!.sha256];
            return JSON.stringify(reply);
          }
          expect(input.reviewCorrection.problem).toContain("caller access");
          expect(input.claims).toHaveLength(1);
          return approvedReview(input.claims);
        }
        expect(reviews).toBe(0);
        expect(input.evidenceSources[0].server).toBe("deployments");
        if (!onEvidence) throw new Error("Missing evidence collector");
        for (const record of records) onEvidence(record);
        return JSON.stringify({ uses: [positive], limitations: [] });
      },
    },
  );
  if (!("checks" in result)) throw new Error("Missing package report");
  const check = result.checks[0]!;
  expect(reviews).toBe(2);
  expect(check.uses[0]!.verdict).toBe("exploitable");
  expect<unknown>(check.uses[0]!.observations).toEqual(
    positive.observations.map((ref) => ({
      server: ref.server,
      record: ref.quote,
      supports: ref.supports,
    })),
  );
  expect(
    check.uses[0]!.decidingEvidence.filter((r) => r.kind === "receipt").map(
      (r) => r.receiptId,
    ),
  ).toEqual(records.map((r) => r.sha256));
  expect<unknown>(dependencyCheckOutputSchema.parse(result)).toEqual(result);
  expect(check.claimEvidence.receipts[records[0]!.sha256]).toEqual(records[0]!);
});

test("only unambiguous returned facts can bind a selected copy and independent caller access", async () => {
  await using f = await fixture();
  const scope = reviewScopes([f.discovery])[0]!;
  const { positive: asserted, records } = deploymentFor(f, "example");
  const verify = (use: Proposal["uses"][number], evidence = records) =>
    verifyProposedUse(f.path, scope, use, signal, true, evidence);
  const [running, access] = asserted.observations;
  const releaseOnly = await verify({
    ...f.use,
    place: { deploymentBasis: "observed" },
    observations: [running!, { ...access!, supports: ["context"] }],
    remainingQuestions: ["Who can reach this service?"],
  });
  expect(releaseOnly.findingEvidence).toEqual([
    { field: "running build", keys: [records[0]!.sha256] },
  ]);
  await expect(
    verify({
      ...asserted,
      observations: [{ ...running!, quote: "only in request" }, access!],
    }),
  ).rejects.toThrow("one recorded reply");
  await expect(
    verify(asserted, [
      ...records,
      {
        ...records[0]!,
        arguments: { selector: "other" },
        sha256: "f".repeat(64),
      },
    ]),
  ).rejects.toThrow("one recorded reply");
  await expect(
    verify({
      ...asserted,
      observations: [running!, { ...running!, supports: ["access"] }],
    }),
  ).rejects.toThrow("separate evidence");
  // A shorter span of the running quote still cannot establish caller access.
  await expect(
    verify({
      ...asserted,
      observations: [
        running!,
        { ...running!, supports: ["access"], quote: "Deployed example" },
      ],
    }),
  ).rejects.toThrow("separate evidence");
  const duplicate = {
    ...records[0]!,
    arguments: { selector: "other" },
    sha256: "f".repeat(64),
  };
  const disambiguated = {
    ...asserted,
    observations: [{ ...running!, sha256: records[0]!.sha256 }, access!],
  };
  expect(
    (await verify(disambiguated, [...records, duplicate])).observations[0]!
      .sha256,
  ).toBe(records[0]!.sha256);
  const other = deploymentFor(f, "another-example");
  await expect(verify(other.positive, other.records)).rejects.toThrow(
    "this running service",
  );
  const wrongVersion = running!.quote.replace("1.0.0", "11.0.0");
  await expect(
    verify(
      {
        ...asserted,
        observations: [{ ...running!, quote: wrongVersion }, access!],
      },
      [returnedEvidence("running", wrongVersion), records[1]!],
    ),
  ).rejects.toThrow("this running service");
  const affected = affectedByFrozenVersion(f.pkg, "1.0.0", [
    {
      id: "CVE-2099-0001",
      url: "https://example.invalid/advisory",
      sha256: createHash("sha256").update("fixture advisory").digest("hex"),
      affected: [
        {
          package: f.pkg,
          ranges: [
            {
              type: "SEMVER",
              events: [{ introduced: "0" }, { fixed: "1.0.0" }],
            },
          ],
        },
      ],
    },
  ]);
  expect(affected).toBe(false);
  await expect(
    verifyProposedUse(f.path, scope, asserted, signal, affected, records),
  ).rejects.toThrow("excludes version");
});

test("resource citations use delivered text and reject echoed URIs and truncated reads", async () => {
  await using f = await fixture();
  const { positive, records } = deploymentFor(f, "example");
  const [running, access] = positive.observations;
  const asserted = {
    ...positive,
    observations: [{ ...running!, tool: "read_mcp_resource" }, access!],
  };
  const scope = reviewScopes([f.discovery])[0]!;
  const verify = (
    uri: string,
    body: string,
    native = false,
    itemUri = uri,
    requestedServer = "deployments",
  ) => {
    const server = "deployments";
    const tool = "read_mcp_resource";
    const response = { server, uri, contents: [{ uri: itemUri, text: body }] };
    const record = {
      server,
      tool,
      arguments: { server: requestedServer, uri },
      result: native
        ? { contents: response.contents }
        : { content: [{ type: "text", text: JSON.stringify(response) }] },
    };
    return verifyProposedUse(f.path, scope, asserted, signal, true, [
      { ...record, sha256: dependencyRecordHash(record) },
      records[1]!,
    ]);
  };
  expect((await verify("release://example", running!.quote)).verdict).toBe(
    "exploitable",
  );
  for (const native of [false, true]) {
    expect(
      (await verify("release://example", running!.quote, native)).verdict,
    ).toBe("exploitable");
    await expect(
      verify("release://example", running!.quote, native, "release://other"),
    ).rejects.toThrow("one recorded reply");
    await expect(
      verify(
        "release://example",
        running!.quote,
        native,
        "release://example",
        "other",
      ),
    ).rejects.toThrow("one recorded reply");
  }
  await expect(
    verify(`release://example?selector=${running!.quote}`, "Release unknown."),
  ).rejects.toThrow("one recorded reply");
  await expect(
    verify("release://example", `${running!.quote} …17 tokens truncated…`),
  ).rejects.toThrow("one recorded reply");
});

test("a reviewed exclusion cannot contradict the cited advisory conditions", async () => {
  await using f = await fixture();
  const scope = reviewScopes([f.discovery])[0]!;
  const excluded = {
    ...f.use,
    verdict: "ruled_out" as const,
    evidence: f.use.evidence.map((e) => ({
      ...e,
      supports: [...e.supports, "exclusion" as const],
    })),
  };
  await expect(
    verifyProposedUse(f.path, scope, excluded, signal, true),
  ).rejects.toThrow("disproved advisory condition");
  const disproved = {
    ...f.use.proof,
    conditions: f.use.proof.conditions.map((c) => ({
      ...c,
      status: "ruled_out" as const,
    })),
  };
  await expect(
    verifyProposedUse(
      f.path,
      scope,
      { ...f.use, proof: disproved },
      signal,
      true,
    ),
  ).rejects.toThrow("disproved necessary condition");
  expect(
    (
      await verifyProposedUse(
        f.path,
        scope,
        { ...excluded, proof: disproved },
        signal,
        true,
      )
    ).verdict,
  ).toBe("ruled_out");
});

test("a failed model invocation retains prior results and identifies unattempted advisories", async () => {
  await using f = await fixture();
  const ids = ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"];
  try {
    await runReviewedDependencyCheck(f.packageOptions, {
      discover: async () => f.discovery,
      lookupPackage: async () => ids.map((id) => ({ id, advisories: [] })),
      runAgent: async ({ prompt }) => {
        const input = JSON.parse(prompt.split("\n\n").at(-1)!);
        if (input.issue.id === ids[1]) throw Error("Model unavailable.");
        return input.claims
          ? approvedReview(input.claims)
          : JSON.stringify({ uses: [f.use], limitations: [] });
      },
    });
    throw Error("Expected a partial package outcome.");
  } catch (error) {
    if (!(error instanceof DependencyInvestigationBlockedError)) throw error;
    expect(error.outcome).toMatchObject({
      status: "blocked",
      code: "INVESTIGATION_BLOCKED",
      checks: [
        { advisoryId: ids[0], schemaVersion: 2 },
        { advisoryId: ids[1], status: "blocked" },
      ],
      pendingAdvisories: [ids[2]],
    });
  }
});

test("a package continues with independent advisories after a scoped block or exhausted review", async () => {
  await using f = await fixture();
  const ids = ["issue-a", "issue-b", "issue-c", "issue-d"];
  const scoped = {
    status: "blocked" as const,
    code: "INVESTIGATION_BLOCKED" as const,
    reason: "Required records for the selected release are unavailable.",
    affectedScope: "worker",
    evidenceReferences: ["record-1"],
  };
  const result = runReviewedDependencyCheck(f.packageOptions, {
    discover: async () => f.discovery,
    lookupPackage: async () => ids.map((id) => ({ id, advisories: [] })),
    runAgent: async ({ prompt }) => {
      const input = JSON.parse(prompt.split("\n\n").at(-1)!);
      if (input.issue.id === ids[1])
        throw new DependencyInvestigationBlockedError(scoped, undefined);
      if (!input.claims)
        return JSON.stringify({ uses: [f.use], limitations: [] });
      return JSON.stringify({
        decisions: input.claims.map((claim: ReviewClaim) => ({
          ...reference(claim),
          evidenceKeys: claim.availableEvidenceKeys,
          approved: input.issue.id !== ids[2],
          reason:
            input.issue.id === ids[2]
              ? "No proof for this release."
              : "Verified.",
        })),
      });
    },
  });
  try {
    await result;
    throw Error("Expected a partial package outcome.");
  } catch (error) {
    if (!(error instanceof DependencyInvestigationBlockedError)) throw error;
    expect(error.outcome).toMatchObject({
      status: "blocked",
      checks: [
        { advisoryId: ids[0], schemaVersion: 2 },
        { advisoryId: ids[1], ...scoped },
        {
          advisoryId: ids[2],
          status: "blocked",
          reason: expect.stringContaining("No proof for this release."),
        },
        { advisoryId: ids[3], schemaVersion: 2 },
      ],
    });
    expect(error.outcome.pendingAdvisories).toBeUndefined();
  }
});

test("a runtime display name shared by two packages cannot establish either deployment", async () => {
  await using f = await fixture();
  f.discovery.manifests = ["notes", "reviews"].map((project, i) => ({
    project,
    name: "shared-service",
    requested: "1.0.0",
    line: 1,
    path: i ? "package-lock.json" : "app.js",
  }));
  const scopes = reviewScopes([f.discovery]);
  const shared = deploymentFor(f, "shared-service");
  for (const scope of scopes)
    await expect(
      verifyProposedUse(
        f.path,
        scope,
        shared.positive,
        signal,
        true,
        shared.records,
      ),
    ).rejects.toThrow("this running service");
  const exact = deploymentFor(f, "notes");
  expect(
    (
      await verifyProposedUse(
        f.path,
        scopes[0]!,
        exact.positive,
        signal,
        true,
        exact.records,
      )
    ).verdict,
  ).toBe("exploitable");
  await expect(
    verifyProposedUse(
      f.path,
      scopes[1]!,
      exact.positive,
      signal,
      true,
      exact.records,
    ),
  ).rejects.toThrow("this running service");
  f.discovery.manifests[1]!.name = "notes";
  expect(reviewScopes([f.discovery])[1]!.runtimeServices).toEqual(["reviews"]);
});

test("an unnamed root manifest binds a service through its observed revision and cited caller", async () => {
  await using f = await fixture({
    "requirements.txt": "fixture-parser==1.0.0\n",
    "receiver.py":
      "import fixture_parser\nfixture_parser.parse(request.body)\n",
  });
  const discovery = await discoverDependencyRepository({
    repository: f.path,
    package: { ecosystem: "PyPI", name: "fixture-parser" },
    environment: { PATH: "" },
  });
  const scope = reviewScopes([discovery])[0]!;
  expect(scope).toMatchObject({ location: ".", manifest: "requirements.txt" });
  const { positive, records } = deploymentFor(f, "example");
  const verify = (...running: string[]) => {
    const callSite = { path: "receiver.py", line: 2 };
    return verifyProposedUse(
      f.path,
      scope,
      {
        ...positive,
        observations: [
          ...running.map((quote) => ({ ...positive.observations[0]!, quote })),
          positive.observations[1]!,
        ],
        evidence: [
          { ...positive.evidence[0]!, path: "receiver.py" },
          { ...positive.evidence[1]!, path: "requirements.txt" },
        ],
        proof: {
          sink: { function: "parse", callSite },
          conditions: positive.proof.conditions.map((c) => ({
            ...c,
            citations: [callSite],
          })),
        },
      },
      signal,
      true,
      [
        ...running.map((quote) => returnedEvidence("running", quote)),
        records[1]!,
      ],
    );
  };
  const release = positive.observations[0]!.quote;
  expect(await verify(`${release} Entrypoint: ./receiver.py`)).toMatchObject({
    scope: scope.id,
    location: "example",
    verdict: "exploitable",
  });
  await expect(
    verify(
      `${release} Entrypoint: sibling/receiver.py`,
      `${release} Entrypoint: ../receiver.py`,
      `${release.replace("1.0.0", "2.0.0")} Entrypoint: receiver.py`,
      `Deployed another service at ${f.revision} with entrypoint receiver.py.`,
      "Deployed example at a different revision with entrypoint receiver.py.",
    ),
  ).rejects.toThrow("this running service");
});

test("an embedded component has its own selected version, deployment and deciding citations", async () => {
  await using f = await fixture({
    "wheel.json": JSON.stringify({
      distribution: "fixture-parser",
      distributionVersion: "1.0.0",
      native: { name: "fixture-codec", version: "2.0.3" },
      digest: "sha256:abc",
    }),
  });
  const scope = {
    ...reviewScopes([f.discovery])[0]!,
    selectedVersion: "1.0.0",
  };
  const use: Proposal["uses"][number] = {
    ...f.use,
    component: "fixture-codec",
    version: "2.0.3",
    place: {
      artifact: "sha256:abc",
      deploymentBasis: "configured",
      environment: "worker",
      patch: "Codec patch supplied by the wheel.",
      dependencySelection: "Pinned wheel inventory",
    },
    evidence: [
      ...f.use.evidence,
      {
        path: "wheel.json",
        startLine: 1,
        endLine: 1,
        supports: ["affected_copy"],
      },
    ],
  };
  const verified = await verifyProposedUse(f.path, scope, use, signal);
  await expect(
    verifyProposedUse(
      f.path,
      { ...scope, selectedVersion: "1.1.0" },
      use,
      signal,
    ),
  ).rejects.toThrow("selected parent artifact");
  await expect(
    verifyProposedUse(
      f.path,
      scope,
      { ...use, version: scope.selectedVersion },
      signal,
    ),
  ).rejects.toThrow("embedded dependency");
  const choice = verified.evidence.at(-1)!;
  const claim = {
    id: "use-1",
    revision: 1,
    hash: "a".repeat(64),
    value: { kind: "use" as const, use: verified },
  };
  const row = reportedUse(verified, claim, [dependencyRecordHash(choice)]);
  expect(row).toMatchObject({
    component: "fixture-codec",
    version: "2.0.3",
    deployment: "configured",
    place: { ...use.place, revision: f.revision },
  });
  expect(row.evidence).toHaveLength(verified.evidence.length);
  expect(row.decidingEvidence).toEqual([
    {
      kind: "source",
      path: "wheel.json",
      commit: f.revision,
      startLine: 1,
      endLine: 1,
    },
  ]);
  await expect(
    verifyProposedUse(f.path, scope, { ...use, version: "2.0.30" }, signal),
  ).rejects.toThrow("embedded dependency");
  await expect(
    verifyProposedUse(
      f.path,
      scope,
      { ...use, component: "unrelated-codec" },
      signal,
    ),
  ).rejects.toThrow("embedded dependency");
});

test("an investigator tool cannot substitute for a running deployment and provenance selects an actual returned record", async () => {
  await using f = await fixture();
  const scope = reviewScopes([f.discovery])[0]!;
  const { positive, records } = deploymentFor(f, "example");
  const own = { ...records[0]!, server: investigationServer };
  const invented = {
    ...positive,
    observations: [
      { ...positive.observations[0]!, server: investigationServer },
      positive.observations[1]!,
    ],
  };
  await expect(
    verifyProposedUse(f.path, scope, invented, signal, true, [
      own,
      records[1]!,
    ]),
  ).rejects.toThrow("Local investigation tool");
  const message = positive.observations[0]!.quote;
  const raw = {
    server: "deployments",
    tool: "running",
    arguments: {},
    result: {
      structuredContent: {
        workloads: [
          { name: "example", message },
          { name: "other", message: "a neighboring build" },
        ],
      },
    },
  };
  const rec = { ...raw, sha256: dependencyRecordHash(raw) };
  const ref = {
    kind: "receipt" as const,
    receiptId: rec.sha256,
    originalPayloadSha256: dependencyRecordHash(raw.result),
    selection: { textBlock: null, record: ["workloads", 0] },
  };
  const associated = {
    ...positive,
    services: [
      {
        id: "example",
        name: "example",
        source: "deployments",
        evidence: [ref],
      },
    ],
  };
  const verify = (u: Proposal["uses"][number]) =>
    verifyProposedUse(f.path, scope, u, signal, true, [rec, records[1]!]);
  // Findings may cite an explicitly bound item receipt even when it did not
  // establish runtime or access and is absent from the observations array.
  const configured = {
    ...f.use,
    services: associated.services,
    receiptSelections: [{ receiptId: rec.sha256, ...ref.selection }],
  };
  expect((await verify(configured)).services).toEqual(associated.services);
  await expect(
    verify({
      ...configured,
      receiptSelections: [
        { receiptId: rec.sha256, textBlock: null, record: ["workloads", 1] },
      ],
    }),
  ).rejects.toThrow("services[0].evidence[0]");
  await expect(
    verify({
      ...configured,
      services: [
        {
          ...associated.services[0]!,
          evidence: [{ ...ref, originalPayloadSha256: "0".repeat(64) }],
        },
      ],
    }),
  ).rejects.toThrow("services[0].evidence[0]");
  const verified = await verify(associated);
  expect(verified.services).toEqual(associated.services);
  const store = new DependencyAttemptStore(":memory:");
  try {
    const claim = store.recordClaim<Claim["value"]>("use-1", {
      kind: "use",
      use: verified,
    });
    const keys = verified.observations.flatMap(
      (row) => row.evidenceKeys ?? [row.sha256],
    );
    const decision = {
      id: claim.id,
      revision: claim.revision,
      hash: claim.hash,
      reason: "Checked the selected facts.",
      approved: true,
    };
    expect(() =>
      approveDependencyClaims(
        store,
        [claim],
        [{ ...decision, evidenceKeys: [rec.sha256, records[1]!.sha256] }],
      ),
    ).toThrow("select the deciding evidence");
    expect(() =>
      approveDependencyClaims(
        store,
        [claim],
        [{ ...decision, evidenceKeys: [keys[0]!] }],
      ),
    ).toThrow("caller access");
    expect(() =>
      approveDependencyClaims(
        store,
        [claim],
        [{ ...decision, evidenceKeys: [records[1]!.sha256] }],
      ),
    ).toThrow("services[0].evidence[0]");
    approveDependencyClaims(
      store,
      [claim],
      [{ ...decision, evidenceKeys: keys }],
    );
    expect(
      reportedUse(verified, claim, keys).decidingEvidence.filter(
        (r) => r.kind === "receipt",
      ),
    ).toContainEqual(ref);
  } finally {
    store.close();
  }
  await expect(
    verify({
      ...positive,
      receiptSelections: [
        { receiptId: rec.sha256, textBlock: null, record: ["workloads", 1] },
      ],
    }),
  ).rejects.toThrow("outside this use's selected receipt rows");
  await expect(
    verify({
      ...associated,
      services: [
        {
          ...associated.services[0]!,
          evidence: [
            {
              ...ref,
              selection: { textBlock: null, record: ["workloads", 2] },
            },
          ],
        },
      ],
    }),
  ).rejects.toThrow("Selector does not exist");
});

test("linked resources remain on the host and the complete preview has a fixed budget", () => {
  const content = "original page body";
  const raw = {
    server: "observations",
    tool: "read_mcp_resource",
    arguments: { uri: "fixture://original" },
    result: { contents: [{ text: content }] },
  };
  const linked = {
    ...raw,
    linkedFrom: "a".repeat(64),
    contentSha256: [dependencyRecordHash(content)],
    sha256: dependencyRecordHash(raw),
  };
  const originals = Array.from({ length: 64 }, (_, i) => {
    const original = {
      server: "observations",
      tool: "lookup",
      arguments: { i },
      result: { value: "entry".repeat(1000) },
    };
    return { ...original, sha256: dependencyRecordHash(original) };
  });
  const preview = evidencePreviews([linked, ...originals]);
  expect(preview[0]).toEqual({
    id: linked.sha256,
    originalPayloadSha256: dependencyRecordHash(raw.result),
    server: linked.server,
    tool: linked.tool,
    linkedFrom: linked.linkedFrom,
    contentSha256: linked.contentSha256,
  });
  expect(JSON.stringify(preview)).not.toContain(content);
  expect(JSON.stringify(preview)).not.toContain("fixture://original");
  expect(preview.length).toBeLessThan(originals.length);
  expect(Buffer.byteLength(JSON.stringify(preview))).toBeLessThan(24_001);
});

test("native investigators share asynchronous reviews, immutable premises and paged original receipts", async () => {
  await using f = await fixture();
  const largeReply = {
    server: "builds",
    tool: "observe",
    arguments: { project: "example" },
    result: {
      structuredContent: {
        partial: true,
        detail: "build evidence ".repeat(1000),
        component: "fixture-parser",
      },
    },
  };
  const receipt = { ...largeReply, sha256: dependencyRecordHash(largeReply) };
  type State = PremiseRef & { state: string };
  type ReviewInput = ReviewClaim & {
    sources: { id: string }[];
    dependencies: PremiseRef[];
  };
  const counts = new Map<string, number>();
  const waiting = Promise.withResolvers<void>(),
    release = Promise.withResolvers<void>();
  const result = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Wrong parser input.",
      evidenceSources: [
        { server: "builds", instructions: "Inspect the recorded build." },
      ],
    },
    {
      discover: async () => f.discovery,
      async runAgent(req) {
        const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        const tools = await req.investigationTools!();
        const call = tools.call;
        if (!req.coordinator) {
          for (const c of input.claims as ReviewInput[])
            counts.set(c.id, (counts.get(c.id) ?? 0) + 1);
          if (
            input.claims.some((c: ReviewInput) => c.id === "premise:version")
          ) {
            expect(input.evidence[0].result).toBeUndefined();
            expect(input.evidence[0].preview.next).toBe(4000);
            const metadata = await call("read_dependency_evidence", {
              server: "builds",
              tool: "observe",
            });
            expect(metadata).toEqual({
              receipts: [
                {
                  id: receipt.sha256,
                  originalPayloadSha256: dependencyRecordHash(
                    largeReply.result,
                  ),
                  server: "builds",
                  tool: "observe",
                },
              ],
              next: null,
            });
            const page = await call("read_dependency_evidence", {
              id: receipt.sha256,
              path: ["structuredContent", "component"],
            });
            expect(page).toMatchObject({
              originalPayloadSha256: dependencyRecordHash(largeReply.result),
              text: '"fixture-parser"',
              next: null,
            });
            waiting.resolve();
            await release.promise;
          }
          return JSON.stringify({
            decisions: input.claims.map((c: ReviewInput) => ({
              ...reference(c),
              approved: true,
              reason: "Verified each selected reference.",
              // Only the returned build record decided this premise. Its source is supporting context.
              evidenceKeys:
                c.id === "premise:version"
                  ? [receipt.sha256]
                  : c.availableEvidenceKeys,
            })),
          });
        }
        req.onEvidence!(receipt);
        await call("trace_codex_security_code", {
          package: "fixture-parser",
          files: ["package-lock.json"],
          source_only: true,
          max_hops: 0,
          time_budget_ms: 5000,
        });
        await expect(
          call("trace_codex_security_code", {
            package: "fixture-parser",
            files: ["../outside"],
            max_hops: 0,
            time_budget_ms: 5000,
          }),
        ).rejects.toThrow();
        req.onEvidenceDiagnostic!("One linked resource was unavailable.");
        req.onEvidenceFailure!({
          server: "builds",
          tool: "labels",
          arguments: {},
        });
        expect(tools.definitions.map((d) => d.name)).toContain(
          "submit_dependency_assessments",
        );
        await call("submit_dependency_claims", {
          claims: [
            {
              id: "version",
              expectedRevision: 0,
              scope: "service",
              statement: "The build selected the parser.",
              sources: [{ path: "app.js", startLine: 1, endLine: 1 }],
              receiptIds: [receipt.sha256],
              dependencies: [],
            },
          ],
        });
        await waiting.promise;
        const other = (await req.investigationTools!()).call;
        const pending = (await other("query_dependency_claims", {
          ids: ["premise:version"],
        })) as State[];
        expect(pending[0]!.state).toBe("pending");
        release.resolve();
        const [approved] = (await other("query_dependency_claims", {
          ids: ["premise:version"],
          wait: true,
        })) as State[];
        expect(approved!.state).toBe("approved");
        const premise = {
          id: approved!.id,
          hash: approved!.hash,
          revision: approved!.revision,
        };
        await expect(
          other("submit_dependency_assessments", {
            assessments: [
              {
                id: "app",
                expectedRevision: 0,
                use: {
                  ...f.use,
                  premises: [{ ...premise, hash: "f".repeat(64) }],
                },
              },
            ],
          }),
        ).rejects.toThrow("currently approved premise");
        await other("submit_dependency_claims", {
          claims: [
            {
              id: "consumer",
              expectedRevision: 0,
              scope: "secondary.js",
              statement: "The second caller imports the same dependency.",
              sources: [{ path: "secondary.js", startLine: 1, endLine: 1 }],
              receiptIds: [],
              dependencies: [premise],
            },
          ],
        });
        const [consumer] = (await other("query_dependency_claims", {
          ids: ["premise:consumer"],
          wait: true,
        })) as State[];
        const consumerRef = {
          id: consumer!.id,
          revision: consumer!.revision,
          hash: consumer!.hash,
        };
        await other("submit_dependency_assessments", {
          assessments: [
            {
              id: "app",
              expectedRevision: 0,
              use: { ...f.use, premises: [consumerRef] },
            },
          ],
        });
        const [assessment] = (await call("query_dependency_claims", {
          ids: ["assessment:app"],
          wait: true,
        })) as State[];
        expect(assessment!.state).toBe("approved");
        return JSON.stringify({ uses: [], limitations: [] });
      },
    },
  );
  if (!("checks" in result)) throw Error("Missing package result");
  const check = result.checks[0]!,
    use = check.uses[0]!;
  expect(check.searches.find((row) => row.source === "builds")).toMatchObject({
    result: "returned",
    completeness: "partial",
    evidenceReferences: [receipt.sha256],
  });
  const failedLookup = check.searches.find((row) => row.tool === "labels")!;
  expect(failedLookup).toMatchObject({
    result: "unknown",
    completeness: "error",
  });
  expect(failedLookup.evidenceReferences).toHaveLength(1);
  expect(
    check.claimEvidence.receipts[failedLookup.evidenceReferences[0]!],
  ).toMatchObject({
    server: "builds",
    tool: "labels",
    arguments: {},
    result: { structuredContent: { status: "failed" } },
  });
  const traces = check.searches.filter(
    (search) => search.tool === "trace_codex_security_code",
  );
  expect(traces).toHaveLength(2);
  expect(traces[0]!.scope).toContain('files=["package-lock.json"]');
  expect(traces[0]!.details.join(" ")).toContain("source-only trace");
  expect(
    check.claimEvidence.receipts[traces[0]!.evidenceReferences[0]!],
  ).toMatchObject({ tool: "trace_codex_security_code" });
  expect(traces[1]).toMatchObject({ result: "unknown", completeness: "error" });
  expect(check.limitations).toContain("One linked resource was unavailable.");
  expect(use.conclusionClaim.id).toBe("assessment:app");
  expect(
    check.claims.find((c) => c.id === "assessment:app")!.dependencies[0]!.id,
  ).toBe("premise:consumer");
  const selected = ["premise:consumer", "premise:version"].map((id) => {
    const claim = check.claims.find((c) => c.id === id)!;
    return { id, revision: claim.revision, hash: claim.hash };
  });
  expect(use.supportingClaims).toEqual(selected);
  expect(use.evidence).toContainEqual({
    path: "secondary.js",
    commit: f.revision,
    startLine: 1,
    endLine: 1,
    supports: [],
  });
  expect(use.evidence).not.toContainEqual({
    path: "app.js",
    commit: f.revision,
    startLine: 1,
    endLine: 1,
    supports: [],
  });
  expect(
    check.claims.find((c) => c.id === "premise:version")!.decision.evidenceKeys,
  ).toEqual([receipt.sha256]);
  expect(use.decidingEvidence).toContainEqual({
    kind: "receipt",
    receiptId: receipt.sha256,
    originalPayloadSha256: dependencyRecordHash(receipt.result),
  });
  expect(check.claimEvidence.receipts[receipt.sha256]).toEqual(receipt);
  expect(Object.fromEntries(counts)).toEqual({
    "premise:version": 1,
    "premise:consumer": 1,
    "assessment:app": 1,
    coverage: 1,
  });
});

test("catalog mappings bind the selected row and keep failed lookups open", async () => {
  const unavailable = "package-lock.json";
  await using f = await fixture();
  const server = "service-registry",
    tool = "lookup";
  const result = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Parser behavior",
      evidenceSources: [
        { server, instructions: "Look up an exact checkout path." },
      ],
    },
    {
      discover: async () => f.discovery,
      async runAgent(req) {
        const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        if (!req.coordinator) return approvedReview(input.claims);
        const { call } = await req.investigationTools!();
        const matched = "app.js",
          unmapped = "secondary.js";
        const lookup = (
          path: string,
          services: { id: string; name: string }[],
        ) => {
          const reply = {
            server,
            tool,
            arguments: { path },
            result: { structuredContent: { services } },
          };
          const record = { ...reply, sha256: dependencyRecordHash(reply) };
          req.onEvidence!(record);
          return record;
        };
        req.onEvidenceFailure!({
          server,
          tool,
          arguments: { path: unavailable },
        });
        const failed = (await call("read_dependency_evidence", {
          server,
          tool,
        })) as { receipts: { id: string }[] };
        const first = lookup(matched, [
            { id: "worker-7", name: "mail worker" },
          ]),
          empty = lookup(unmapped, []);
        const resolve = (path: string, ...ids: string[]) =>
          call("resolve_codex_security_services", {
            path,
            lookups: ids.map((receiptId) => ({
              receiptId,
              textBlock: null,
              target: ["path"],
              records: ["services"],
              id: ["id"],
              name: ["name"],
            })),
          });
        const before = await call("query_codex_security_graph", {});
        await expect(
          resolve(unavailable, failed.receipts[0]!.id),
        ).rejects.toThrow("Unknown evidence receipt");
        await expect(
          resolve(matched, first.sha256, empty.sha256),
        ).rejects.toThrow(/file or its project/);
        expect(await call("query_codex_security_graph", {})).toEqual(before);
        await resolve(matched, first.sha256);
        await resolve(unmapped, empty.sha256);
        const query = (node: string) =>
          call("query_codex_security_graph", { node });
        expect(await query(unmapped)).toMatchObject({
          service_lookup: "checked",
          evidence: expect.arrayContaining([
            expect.objectContaining({ relation: "no_service_found" }),
          ]),
        });
        expect(await query(unavailable)).toMatchObject({
          matches: [],
          service_resolution: { checked: 2 },
        });
        const evidence = (await query(matched)) as {
          evidence: {
            relation: string;
            from: { name: string; scope: string };
            source: string;
            receiptSelections: {
              receiptId: string;
              textBlock: number | null;
              record: (string | number)[];
            }[];
          }[];
        };
        const edge = evidence.evidence.find((e) => e.relation === "uses")!;
        const selected = edge.receiptSelections[0]!;
        const meta = (await call("read_dependency_evidence", {
          id: selected.receiptId,
          path: ["structuredContent", ...selected.record],
        })) as { originalPayloadSha256: string; text: string };
        expect(JSON.parse(meta.text)).toEqual({
          id: "worker-7",
          name: "mail worker",
        });
        return JSON.stringify({
          uses: [
            {
              ...f.use,
              services: [
                {
                  id: edge.from.scope,
                  name: edge.from.name,
                  source: edge.source,
                  evidence: [
                    {
                      kind: "receipt",
                      receiptId: selected.receiptId,
                      originalPayloadSha256: meta.originalPayloadSha256,
                      selection: {
                        textBlock: selected.textBlock,
                        record: selected.record,
                      },
                    },
                  ],
                },
              ],
              observations: [
                {
                  server,
                  tool,
                  sha256: selected.receiptId,
                  quote: "mail worker",
                  supports: ["context"],
                  reason: "Catalog row identifies this caller.",
                },
              ],
            },
          ],
          limitations: [
            `The catalog failed for ${unavailable}. Its mapping remains open.`,
          ],
        });
      },
    },
  );
  if (!("checks" in result)) throw Error("Expected a package assessment.");
  expect(result.checks[0]?.uses[0]?.services).toMatchObject([
    {
      id: server + ":worker-7",
      source: server + "/" + tool + "#worker-7",
      evidence: [
        {
          kind: "receipt",
          selection: { textBlock: null, record: ["services", 0] },
        },
      ],
    },
  ]);
  const check = result.checks[0]!;
  const failedLookup = check.searches.find(
    (r) => r.source === server && r.tool === tool && r.completeness === "error",
  )!;
  expect(failedLookup.evidenceReferences).toHaveLength(1);
  expect(
    check.claimEvidence.receipts[failedLookup.evidenceReferences[0]!],
  ).toMatchObject({
    server,
    tool,
    arguments: { path: unavailable },
    result: { structuredContent: { status: "failed" } },
  });
});

test.each([
  "omission",
  "ambiguous",
  "stale",
  "malformed",
  "persistent",
] as const)(
  "requires every current decision and limits corrective review (%s)",
  async (mode) => {
    await using f = await fixture();
    const batches: string[][] = [];
    let coordinators = 0;
    const run = runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Parser behavior" },
      {
        discover: async () => f.discovery,
        async runAgent(req) {
          if (req.coordinator) {
            coordinators++;
            return JSON.stringify({ uses: [f.use], limitations: [] });
          }
          const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
          const rows = (packet.claims as ReviewClaim[]).map((c) => ({
            ...reference(c),
            approved: true,
            reason: "Verified the exact claim.",
            evidenceKeys: c.availableEvidenceKeys,
          }));
          batches.push(rows.map((row) => row.id));
          const use = rows.find((row) => row.id === "use-1")!;
          if (batches.length === 1 || mode === "persistent") {
            if (mode === "malformed") return "{";
            if (mode === "stale")
              return JSON.stringify({
                decisions: rows.map((d) =>
                  d.id === use.id
                    ? { ...d, revision: d.revision + 1, hash: "f".repeat(64) }
                    : d,
                ),
              });
            if (mode === "omission")
              return JSON.stringify({ decisions: [use] });
            return JSON.stringify({
              decisions: [use, use, { ...use, id: "unrequested" }],
            });
          }
          const feedback = packet.reviewCorrection;
          expect(feedback.expected).toEqual(
            rows.map(({ id, revision, hash }) => ({ id, revision, hash })),
          );
          if (mode === "omission") {
            expect(feedback.problem).toContain("Missing ids");
            expect(packet.approvedClaims.map((c: Claim) => c.id)).toContain(
              "use-1",
            );
          } else if (mode === "ambiguous") {
            expect(feedback.problem).toContain('Duplicate id "use-1"');
            expect(feedback.problem).toContain('Unexpected id "unrequested"');
            expect(packet.approvedClaims).toEqual([]);
          } else if (mode === "stale") {
            expect(feedback.problem).toContain(
              'Wrong revision or hash for "use-1"',
            );
            expect(packet.approvedClaims).toEqual([]);
          } else {
            expect(feedback.problem).toContain("JSON object");
          }
          return JSON.stringify({ decisions: rows });
        },
      },
    );
    if (mode === "persistent") {
      await expect(run).rejects.toThrow(
        /Duplicate id "use-1".*Missing ids \["coverage"\].*Still awaiting/,
      );
    } else {
      const r = await run;
      if (!("checks" in r)) throw Error("Expected a reviewed package report.");
      expect(r.checks[0]!.claims.map((c) => c.id)).toEqual([
        "use-1",
        "coverage",
      ]);
    }
    expect(batches).toEqual([
      ["use-1", "coverage"],
      mode === "omission" ? ["coverage"] : ["use-1", "coverage"],
    ]);
    expect(coordinators).toBe(1);
  },
);

test("a reviewed premise retains independently selected rows of the historical multi-record response", async () => {
  await using f = await fixture();
  const frames = [
    { file: "writer.ts", function: "saveImage" },
    { file: "caller-a.ts", function: "start" },
    { file: "completely-unrelated", function: "third_row_must_not_escape" },
  ];
  const uri = "fixture://profiles/exact";
  const result = {
    contents: [
      {
        uri,
        text: JSON.stringify({
          frames,
          privateTail: "UNRELATED-GRAPH-PROFILE-BYTES".repeat(1700),
        }),
      },
    ],
  };
  const original = {
    server: "deployed",
    tool: "mcpServer/resource/read",
    arguments: { uri },
    result,
    linkedFrom: "inventory-1",
  };
  const captured = { ...original, sha256: dependencyRecordHash(original) };
  // These identities are from the original report producer for these exact bytes and origin.
  const keys = [
    "receipt:5698a19b50d94f50ac87a36cdb0cffc6079e6fea62e32a7de621199101189ef9",
    "receipt:6b4a7ad083941eb4ed59d62c3033bdd6d820ded030ebcf392083bb70067a1227",
  ];
  const selections = [0, 1, 2].map((i) => ({
    receiptId: captured.sha256,
    textBlock: 0,
    record: ["frames", i],
  }));
  const checked = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Review the parser.",
      evidenceSources: [
        {
          server: "deployed",
          instructions: "Inspect the matching caller and operation.",
        },
      ],
    },
    {
      discover: async () => f.discovery,
      async runAgent(req) {
        const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        const tools = await req.investigationTools!();
        if (req.coordinator) {
          req.onEvidence!(captured);
          const claim = {
            id: "frame",
            expectedRevision: 0,
            scope: "caller",
            statement: "The stack includes the caller and writer.",
            sources: [],
            receiptIds: [],
            dependencies: [],
          };
          await expect(
            tools.call("submit_dependency_claims", {
              claims: [
                {
                  ...claim,
                  receiptSelections: [
                    { ...selections[0], record: ["frames", 19] },
                  ],
                },
              ],
            }),
          ).rejects.toThrow("Selector does not exist");
          await tools.call("submit_dependency_claims", {
            claims: [
              {
                ...claim,
                receiptSelections: [...selections.slice(0, 2), selections[0]],
              },
            ],
          });
          const [approved] = (await tools.call("query_dependency_claims", {
            ids: ["premise:frame"],
            wait: true,
          })) as {
            id: string;
            revision: number;
            hash: string;
            state: string;
          }[];
          expect(approved!.state).toBe("approved");
          const { id, revision, hash } = approved!;
          const use = { ...f.use, premises: [{ id, revision, hash }] };
          const tag = (index: number) => ({
            name: "writer",
            evidence: [
              {
                kind: "receipt" as const,
                receiptId: captured.sha256,
                originalPayloadSha256: dependencyRecordHash(captured.result),
                selection: { textBlock: 0, record: ["frames", index] },
              },
            ],
          });
          await expect(
            tools.call("submit_dependency_assessments", {
              assessments: [
                {
                  id: "adjacent",
                  expectedRevision: 0,
                  use: { ...use, tags: [tag(2)] },
                },
              ],
            }),
          ).rejects.toThrow("tags[0].evidence[0]");
          await expect(
            tools.call("submit_dependency_assessments", {
              assessments: [
                {
                  id: "stale",
                  expectedRevision: 0,
                  use: {
                    ...use,
                    premises: [{ id, revision, hash: "0".repeat(64) }],
                    tags: [tag(1)],
                  },
                },
              ],
            }),
          ).rejects.toThrow("currently approved premise");
          return JSON.stringify({
            uses: [{ ...use, tags: [tag(1)] }],
            limitations: [],
          });
        }
        expect(req.prompt).not.toContain("third_row_must_not_escape");
        for (const claim of input.claims)
          if (claim.id === "premise:frame") {
            expect(claim.availableEvidenceKeys).toEqual(keys);
            expect(
              claim.receiptSelections.map(
                (row: { result: unknown }) => row.result,
              ),
            ).toEqual(frames.slice(0, 2));
            expect(input.evidence).toEqual([]);
            expect(
              await tools.call("read_dependency_evidence", {
                id: captured.sha256,
                selection: { textBlock: 0, record: ["frames", 1] },
              }),
            ).toMatchObject({ text: JSON.stringify(frames[1]) });
          }
        return approvedReview(input.claims);
      },
    },
  );
  if (!("checks" in checked)) throw Error("Expected package result");
  const report = checked.checks[0]!;
  expect(
    report.claims.find((c) => c.id === "premise:frame")!.evidence.receiptIds,
  ).toEqual(keys);
  for (const [index, key] of keys.entries()) {
    const selection = { textBlock: 0, record: ["frames", index] };
    const ref = {
      kind: "receipt" as const,
      receiptId: captured.sha256,
      originalPayloadSha256:
        "aef67dc0480fc12d9500fe1377a828a759fde9662a75d2908a65a8d36a6aab08",
      selection,
    };
    if (index === 1) expect(report.uses[0]!.tags?.[0]?.evidence).toEqual([ref]);
    expect(report.uses[0]!.decidingEvidence).toContainEqual(ref);
    expect(report.claimEvidence.receipts[key]).toMatchObject({
      key: key.slice(8),
      receiptId: ref.receiptId,
      originalPayloadSha256: ref.originalPayloadSha256,
      selection,
      result: frames[index],
    });
  }
  expect(
    report.uses[0]!.decidingEvidence.filter((r) => r.kind === "receipt"),
  ).toHaveLength(2);
});

test.each(["ledger", "identical", "additional", "invalid"] as const)(
  "final correction preserves distinct approved deployments and checks new uses (%s)",
  async (mode) => {
    await using f = await fixture({
      Dockerfile:
        'FROM scratch\nCOPY . /app\nWORKDIR /app\nCMD ["node", "app.js"]\n',
    });
    const source = {
      kind: "source" as const,
      path: "Dockerfile",
      commit: f.revision,
      startLine: 2,
      endLine: 4,
    };
    function deployment(
      workload: string,
      startLine = 2,
    ): Proposal["uses"][number] {
      return {
        ...f.use,
        place: { workload, deploymentBasis: "configured" },
        evidence: [
          ...f.use.evidence,
          {
            path: "Dockerfile",
            startLine: 2,
            endLine: 4,
            supports: ["context"],
          },
        ],
        runtimeContext: {
          launch: { command: "node app.js", basis: "configured" },
          evidence: [{ ...source, startLine }],
        },
      };
    }
    const submitted = ["first-job", "second-job"];
    const workload = (id: string) => (mode === "identical" ? "shared-job" : id);
    const reviewCounts = new Map<string, number>();
    let rounds = 0;
    const result = runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Parser behavior" },
      {
        discover: async () => f.discovery,
        async runAgent(req) {
          const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
          if (!req.coordinator) {
            return JSON.stringify({
              decisions: input.claims.map((c: ReviewClaim) => {
                reviewCounts.set(c.id, (reviewCounts.get(c.id) ?? 0) + 1);
                return {
                  ...reference(c),
                  evidenceKeys: c.availableEvidenceKeys,
                  reason: "Checked source and workload.",
                  approved: true,
                };
              }),
            });
          }
          rounds++;
          if (rounds === 1) {
            const { call } = await req.investigationTools!();
            await call("submit_dependency_assessments", {
              assessments: submitted.map((id) => ({
                id,
                expectedRevision: 0,
                use: deployment(workload(id)),
              })),
            });
            const approved = (await call("query_dependency_claims", {
              ids: submitted.map((id) => "assessment:" + id),
              wait: true,
            })) as { state: string }[];
            expect(approved.map((c) => c.state)).toEqual([
              "approved",
              "approved",
            ]);
          } else {
            expect(input.feedback.reason).toContain("Final uses[0]");
            expect(input.feedback.reason).toContain(
              "runtimeContext.evidence[0]",
            );
            expect(input.feedback.reason).toContain(
              "Bound ranges for this path at this revision: 2-4.",
            );
            expect(input.feedback.approvedAssessments).toMatchObject({
              total: 2,
              truncated: false,
              items: submitted.map((id) => ({
                id: "assessment:" + id,
                revision: 1,
                scope: f.use.scope,
                location: f.use.location,
                workload: workload(id),
              })),
            });
            expect(input.feedback.recovery).toContain("return uses: []");
            if (mode === "ledger")
              return JSON.stringify({ uses: [], limitations: [] });
            if (mode === "identical")
              return JSON.stringify({
                uses: [deployment("shared-job")],
                limitations: [],
              });
            if (mode === "additional")
              return JSON.stringify({
                uses: [deployment("third-job")],
                limitations: [],
              });
          }
          // The same location can refer to the existing use, a new caller, or another deployment.
          const attempted = mode === "ledger" ? submitted[0]! : "third-job";
          return JSON.stringify({
            uses: [deployment(attempted, 1)],
            limitations: [],
          });
        },
      },
    );
    if (mode === "invalid") {
      await expect(result).rejects.toThrow("Unbound finding evidence");
      expect(rounds).toBe(3);
    } else {
      const report = await result;
      if (!("checks" in report)) throw Error("Expected package report.");
      const uses = report.checks[0]!.uses;
      expect(uses.map((u) => u.place.workload)).toEqual(
        mode === "additional"
          ? [...submitted, "third-job"]
          : submitted.map(workload),
      );
      expect(uses.slice(0, 2).map((u) => u.conclusionClaim.id)).toEqual(
        submitted.map((id) => "assessment:" + id),
      );
      expect(rounds).toBe(2);
    }
    for (const id of submitted)
      expect(reviewCounts.get("assessment:" + id)).toBe(1);
  },
);

test("a correction in a live review batch preserves its independent sibling approval", async () => {
  await using f = await fixture();
  const started = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const seen: string[][] = [];
  const previous = new Map<string, string[]>();
  await runReviewedDependencyCheck(
    { ...f.packageOptions, vulnDescription: "Parser issue" },
    {
      discover: async () => f.discovery,
      async runAgent(req) {
        const input = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        if (!req.coordinator) {
          const rows = input.claims as ReviewClaim[];
          seen.push(rows.map(premiseKey));
          for (const c of rows) {
            previous.set(
              c.id + "/" + c.revision,
              input.approvedClaims.map((ref: PremiseRef) => ref.id).sort(),
            );
          }
          if (rows.some((c) => c.id === "premise:before" && c.revision === 1)) {
            started.resolve();
            await release.promise;
          }
          return JSON.stringify({
            decisions: rows.map((c) => ({
              ...reference(c),
              evidenceKeys: c.availableEvidenceKeys,
              approved: true,
              reason: "Verified",
            })),
          });
        }
        const { call } = await req.investigationTools!();
        const submit = (id: string, expectedRevision = 0) => ({
          id,
          expectedRevision,
          scope: "parser",
          statement: id + expectedRevision,
          sources: [{ path: "app.js", startLine: 1, endLine: 1 }],
          dependencies: [],
          receiptIds: [],
        });
        await call("submit_dependency_claims", {
          claims: [submit("before"), submit("sibling")],
        });
        await started.promise;
        try {
          await call("submit_dependency_claims", {
            claims: [submit("before", 1)],
          });
        } finally {
          release.resolve();
        }
        const claims = (await call("query_dependency_claims", {
          wait: true,
        })) as (PremiseRef & { state: string })[];
        expect(claims.map((c) => [c.id, c.revision, c.state])).toEqual([
          ["premise:before", 2, "approved"],
          ["premise:sibling", 1, "approved"],
        ]);
        expect(seen).toHaveLength(2);
        expect(seen[0]).toHaveLength(2);
        expect(seen[1]).toHaveLength(1);

        await call("submit_dependency_claims", {
          claims: [
            { ...submit("derived"), dependencies: [reference(claims[0]!)] },
          ],
        });
        const derived = (await call("query_dependency_claims", {
          ids: ["premise:derived"],
          wait: true,
        })) as PremiseRef[];
        await call("submit_dependency_assessments", {
          assessments: [
            {
              id: "selected",
              expectedRevision: 0,
              use: { ...f.use, premises: [reference(derived[0]!)] },
            },
          ],
        });
        return JSON.stringify({ uses: [], limitations: [] });
      },
    },
  );
  expect(previous.get("premise:before/2")).toEqual([]);
  expect(previous.get("premise:derived/1")).toEqual(["premise:before"]);
  expect(previous.get("assessment:selected/1")).toEqual([
    "premise:before",
    "premise:derived",
  ]);
  expect(previous.get("coverage/1")).toEqual([
    "assessment:selected",
    "premise:before",
    "premise:derived",
  ]);
});

test.each(["approved", "rejected", "racing", "changed premise"] as const)(
  "an explicit disposition replacement preserves reviewed assessment identities (%s)",
  async (outcome) => {
    await using f = await fixture();
    const caller = { path: "app.js", line: 2 };
    const other = structuredClone(f.use);
    const otherCaller = { path: "secondary.js", line: 2 };
    other.location = "secondary";
    other.proof.sink!.callSite = otherCaller;
    other.proof.conditions[0]!.citations = [otherCaller];
    other.evidence[0]!.path = otherCaller.path;
    const disposition = {
      scope: f.use.scope,
      location: f.use.location,
      kind: "dismissed",
      reason:
        "The same caller and selected copy are reported by assessment:primary.",
      locations: outcome === "approved" ? [] : [caller],
      evidence: [
        { path: caller.path, startLine: 1, endLine: 2, supports: ["context"] },
      ],
      observations: [],
    };
    const target = "assessment:duplicate";
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let original!: PremiseRef, latest!: PremiseRef;
    let corrected: PremiseRef | undefined;
    let coverageRefs: PremiseRef[] = [];
    const reviewedReplacements: number[] = [];
    const checked = await runReviewedDependencyCheck(
      { ...f.packageOptions, vulnDescription: "Parser issue" },
      {
        discover: async () => ({
          ...f.discovery,
          callers: [caller, otherCaller],
        }),
        async runAgent(req) {
          const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
          if (!req.coordinator) {
            for (const c of packet.claims) {
              if (c.id === "coverage")
                coverageRefs = packet.approvedClaims.map(reference);
              if (c.id !== target || c.payload.kind !== "disposition") continue;
              if (c.revision === 2) {
                started.resolve();
                await release.promise;
              }
              expect(c.previousUse).toMatchObject({
                ...original,
                payload: {
                  kind: "use",
                  use: {
                    scope: f.use.scope,
                    location: f.use.location,
                    proof: f.use.proof,
                  },
                },
                decision: { approved: true, evidenceKeys: expect.any(Array) },
              });
              expect(c.payload.disposition).toMatchObject({
                reason: expect.stringContaining("same caller"),
                evidence: [
                  expect.objectContaining({
                    path: caller.path,
                    commit: f.revision,
                  }),
                ],
              });
              const { call } = await req.investigationTools!();
              expect(
                await call("query_dependency_claims", {
                  ids: ["assessment:primary"],
                }),
              ).toMatchObject([
                {
                  state: "approved",
                  payload: { kind: "use", use: { proof: f.use.proof } },
                },
              ]);
              reviewedReplacements.push(c.revision);
            }
            return JSON.stringify({
              decisions: packet.claims.map(
                (c: ReviewClaim & { payload: Claim["value"] }) => ({
                  ...reference(c),
                  approved:
                    c.id !== target ||
                    c.payload.kind !== "disposition" ||
                    (c.revision === 2 &&
                      (outcome === "approved" || outcome === "racing")),
                  reason: "Checked the caller, selected copy and cited source.",
                  evidenceKeys: c.availableEvidenceKeys,
                }),
              ),
            });
          }
          if (packet.feedback) throw Error(packet.feedback.reason);
          const { call } = await req.investigationTools!();
          const submit = (assessments: unknown[]) =>
            call("submit_dependency_assessments", { assessments });
          const query = async (wait: boolean) => {
            const [claim] = (await call("query_dependency_claims", {
              ids: [target],
              wait,
            })) as (PremiseRef & { state: string; retainedUse?: PremiseRef })[];
            return claim!;
          };
          async function revisePremise(expectedRevision: number) {
            await call("submit_dependency_claims", {
              claims: [
                {
                  id: "lock",
                  expectedRevision,
                  scope: f.use.scope,
                  statement: expectedRevision
                    ? "The lock records version 1.0.0."
                    : "The checkout contains a lock.",
                  sources: [
                    { path: "package-lock.json", startLine: 1, endLine: 1 },
                  ],
                  dependencies: [],
                  receiptIds: [],
                },
              ],
            });
            const [premise] = (await call("query_dependency_claims", {
              ids: ["premise:lock"],
              wait: true,
            })) as PremiseRef[];
            return { ...f.use, premises: [reference(premise!)] };
          }
          const duplicate =
            outcome === "changed premise" ? await revisePremise(0) : f.use;
          await submit([
            { id: "primary", expectedRevision: 0, use: f.use },
            { id: "duplicate", expectedRevision: 0, use: duplicate },
            { id: "other", expectedRevision: 0, use: other },
          ]);
          const approved = await query(true);
          expect(approved.state).toBe("approved");
          original = reference(approved);
          const proposal = {
            id: "duplicate",
            expectedRevision: 1,
            replacesUse: original,
            disposition,
          };
          await expect(
            submit([
              {
                ...proposal,
                replacesUse: { ...original, hash: "0".repeat(64) },
              },
            ]),
          ).rejects.toThrow();
          await expect(
            submit([
              {
                ...proposal,
                replacesUse: { ...original, id: "assessment:primary" },
              },
            ]),
          ).rejects.toThrow();
          await submit([proposal]);
          try {
            await started.promise;
            const pending = await query(false);
            expect(pending).toMatchObject({
              id: target,
              revision: 2,
              state: "pending",
              retainedUse: original,
            });
            expect(pending.hash).not.toBe(original.hash);
            await expect(submit([proposal])).rejects.toThrow();
            if (outcome === "racing") {
              await submit([
                {
                  ...proposal,
                  expectedRevision: 2,
                  disposition: {
                    ...disposition,
                    reason: disposition.reason + " Recheck the binding.",
                  },
                },
              ]);
            }
          } finally {
            release.resolve();
          }
          const settled = await query(true);
          latest = reference(settled);
          expect(latest.revision).toBe(outcome === "racing" ? 3 : 2);
          if (outcome === "approved") {
            expect(settled.state).toBe("approved");
            expect(settled.retainedUse).toBeUndefined();
            expect(
              await submit([
                { ...proposal, expectedRevision: latest.revision },
              ]),
            ).toMatchObject([{ ...latest, state: "approved" }]);
            // An existing client can use the same short name in the separate disposition namespace.
            await submit([
              {
                id: "duplicate",
                expectedRevision: 0,
                disposition: {
                  ...disposition,
                  kind: "unresolved",
                  locations: [],
                  reason: "Deployment remains unknown.",
                },
              },
            ]);
          } else {
            expect(settled).toMatchObject({
              state: "rejected",
              retainedUse: original,
            });
            if (outcome === "changed premise") {
              const use = await revisePremise(1);
              expect((await query(false)).retainedUse).toBeUndefined();
              await submit([{ id: "duplicate", expectedRevision: 2, use }]);
              const repaired = await query(true);
              expect(repaired).toMatchObject({
                revision: 3,
                state: "approved",
              });
              corrected = reference(repaired);
            }
          }
          return JSON.stringify({ uses: [], limitations: [] });
        },
      },
    );
    const result = dependencyCheckOutputSchema.parse(checked);
    if (!("checks" in result)) throw Error("Expected a package check.");
    const report = result.checks[0]!;
    const accepted = outcome === "approved";
    const authoritative = accepted ? latest : (corrected ?? original);
    expect(reviewedReplacements).toEqual(outcome === "racing" ? [2, 3] : [2]);
    expect(coverageRefs.filter((c) => c.id === target)).toEqual([
      authoritative,
    ]);
    expect(
      report.claims?.filter((c) => c.id === target).map(reference),
    ).toEqual([authoritative]);
    expect(report.uses.map((u) => u.conclusionClaim?.id).sort()).toEqual(
      (accepted
        ? ["assessment:primary", "assessment:other"]
        : ["assessment:primary", "assessment:other", target]
      ).sort(),
    );
    expect(
      report.uses.find((u) => u.location === "secondary")?.proof?.sink
        ?.callSite,
    ).toEqual(otherCaller);
    expect(
      report.uses
        .filter((u) => u.conclusionClaim?.id === target)
        .map((u) => u.conclusionClaim),
    ).toEqual(accepted ? [] : [authoritative]);
    const replacement = report.coverage?.filter(
      (d) => d.conclusionClaim?.id === target,
    );
    if (accepted) {
      expect(replacement).toMatchObject([
        {
          kind: "dismissed",
          conclusionClaim: latest,
          reason: disposition.reason,
        },
      ]);
      expect(report.coverage?.map((d) => d.conclusionClaim?.id)).toContain(
        "disposition:duplicate",
      );
    } else expect(replacement).toEqual([]);
  },
);

test("independently verifies candidate dispositions and publishes their selected evidence and handoffs", async () => {
  await using f = await fixture({
    "parser.test.js":
      "import { test } from 'node:test'; import parse from 'fixture-parser';\ntest('fixture', () => parse('sample'));\n",
    "package.json":
      '{"scripts":{"start":"node app.js","test":"node --test parser.test.js"}}\n',
  });
  const caller = { path: "app.js", line: 2 };
  const demo = { path: "parser.test.js", line: 2 };
  const other = { path: "secondary.js", line: 2 };
  const source = (c: typeof caller) => ({
    path: c.path,
    startLine: c.line,
    endLine: c.line,
    supports: ["context"],
  });
  const original = {
    server: "catalog",
    tool: "lookup",
    arguments: { project: "example" },
    result: {
      structuredContent: { rows: [{ id: "worker" }, { id: "unrelated" }] },
    },
  };
  const receipt = { ...original, sha256: dependencyRecordHash(original) };
  const selection = { textBlock: null, record: ["rows", 0] };
  const bound = {
    kind: "receipt",
    receiptId: receipt.sha256,
    originalPayloadSha256: dependencyRecordHash(original.result),
    selection,
  };
  const handoff = {
    verified: "Requests reach the parser dispatch.",
    missing: "Which backend does the running worker select?",
  };
  const place = {
    kind: "job",
    revision: f.revision,
    environment: null,
    artifact: null,
    observationWindow: null,
    deploymentBasis: "configured",
    deploymentDetail: "The worker is configured.",
    dependencySelection: null,
    patch: null,
    unresolvedQuestions: [handoff.missing],
  };
  const input = {
    kind: "unresolved",
    scope: "1.1",
    reason: handoff.missing,
    handoff,
    place,
    location: "worker",
    locations: [caller],
    evidence: [source(caller)],
    observations: [],
    receiptSelections: [{ receiptId: receipt.sha256, ...selection }],
    services: [
      { id: "worker", name: "Worker", source: "catalog", evidence: [bound] },
    ],
  };
  const checked = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Review the parser.",
      evidenceSources: [
        { server: "catalog", instructions: "Identify the deployed consumer." },
      ],
    },
    {
      discover: async () => ({
        ...f.discovery,
        callers: [caller, demo, other],
      }),
      async runAgent(req) {
        const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        const { call } = await req.investigationTools!();
        if (!req.coordinator)
          return JSON.stringify({
            decisions: packet.claims.map((c: ReviewClaim) => {
              if (c.id === "disposition:handoff") {
                expect(c.availableEvidenceKeys.length).toBe(3);
                if (c.revision === 1) {
                  return {
                    ...reference(c),
                    approved: true,
                    reason: "The catalog row was checked.",
                    evidenceKeys: c.availableEvidenceKeys.filter((key) =>
                      key.startsWith("receipt:"),
                    ),
                  };
                }
              }
              return {
                ...reference(c),
                approved: true,
                reason:
                  "Verified this candidate, checkout and original catalog row.",
                evidenceKeys: c.availableEvidenceKeys,
              };
            }),
          });
        req.onEvidence!(receipt);
        const submit = (id: string, disposition: unknown) =>
          call("submit_dependency_assessments", {
            assessments: [{ id, expectedRevision: 0, disposition }],
          });
        await expect(
          submit("default-deployment", {
            ...input,
            place: {
              ...place,
              deploymentBasis: "assumed_not_deployed",
              deploymentDetail: packet.callerScope,
            },
          }),
        ).rejects.toThrow("caller-supplied boundary");
        await expect(
          submit("unknown-candidate", {
            ...input,
            locations: [{ path: "app.js", line: 99 }],
          }),
        ).rejects.toThrow("Unknown candidate");
        await expect(
          submit("fake-source", { ...input, evidence: [source(other)] }),
        ).rejects.toThrow("Cite the checked-out source");
        await expect(
          submit("fake-row", {
            ...input,
            services: [
              {
                ...input.services[0],
                evidence: [
                  {
                    ...bound,
                    selection: { textBlock: null, record: ["rows", 1] },
                  },
                ],
              },
            ],
          }),
        ).rejects.toThrow("Unbound finding evidence");
        await expect(
          submit("fake-claim", {
            ...input,
            conclusionClaim: { id: "invented", revision: 1, hash: "fake" },
          }),
        ).rejects.toThrow();
        await expect(
          submit("no-candidate", {
            ...input,
            kind: "dismissed",
            locations: [],
          }),
        ).rejects.toThrow("observed dependency candidate");
        await call("submit_dependency_claims", {
          claims: [
            {
              id: "lock",
              expectedRevision: 0,
              scope: "worker",
              statement: "The fixture contains a lock.",
              sources: [
                { path: "package-lock.json", startLine: 1, endLine: 1 },
              ],
              receiptIds: [],
              dependencies: [],
            },
          ],
        });
        const [premise] = (await call("query_dependency_claims", {
          ids: ["premise:lock"],
          wait: true,
        })) as { id: string; revision: number; hash: string; state: string }[];
        expect(premise!.state).toBe("approved");
        const { id, revision, hash } = premise!;
        const candidate = { ...input, premises: [{ id, revision, hash }] };
        await submit("handoff", candidate);
        const [rejected] = (await call("query_dependency_claims", {
          ids: ["disposition:handoff"],
          wait: true,
        })) as { state: string; reason: string }[];
        expect(rejected).toMatchObject({ state: "rejected" });
        expect(rejected!.reason).toContain("candidate app.js:2");
        await call("submit_dependency_assessments", {
          assessments: [
            {
              id: "handoff",
              expectedRevision: 1,
              disposition: {
                ...candidate,
                reason:
                  "The source establishes dispatch but does not identify the production backend.",
              },
            },
          ],
        });
        await submit("test", {
          kind: "dismissed",
          scope: "1.1",
          classification: "test_only_outside_scope",
          reason: "The test fixture invokes the parser only in tests.",
          locations: [demo],
          evidence: [
            { ...source(demo), startLine: 1 },
            source({ path: "package.json", line: 1 }),
          ],
          observations: [],
        });
        return JSON.stringify({ uses: [], limitations: [] });
      },
    },
  );
  const report = dependencyCheckOutputSchema.parse(checked);
  expect<unknown>(report).toEqual(checked);
  if (!("checks" in report)) throw new Error("Expected a package check.");
  const result = report.checks[0]!;
  const rows = result.coverage!;
  const gap = rows.find(
    (row) => row.conclusionClaim?.id === "disposition:handoff",
  )!;
  const dismissal = rows.find(
    (row) => row.conclusionClaim?.id === "disposition:test",
  )!;
  expect(gap).toMatchObject({
    kind: "unresolved",
    conclusionClaim: { revision: 2 },
    location: "worker",
    handoff,
    place,
    services: input.services,
    locations: [{ ...caller, candidateId: expect.any(String) }],
    supportingClaims: [{ id: "premise:lock" }],
  });
  expect(dismissal).toMatchObject({
    kind: "dismissed",
    classification: "test_only_outside_scope",
    locations: [demo],
  });
  expect(gap.decidingEvidence).toEqual(
    expect.arrayContaining([
      bound,
      {
        kind: "source",
        path: "app.js",
        commit: f.revision,
        startLine: 2,
        endLine: 2,
      },
      {
        kind: "source",
        path: "package-lock.json",
        commit: f.revision,
        startLine: 1,
        endLine: 1,
      },
    ]),
  );
  for (const row of [gap, dismissal])
    expect(result.claims).toContainEqual(
      expect.objectContaining({ ...row.conclusionClaim, state: "approved" }),
    );
  expect(rows.filter((row) => !row.conclusionClaim)).toMatchObject([
    {
      kind: "unresolved",
      evidence: [{ path: other.path, startLine: other.line }],
    },
  ]);
  expect(result.uses).toEqual([]);
});

test("accounts for native graph candidate lines in their pinned package and preserves other candidate gaps", async () => {
  await using f = await fixture({
    "package.json": '{"dependencies":{"fixture-parser":"1.0.0"}}\n',
    "new.js": "factory();\n",
    "remaining.js": "flow();\n",
    "dirty.js": "old();\n",
  });
  await mkdir(join(f.path, "nested"));
  await writeFile(join(f.path, "nested", "package.json"), '{"name":"other"}\n');
  await writeFile(join(f.path, "nested", "other.js"), "call();\n");
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", f.path, ...args], { encoding: "utf8" }).trim();
  git("add", "nested");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "nested",
  );
  const revision = git("rev-parse", "HEAD");
  await writeFile(join(f.path, "dirty.js"), "different();\n");
  const checked = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Check parser call paths.",
      evidenceSources: [
        { server: "catalog", instructions: "Check deployments." },
      ],
    },
    {
      discover: async () => ({
        ...f.discovery,
        revision,
        manifests: [
          {
            path: "package.json",
            project: ".",
            name: "project",
            requested: "1.0.0",
            line: 1,
          },
        ],
      }),
      async runAgent(req) {
        const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        if (!req.coordinator) return approvedReview(packet.claims);
        const trace = (relation: string, source: string) => ({
          relation,
          from: { kind: "file", name: source },
          evidence: [{ source, lines: [1] }],
        });
        const paths = (relation: string, source: string) => ({
          relation,
          source,
          line: 1,
        });
        const capture = (
          server: string,
          tool: string,
          data: Record<string, unknown>,
        ) => {
          const v = {
            server,
            tool,
            arguments: {},
            result: { structuredContent: data },
          };
          req.onEvidence!({ ...v, sha256: dependencyRecordHash(v) });
        };
        capture(investigationServer, "trace_codex_security_code", {
          trace: [
            trace("candidate_call", "new.js"),
            trace("candidate_flow", "remaining.js"),
            trace("candidate_call", "dirty.js"),
            trace("candidate_call", "nested/other.js"),
          ],
        });
        capture(investigationServer, "query_codex_security_graph", {
          paths: [
            paths("candidate_call", "new.js"),
            { ...paths("candidate_flow", "new.js"), line: 444 },
            paths("observed", "secondary.js"),
          ],
          evidence: [
            {
              ...paths("depends_on", "package.json"),
              to: { kind: "package", name: "fixture-parser" },
            },
          ],
        });
        capture("catalog", "query_codex_security_graph", {
          paths: [paths("candidate_call", "secondary.js")],
        });
        const { call } = await req.investigationTools!();
        const submit = (path: string) =>
          call("submit_dependency_assessments", {
            assessments: [
              {
                id: "reviewed",
                expectedRevision: 0,
                disposition: {
                  kind: "dismissed",
                  scope: "1.1",
                  reason: "This factory operation is unrelated.",
                  locations: [{ path, line: 1 }],
                  evidence: [
                    { path, startLine: 1, endLine: 1, supports: ["context"] },
                  ],
                  observations: [],
                },
              },
            ],
          });
        for (const path of ["nested/other.js", "dirty.js", "secondary.js"])
          await expect(submit(path)).rejects.toThrow("Unknown candidate");
        await submit("new.js");
        return JSON.stringify({ uses: [], limitations: [] });
      },
    },
  );
  const report = dependencyCheckOutputSchema.parse(checked);
  if (!("checks" in report)) throw new Error("Expected package report");
  const coverage = report.checks[0]!.coverage!;
  expect(coverage.find((c) => c.conclusionClaim)).toMatchObject({
    kind: "dismissed",
    locations: [{ path: "new.js", line: 1 }],
  });
  expect(
    coverage
      .filter((c) => c.kind === "unresolved")
      .flatMap((c) => c.evidence.map((s) => s.path))
      .sort(),
  ).toEqual(["app.js", "package.json", "remaining.js"]);
});

test("reports the scope and outcome of original evidence lookups across MCP response formats", async () => {
  await using f = await fixture();
  const args = {
    selector: { environment: "prod", name: "release\nitem" },
    path: "a".repeat(5000),
    token: "opaque argument",
  };
  const noMatch = { status: "not_found", coverage: { complete: true } };
  const text = (value: unknown) => ({
    type: "text",
    text: JSON.stringify(value),
  });
  const inputs = [
    {
      tool: "lookup",
      reply: { structuredContent: noMatch },
      result: "no_match",
      completeness: "complete",
    },
    {
      tool: "lookup_samples",
      reply: {
        structured_content: {
          content: [
            text({ data: { outcome: "matched", result_complete: true } }),
            text({ metadata: { has_more: true } }),
          ],
        },
      },
      result: "matches",
      completeness: "partial",
    },
    {
      tool: "lookup_empty",
      reply: { content: [] },
      result: "unknown",
      completeness: "unknown",
    },
    {
      tool: "lookup_unstructured",
      reply: { content: [text({ rows: [] })] },
      result: "returned",
      completeness: "unknown",
    },
    {
      tool: "lookup_cutoff",
      reply: { content: [{ type: "text", text: "…13 chars truncated…" }] },
      result: "returned",
      completeness: "partial",
    },
    {
      tool: "lookup_failed",
      reply: { isError: true },
      result: "unknown",
      completeness: "error",
    },
  ];
  const result = await runReviewedDependencyCheck(
    {
      ...f.packageOptions,
      vulnDescription: "Parser input.",
      evidenceSources: [
        { server: "inventory", instructions: "Look up deployed copies." },
        { server: "offline", instructions: "Look up release records." },
      ],
    },
    {
      discover: async () => f.discovery,
      async runAgent(req) {
        if (req.coordinator) {
          req.onEvidenceStartup!(
            "offline",
            "failed",
            false,
            "Connection refused",
          );
          const capture = createDependencyEvidenceCapture(
            { inventory: {} },
            req.onEvidenceFailure,
          );
          for (const { tool, reply } of inputs) {
            const evidence = capture({
              type: "item.completed",
              item: {
                type: "mcp_tool_call",
                status: "completed",
                server: "inventory",
                tool,
                arguments: args,
                result: reply,
              },
            });
            if (evidence) req.onEvidence!(evidence);
          }
          return JSON.stringify({ uses: [], limitations: [] });
        }
        const packet = JSON.parse(req.prompt.split("\n\n").at(-1)!);
        return approvedReview(packet.claims);
      },
    },
  );
  if (!("checks" in result)) throw Error("Expected a package check");
  const check = result.checks[0]!;
  const offline = check.searches.find((row) => row.source === "offline")!;
  expect([offline.result, offline.completeness]).toEqual([
    "not_run",
    "unavailable",
  ]);
  expect(
    check.claimEvidence.receipts[offline.evidenceReferences[0]!],
  ).toMatchObject({
    server: "offline",
    tool: "mcp_server_startup",
    result: {
      structuredContent: { status: "failed", error: "Connection refused" },
    },
  });
  for (const input of inputs) {
    const row = check.searches.find((entry) => entry.tool === input.tool)!;
    expect(row.scope).toEqual([
      "environment=prod",
      "name=release\\u000aitem",
      "Request SHA-256 " + dependencyRecordHash(args),
    ]);
    expect([row.result, row.completeness]).toEqual([
      input.result,
      input.completeness,
    ]);
    const original = {
      server: "inventory",
      tool: input.tool,
      arguments: args,
      result: input.reply,
      ...(input.result === "unknown" &&
        input.completeness === "error" && { hostStatus: "failed" }),
    };
    expect(row.evidenceReferences).toEqual([dependencyRecordHash(original)]);
    expect(check.claimEvidence.receipts[row.evidenceReferences[0]!]).toEqual({
      ...original,
      sha256: dependencyRecordHash(original),
    });
  }
});
