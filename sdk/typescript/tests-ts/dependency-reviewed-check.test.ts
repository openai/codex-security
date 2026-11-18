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
import { readDependencyCheckOutput } from "../src/dependency-reachability";
import { withDependencyCheckOutput } from "../src/dependency-check-output";
import {
  approveDependencyClaims,
  reviewScopes,
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
  investigationServer,
  type DependencyEvidenceRecord,
} from "../src/dependency-evidence-sources";
import {
  discoverDependencyRepository,
  type RepositoryDiscovery,
} from "../src/dependency-discovery";

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
    [Symbol.asyncDispose]: () => rm(path, { recursive: true, force: true }),
  };
}

test("package checks freeze each advisory independently and verify exact source and review references", async () => {
  await using f = await fixture();
  const events: {
    type: string;
    subject?: string;
    fields?: Record<string, unknown>;
  }[] = [];
  const result = await runReviewedDependencyCheck(
    {
      directory: f.path,
      subject: "npm:fixture-parser",
      signal,
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
        return JSON.stringify({
          decisions: input.claims.map(
            (claim: Claim & { availableEvidenceKeys: string[] }) => ({
              evidenceKeys: claim.availableEvidenceKeys,
              id: claim.id,
              hash: claim.hash,
              revision: claim.revision,
              approved: true,
              reason: "Checked the selected source and scope.",
            }),
          ),
        });
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
      {
        directory: f.path,
        subject: "npm:fixture-parser",
        vulnDescription: "Incorrect length validation.",
        signal,
      },
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
      {
        directory: f.path,
        subject: "npm:fixture-parser",
        vulnDescription: "Incorrect length validation.",
        signal,
      },
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
          directory: f.path,
          subject: "npm:fixture-parser",
          vulnDescription: "Incorrect length validation.",
          signal,
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
            id: first.id,
            revision: first.revision,
            hash: first.hash,
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
          id: c.id,
          revision: c.revision,
          hash: c.hash,
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
    const ref = (c: Claim) => ({
      id: c.id,
      revision: c.revision,
      hash: c.hash,
    });
    const parent = submit("caller", [ref(base)], []);
    approve(parent, [premiseKey(base)]);
    const leaf = submit("service", [ref(parent)], []);
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
          ...ref(c),
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
      directory: f.path,
      subject: "npm:fixture-parser",
      vulnDescription: "Untrusted input reaches the parser.",
      signal,
    },
    {
      discover: async () => f.discovery,
      runAgent: async ({ prompt }) => {
        const input = JSON.parse(prompt.split("\n\n").at(-1)!);
        if (input.claims) {
          reviews++;
          return JSON.stringify({
            decisions: input.claims.map(
              (claim: Claim & { availableEvidenceKeys: string[] }) => ({
                evidenceKeys: claim.availableEvidenceKeys,
                id: claim.id,
                revision: claim.revision,
                hash: claim.hash,
                approved: reviews > 1 || claim.id === "coverage",
                reason:
                  reviews === 1
                    ? "Explain the observed data flow more precisely."
                    : "Checked the revised citation.",
              }),
            ),
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
    {
      directory: f.path,
      subject: "npm:fixture-parser",
      vulnDescription: "Parser failure.",
      signal,
    },
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
        return JSON.stringify({
          decisions: input.claims.map(
            (c: Claim & { availableEvidenceKeys: string[] }) => ({
              evidenceKeys: c.availableEvidenceKeys,
              id: c.id,
              revision: c.revision,
              hash: c.hash,
              approved: true,
              reason: "Checked the pins and outstanding caller.",
            }),
          ),
        });
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

test("the investigator cites live replies and a separate reviewer sees their originals", async () => {
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
  const result = await runReviewedDependencyCheck(
    {
      directory: f.path,
      subject: "npm:fixture-parser",
      vulnDescription: "A parser issue.",
      evidenceSources: [
        {
          server: "deployments",
          instructions: "Look up release details and external caller access.",
        },
      ],
      signal,
    },
    {
      discover: async () => f.discovery,
      runAgent: async ({ prompt, onEvidence }) => {
        const input = JSON.parse(prompt.split("\n\n").at(-1)!);
        if (input.claims) {
          expect(onEvidence).toBeUndefined();
          expect(input.evidence).toEqual(records);
          return JSON.stringify({
            decisions: input.claims.map(
              (c: Claim & { availableEvidenceKeys: string[] }) => ({
                evidenceKeys: c.availableEvidenceKeys,
                id: c.id,
                hash: c.hash,
                revision: c.revision,
                approved: true,
                reason: "Checked the original replies and source.",
              }),
            ),
          });
        }
        expect(input.evidenceSources[0].server).toBe("deployments");
        if (!onEvidence) throw new Error("Missing evidence collector");
        for (const record of records) onEvidence(record);
        return JSON.stringify({ uses: [positive], limitations: [] });
      },
    },
  );
  if (!("checks" in result)) throw new Error("Missing package report");
  const check = result.checks[0]!;
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
  expect<unknown>(readDependencyCheckOutput(result)).toEqual(result);
  expect(check.claimEvidence.receipts[records[0]!.sha256]).toEqual(records[0]!);
});

test("only unambiguous returned facts can bind a selected copy and independent caller access", async () => {
  await using f = await fixture();
  const scope = reviewScopes([f.discovery])[0]!;
  const { positive: asserted, records } = deploymentFor(f, "example");
  const verify = (use: Proposal["uses"][number], evidence = records) =>
    verifyProposedUse(f.path, scope, use, signal, true, evidence);
  const [running, access] = asserted.observations;
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

test("a blocked package retains prior independently approved results and identifies unattempted advisories", async () => {
  await using f = await fixture();
  const ids = ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"];
  try {
    await runReviewedDependencyCheck(
      { directory: f.path, subject: "npm:fixture-parser", signal },
      {
        discover: async () => f.discovery,
        lookupPackage: async () => ids.map((id) => ({ id, advisories: [] })),
        runAgent: async ({ prompt }) => {
          const input = JSON.parse(prompt.split("\n\n").at(-1)!);
          if (input.issue.id === ids[1]) throw Error("Model unavailable.");
          return JSON.stringify(
            input.claims
              ? {
                  decisions: input.claims.map(
                    (c: Claim & { availableEvidenceKeys: string[] }) => ({
                      evidenceKeys: c.availableEvidenceKeys,
                      id: c.id,
                      hash: c.hash,
                      revision: c.revision,
                      approved: true,
                      reason: "Verified.",
                    }),
                  ),
                }
              : { uses: [f.use], limitations: [] },
          );
        },
      },
    );
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
      structuredContent: { workloads: [{ name: "example", message }] },
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
  expect((await verify(associated)).services).toEqual(associated.services);
  await expect(
    verify({
      ...associated,
      services: [
        {
          ...associated.services[0]!,
          evidence: [
            {
              ...ref,
              selection: { textBlock: null, record: ["workloads", 1] },
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
  type Ref = { id: string; revision: number; hash: string };
  type State = Ref & { state: string };
  type ReviewInput = {
    id: string;
    revision: number;
    hash: string;
    availableEvidenceKeys: string[];
    sources: { id: string }[];
    dependencies: Ref[];
  };
  const counts = new Map<string, number>();
  const waiting = Promise.withResolvers<void>(),
    release = Promise.withResolvers<void>();
  const result = await runReviewedDependencyCheck(
    {
      directory: f.path,
      subject: "npm:fixture-parser",
      vulnDescription: "Wrong parser input.",
      evidenceSources: [
        { server: "builds", instructions: "Inspect the recorded build." },
      ],
      signal,
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
            const metadata = await call("list_dependency_evidence", {
              server: "builds",
              tool: "observe",
            });
            expect(metadata).toEqual({
              receipts: [
                { id: receipt.sha256, server: "builds", tool: "observe" },
              ],
              next: null,
            });
            const page = await call("read_dependency_evidence", {
              id: receipt.sha256,
              path: ["structuredContent", "component"],
            });
            expect(page).toMatchObject({
              text: '"fixture-parser"',
              next: null,
            });
            waiting.resolve();
            await release.promise;
          }
          return JSON.stringify({
            decisions: input.claims.map((c: ReviewInput) => ({
              id: c.id,
              revision: c.revision,
              hash: c.hash,
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
        await other("submit_dependency_assessments", {
          assessments: [
            {
              id: "app",
              expectedRevision: 0,
              use: { ...f.use, premises: [premise] },
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
  expect(check.searches.find((row) => row.tool === "labels")).toMatchObject({
    result: "unknown",
    completeness: "error",
    evidenceReferences: [],
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
  ).toBe("premise:version");
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
    "assessment:app": 1,
    coverage: 1,
  });
});
