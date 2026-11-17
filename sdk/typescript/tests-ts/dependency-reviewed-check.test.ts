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
import { affectedByFrozenVersion } from "../src/dependency-advisory-version";
import { withDependencyCheckOutput } from "../src/dependency-check-output";
import {
  approveDependencyClaims,
  reviewScopes,
  verifyProposedUse,
  type Claim,
  type Proposal,
} from "../src/dependency-reviewed-claims";
import {
  DependencyInvestigationBlockedError,
  runReviewedDependencyCheck,
} from "../src/dependency-reviewed-check";
import type { DependencyEvidenceRecord } from "../src/dependency-evidence-sources";
import type { RepositoryDiscovery } from "../src/dependency-discovery";

const signal = new AbortController().signal;
async function fixture() {
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
  const phases: string[] = [];
  const result = await runReviewedDependencyCheck(
    {
      directory: f.path,
      subject: "npm:fixture-parser",
      signal,
      onProgress(type) {
        phases.push(type);
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
          decisions: input.claims.map((claim: Claim) => ({
            id: claim.id,
            hash: claim.hash,
            revision: claim.revision,
            approved: true,
            reason: "Checked the selected source and scope.",
          })),
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
  expect(phases).toEqual([
    "advisory",
    "discovery",
    "investigation",
    "review",
    "discovery",
    "investigation",
    "review",
  ]);
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
  ).toEqual(["started", "review", "failed"]);
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
            decisions: input.claims.map((claim: Claim) => ({
              id: claim.id,
              revision: claim.revision,
              hash: claim.hash,
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
          decisions: input.claims.map((c: Claim) => ({
            id: c.id,
            revision: c.revision,
            hash: c.hash,
            approved: true,
            reason: "Checked the pins and outstanding caller.",
          })),
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
            decisions: input.claims.map((c: Claim) => ({
              id: c.id,
              hash: c.hash,
              revision: c.revision,
              approved: true,
              reason: "Checked the original replies and source.",
            })),
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
  expect(check.uses[0]!.observations.map((ref) => ref.sha256)).toEqual(
    records.map((r) => r.sha256),
  );
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
  const verify = (uri: string, body: string) => {
    const server = "deployments";
    const tool = "read_mcp_resource";
    const response = { server, uri, contents: [{ uri, text: body }] };
    const record = {
      server,
      tool,
      arguments: { server, uri },
      result: { content: [{ type: "text", text: JSON.stringify(response) }] },
    };
    return verifyProposedUse(f.path, scope, asserted, signal, true, [
      { ...record, sha256: dependencyRecordHash(record) },
      records[1]!,
    ]);
  };
  expect((await verify("release://example", running!.quote)).verdict).toBe(
    "exploitable",
  );
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
                  decisions: input.claims.map((c: Claim) => ({
                    id: c.id,
                    hash: c.hash,
                    revision: c.revision,
                    approved: true,
                    reason: "Verified.",
                  })),
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
