import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { DependencyAttemptStore } from "../src/dependency-attempt-store.js";
import { createDependencyClaims } from "../src/dependency-claims.js";
import { readDependencyClaimExcerpts } from "../src/dependency-report-submission.js";
import {
  finalizeStackReport,
  prepareStackAssessment,
  stackInvestigationReportSchema,
} from "../src/dependency-stack-assessment.js";
import {
  prepareStackPacket,
  stackPacketWorkItems,
} from "../src/dependency-stack-packet.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { git } from "./git-fixture.js";

const fixture = fileURLToPath(
  new URL(
    "../../../evals/dependency-reachability/fixtures/stack-workflow/prepare.mjs",
    import.meta.url,
  ),
);
async function capture(
  root: string,
  variant: "fixed" | "unbound",
  affectedVersionRange?: string,
  fixedInput = false,
) {
  const input = join(root, variant);
  execFileSync("node", [fixture, input, variant]);
  const repository = join(input, "target");
  if (affectedVersionRange) {
    const file = join(input, "sinks.json");
    const sinks = JSON.parse(await readFile(file, "utf8"));
    sinks.sinks[0].affectedVersions = [affectedVersionRange];
    sinks.advisory.summary =
      "The decoder operation is affected inside the supplied range when its input is controlled.";
    await writeFile(file, JSON.stringify(sinks));
    const captureFile = join(input, "stacks.json");
    const capture = JSON.parse(await readFile(captureFile, "utf8"));
    if (fixedInput) {
      await writeFile(
        join(repository, "decode.js"),
        'import { decode } from "sample-codec";\nexport function handle() {\n  return decode(new Uint8Array(0));\n}\n',
      );
      git(
        repository,
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-qam",
        "Use the fixed input",
      );
      capture.target.sha = git(repository, "rev-parse", "HEAD");
    }
    capture.queries[0].groups[0].observations[0].bindings[0].sourceSha =
      capture.target.sha;
    await writeFile(captureFile, JSON.stringify(capture));
  }
  const packet = await prepareStackPacket({
    cve: "CVE-2099-0001",
    repository,
    sourcesPath: join(input, "sources.json"),
    sinksPath: join(input, "sinks.json"),
    stacksPath: join(input, "stacks.json"),
    inputsDir: join(input, "frozen"),
    toolRevision: "fixture-1",
  });
  return { packet, repository, work: stackPacketWorkItems(packet)[0]! };
}

test("a bound exclusion retains the actual evidence and becomes unusable after its premise changes", async () => {
  await using dir = await scopedTemporaryDirectory("stack-binding-");
  const { packet, repository, work } = await capture(dir.path, "fixed");
  const store = new DependencyAttemptStore(join(dir.path, "run.sqlite"));
  try {
    const ledger = createDependencyClaims(
      packet.manifest.attemptId,
      undefined,
      store,
      "single_agent",
    );
    const binding = work.observation!.bindings![0]!;
    const excerpts = await readDependencyClaimExcerpts(
      binding.evidence!.map((range) => ({
        ...range,
        commit: packet.manifest.target.sha,
      })),
      repository,
    );
    const fact = {
      id: "selected-copy",
      scope: work.id,
      payload: { version: binding.version },
      dependencies: [],
      receipts: [],
      excerpts,
    };
    const premise = ledger.reference(ledger.propose(fact).record);
    const claim = ledger.reference(
      ledger.propose({ ...fact, id: "outside-range", dependencies: [premise] })
        .record,
    );
    const input = {
      workItemId: work.id,
      verdict: "ruled_out",
      reason: "The recorded decoder deployment contains 2.1.0.",
      supportingClaims: [claim],
    };
    const row = await prepareStackAssessment(
      input,
      work,
      packet,
      ledger,
      repository,
    );
    const report = finalizeStackReport(packet, [row], ledger);
    expect(report.verdict).toBe("ruled_out");
    expect(report.claims.map((c) => c.id)).toEqual([
      "outside-range",
      "selected-copy",
    ]);
    expect(report.claims[0]!.sources[0]).toMatchObject({
      path: "deployment.json",
      commit: packet.manifest.target.sha,
      startLine: 1,
      endLine: 8,
    });
    expect(report.claims[0]!.sources[0]!.text).toContain("2.1.0");
    expect(
      report.assessments[0]!.observation!.frames.map((f) => f.rawIndex),
    ).toEqual([0, 1]);
    expect(report.coverage).toMatchObject({
      total: 1,
      assessed: 1,
      outstanding: [],
    });

    await expect(
      prepareStackAssessment(
        input,
        {
          ...work,
          scope: { ...work.scope, image_digest: "sha256:" + "2".repeat(64) },
        },
        packet,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/exclusion|supplied sink|mapped sink/i);
    ledger.propose(
      { ...fact, payload: { version: "unresolved" } },
      premise.revision,
    );
    expect(() => finalizeStackReport(packet, [row], ledger)).toThrow(/stale/);
  } finally {
    store.close();
  }
});

test("a mapped implementation keeps its own frame and a different requested workload stays unresolved", async () => {
  await using dir = await scopedTemporaryDirectory("stack-query-scope-");
  const { packet, repository } = await capture(dir.path, "fixed");
  const query = packet.stacks.queries[0]!;
  const observed = query.groups[0]!.observations[0]!;
  observed.scope = {
    service: query.scope.service!,
    image_digest: query.scope.image_digest!,
  };
  query.selectors.sinks = [{ name: "publicDecode" }];
  observed.frames.splice(1, 0, { name: "publicDecode", type: "javascript" });
  observed.sourceIndex = 2;
  observed.sinkIndex = 1;
  observed.sinkMatches = [{ sinkId: "decoder", rawIndex: 0 }];
  delete observed.sinkIds;
  const [matched] = stackPacketWorkItems(packet);
  const store = new DependencyAttemptStore(":memory:");
  try {
    const ledger = createDependencyClaims(
      packet.manifest.attemptId,
      undefined,
      store,
      "single_agent",
    );
    const binding = observed.bindings![0]!;
    const excerpts = await readDependencyClaimExcerpts(
      binding.evidence!.map((r) => ({
        ...r,
        commit: packet.manifest.target.sha,
      })),
      repository,
    );
    const ref = ledger.reference(
      ledger.propose({
        id: "fixed-release",
        scope: matched!.id,
        payload: binding.version,
        dependencies: [],
        receipts: [],
        excerpts,
      }).record,
    );
    const input = {
      workItemId: matched!.id,
      verdict: "ruled_out",
      reason: "The observed release is fixed.",
      supportingClaims: [ref],
    };
    const fixed = await prepareStackAssessment(
      input,
      matched!,
      packet,
      ledger,
      repository,
    );
    const decided = finalizeStackReport(packet, [fixed], ledger);
    expect(decided.assessments[0]).toMatchObject({
      verdict: "ruled_out",
      frameIndices: [0, 1, 2],
      scopeConflicts: [],
      observation: {
        sinkIndex: 1,
        sinkMatches: [{ sinkId: "decoder", rawIndex: 0 }],
      },
    });

    const wrong = structuredClone(packet);
    const requested = wrong.stacks.queries[0]!.scope;
    requested.service = "another-decoder";
    requested.image_digest = "sha256:" + "e".repeat(64);
    const [returned] = stackPacketWorkItems(wrong);
    await expect(
      prepareStackAssessment(input, returned!, wrong, ledger, repository),
    ).rejects.toThrow(/conflicting capture scope/i);
    expect(() => finalizeStackReport(wrong, [fixed], ledger)).toThrow(
      /conflicting capture scope/i,
    );
    const gap = await prepareStackAssessment(
      {
        ...input,
        verdict: "unknown",
        reason: "The sample covers a different service and image.",
      },
      returned!,
      wrong,
      ledger,
      repository,
    );
    const report = finalizeStackReport(wrong, [gap], ledger);
    expect(report).toMatchObject({
      verdict: "unknown",
      coverage: { scopeConflicts: [matched!.id] },
      assessments: [
        {
          queryScope: {
            service: "another-decoder",
            image_digest: requested.image_digest,
          },
          scope: { service: "decoder", image_digest: binding.imageDigest },
          scopeConflicts: returned!.scopeConflicts,
        },
      ],
    });
    expect(report.remainingQuestions.join(" ")).toContain("another-decoder");
    expect(report.remainingQuestions.join(" ")).toContain(
      requested.image_digest,
    );
  } finally {
    store.close();
  }
});

test("a sample without a package binding and an empty capture stay scoped unknown", async () => {
  await using dir = await scopedTemporaryDirectory("stack-gap-");
  const { packet, repository, work } = await capture(dir.path, "unbound");
  const store = new DependencyAttemptStore(":memory:");
  try {
    const ledger = createDependencyClaims(
      packet.manifest.attemptId,
      undefined,
      store,
      "single_agent",
    );
    const input = {
      workItemId: work.id,
      verdict: "unknown",
      reason: "The decoder frame was sampled.",
      remainingQuestions: [
        "Which dependency version ran in the sampled workload?",
      ],
    };
    const row = await prepareStackAssessment(
      input,
      work,
      packet,
      ledger,
      repository,
    );
    expect(finalizeStackReport(packet, [row], ledger)).toMatchObject({
      verdict: "unknown",
      remainingQuestions: input.remainingQuestions,
    });
    await expect(
      prepareStackAssessment(
        { ...input, verdict: "ruled_out" },
        work,
        packet,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/supporting claim/);
    await expect(
      prepareStackAssessment(
        { ...input, frameIndices: [55] },
        work,
        packet,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/outside/);

    const group = packet.stacks.queries[0]!.groups[0]!;
    group.status = "no_match";
    group.observations = [];
    const missing = stackPacketWorkItems(packet)[0]!;
    const unresolved = await prepareStackAssessment(
      { ...input, workItemId: missing.id },
      missing,
      packet,
      ledger,
      repository,
    );
    expect(finalizeStackReport(packet, [unresolved], ledger)).toMatchObject({
      verdict: "unknown",
      coverage: { noMatch: [missing.id] },
      assessments: [{ observation: null }],
    });
    expect(() => finalizeStackReport(packet, [], ledger)).toThrow(
      /disposition/,
    );
  } finally {
    store.close();
  }
});

test("an affected version and sampled frames still need cited input control and advisory conditions", async () => {
  await using dir = await scopedTemporaryDirectory("stack-advisory-");
  const { packet, repository, work } = await capture(
    dir.path,
    "fixed",
    "<3.0.0",
  );
  const store = new DependencyAttemptStore(":memory:");
  try {
    const ledger = createDependencyClaims(
      packet.manifest.attemptId,
      undefined,
      store,
      "single_agent",
    );
    const binding = work.observation!.bindings![0]!;
    const version = binding.evidence![0]!;
    const code = { path: "decode.js", startLine: 2, endLine: 3 };
    async function claim(id: string, range: typeof code) {
      const excerpts = await readDependencyClaimExcerpts(
        [{ ...range, commit: packet.manifest.target.sha }],
        repository,
      );
      return ledger.reference(
        ledger.propose({
          id,
          scope: work.id,
          payload: id,
          excerpts,
          dependencies: [],
          receipts: [],
        }).record,
      );
    }
    const versionClaim = await claim("running-copy", version);
    const callClaim = await claim("caller-argument", code);
    const use = {
      location: "fixture handler",
      component: binding.package,
      version: binding.version,
      verdict: "exploitable",
      deployment: "confirmed",
      reason: "The fixture handler forwards its caller's bytes to decode.",
      evidence: [
        { ...version, supports: ["affected_copy", "running"] },
        { ...code, supports: ["affected_use", "access"] },
      ],
      proof: {
        sink: { function: "decode", callSite: { path: code.path, line: 3 } },
        conditions: [],
      },
    };
    const input = {
      workItemId: work.id,
      verdict: use.verdict,
      reason: use.reason,
      supportingClaims: [versionClaim, callClaim],
      use,
    };
    await expect(
      prepareStackAssessment(input, work, packet, ledger, repository),
    ).rejects.toThrow(/attacker control/);
    await expect(
      prepareStackAssessment(
        { ...input, attackerControlClaim: versionClaim },
        work,
        packet,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/attacker control/);
    await expect(
      prepareStackAssessment(
        { ...input, attackerControlClaim: callClaim },
        work,
        packet,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/precondition/);
    const decisive = {
      ...input,
      attackerControlClaim: callClaim,
      use: {
        ...use,
        proof: {
          ...use.proof,
          conditions: [
            {
              label: packet.sinks.sinks[0]!.preconditions[0]!,
              status: "met",
              explanation: "Bytes originate from the selected caller argument.",
              citations: [{ path: code.path, line: 2 }],
            },
          ],
        },
      },
    };
    const row = await prepareStackAssessment(
      decisive,
      work,
      packet,
      ledger,
      repository,
    );
    expect(finalizeStackReport(packet, [row], ledger).verdict).toBe(
      "exploitable",
    );
    await expect(
      prepareStackAssessment(
        {
          ...decisive,
          use: {
            ...decisive.use,
            evidence: [{ ...code, supports: ["affected_use", "access"] }],
          },
        },
        work,
        packet,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/unknown/);
  } finally {
    store.close();
  }
});

test("a source guard rules out the sampled path only when the running build is tied to that source", async () => {
  await using dir = await scopedTemporaryDirectory("stack-guard-");
  const { packet, repository, work } = await capture(
    dir.path,
    "fixed",
    "<3.0.0",
    true,
  );
  const store = new DependencyAttemptStore(":memory:");
  try {
    const ledger = createDependencyClaims(
      packet.manifest.attemptId,
      undefined,
      store,
      "single_agent",
    );
    const binding = work.observation!.bindings![0]!;
    const code = { path: "decode.js", startLine: 3, endLine: 3 };
    const ranges = [...binding.evidence!, code];
    const excerpts = await readDependencyClaimExcerpts(
      ranges.map((r) => ({ ...r, commit: packet.manifest.target.sha })),
      repository,
    );
    const ref = ledger.reference(
      ledger.propose({
        id: "constant-input",
        scope: work.id,
        payload: "The verified build calls decode with a constant.",
        excerpts,
        dependencies: [],
        receipts: [],
      }).record,
    );
    const reason = "The decoder receives a newly allocated empty array.";
    const input = {
      workItemId: work.id,
      verdict: "ruled_out",
      reason,
      supportingClaims: [ref],
      use: {
        location: "decoder",
        component: binding.package,
        version: binding.version,
        verdict: "ruled_out",
        deployment: "confirmed",
        reason,
        evidence: ranges.map((r) => ({ ...r, supports: [] })),
        proof: {
          sink: { function: "decode", callSite: { path: code.path, line: 3 } },
          conditions: [
            {
              label: packet.sinks.sinks[0]!.preconditions[0]!,
              status: "ruled_out",
              explanation: reason,
              citations: [{ path: code.path, line: 3 }],
            },
          ],
        },
      },
    };
    const row = await prepareStackAssessment(
      input,
      work,
      packet,
      ledger,
      repository,
    );
    expect(finalizeStackReport(packet, [row], ledger).verdict).toBe(
      "ruled_out",
    );
    const differentBuild = structuredClone(packet);
    differentBuild.stacks.queries[0]!.groups[0]!.observations[0]!.bindings![0]!.sourceSha =
      "a".repeat(40);
    const [observed] = stackPacketWorkItems(differentBuild);
    await expect(
      prepareStackAssessment(
        input,
        observed!,
        differentBuild,
        ledger,
        repository,
      ),
    ).rejects.toThrow(/build-to-source/);
    expect(() => finalizeStackReport(differentBuild, [row], ledger)).toThrow(
      /build-to-source/,
    );
  } finally {
    store.close();
  }
});

test("the published stack report schema matches the validated CLI report", async () => {
  const file = new URL(
    "../schemas/stack-investigation-report-v1.schema.json",
    import.meta.url,
  );
  expect(JSON.parse(await readFile(file, "utf8"))).toEqual(
    z.toJSONSchema(stackInvestigationReportSchema, { reused: "ref" }),
  );
});
