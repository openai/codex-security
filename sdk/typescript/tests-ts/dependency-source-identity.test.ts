import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  readDependencyEvidence,
  type DependencyExcerpt,
} from "../src/dependency-reachability.js";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import { readDependencyReportCode } from "../src/dependency-report-renderer.js";
import { createDependencyReportSubmission } from "../src/dependency-report-submission.js";
import { evidenceKey } from "../src/dependency-evidence-store.js";
import { createDependencySourceEvidence } from "../src/dependency-source-evidence.js";
import { createDependencySourceIdentityReader } from "../src/dependency-source-identity.js";
import {
  readRegularInputFile,
  readRegularInputFileBytes,
} from "../src/prompt-files.js";
import { gitText } from "./support/shell.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

function git(repository: string, ...args: string[]): string {
  return gitText(
    [
      "-C",
      repository,
      "-c",
      "core.autocrlf=false",
      "-c",
      "commit.gpgsign=false",
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
}

async function initialize(
  repository: string,
  bytes: string | Buffer,
  objectFormat = "sha1",
) {
  await mkdir(repository, { recursive: true });
  git(
    repository,
    "init",
    "-q",
    "--template=",
    `--object-format=${objectFormat}`,
  );
  await writeFile(join(repository, "codec.ts"), bytes);
  git(repository, "add", "codec.ts");
  git(repository, "commit", "-qm", "Source fixture");
  return {
    commit: git(repository, "rev-parse", "HEAD"),
    blob: git(repository, "rev-parse", "HEAD:codec.ts"),
  };
}

const sha256 = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");

test.each(["sha1", "sha256"])(
  "captures the exact %s commit, relative path, blob and full-file bytes for every submitted range",
  async (objectFormat) => {
    await using root = await scopedTemporaryDirectory("dependency-source-git-");
    const bytes = Buffer.from("import codec;\ncodec.decode(input);\n");
    const expected = await initialize(root.path, bytes, objectFormat);
    const excerpts: DependencyExcerpt[] = [];
    await readDependencyEvidence(
      [1, 2].map((line) => ({
        path: "codec.ts",
        startLine: line,
        endLine: line,
        supports: [],
      })),
      root.path,
      undefined,
      (excerpt) => excerpts.push(excerpt),
    );
    expect(excerpts.map((excerpt) => excerpt.text)).toEqual([
      "import codec;",
      "codec.decode(input);",
    ]);
    for (const excerpt of excerpts) {
      expect(excerpt.sourceIdentity).toEqual({
        kind: "git",
        status: "verified",
        repositoryRoot: root.path,
        repositoryPath: "codec.ts",
        ...expected,
        contentSha256: sha256(bytes),
      });
    }
    expect(excerpts[0]!.sourceIdentity).toBe(excerpts[1]!.sourceIdentity);
  },
);

test("retains an investigation's commit but compares each fresh capture, and a new investigation resolves a new commit", async () => {
  await using root = await scopedTemporaryDirectory(
    "dependency-source-revision-",
  );
  const file = join(root.path, "codec.ts");
  const first = Buffer.from("export const patched = true;\n");
  const original = await initialize(root.path, first);
  const readIdentity = createDependencySourceIdentityReader(root.path);
  expect(await readIdentity(file, first)).toMatchObject({
    ...original,
    status: "verified",
  });
  const changed = Buffer.from("export const patched = false;\n");
  await writeFile(file, changed);
  git(root.path, "add", "codec.ts");
  git(root.path, "commit", "-qm", "Different source fixture");
  const artifact = { sourceCommit: git(root.path, "rev-parse", "HEAD") };
  const stale = await readIdentity(file, changed);
  expect(stale).toMatchObject({
    ...original,
    status: "modified",
    contentSha256: sha256(changed),
  });
  expect(stale.commit).not.toBe(artifact.sourceCommit);
  expect(
    await createDependencySourceIdentityReader(root.path)(file, changed),
  ).toMatchObject({ status: "verified", commit: artifact.sourceCommit });
});

test("ignores unrelated dirty files while identifying modified and uncommitted cited files", async () => {
  await using root = await scopedTemporaryDirectory("dependency-source-dirty-");
  const bytes = Buffer.from("codec.decode(input);\n");
  const expected = await initialize(root.path, bytes);
  const file = join(root.path, "codec.ts");
  const readIdentity = createDependencySourceIdentityReader(root.path);
  await writeFile(join(root.path, "unrelated.ts"), "unrelated change\n");
  expect(await readIdentity(file, bytes)).toMatchObject({
    ...expected,
    status: "verified",
  });
  const changed = Buffer.from("codec.encode(input);\n");
  await writeFile(file, changed);
  git(root.path, "add", "codec.ts", "unrelated.ts");
  expect(await readIdentity(file, changed)).toMatchObject({
    ...expected,
    status: "modified",
  });
  expect(
    await readIdentity(
      join(root.path, "unrelated.ts"),
      await readFile(join(root.path, "unrelated.ts")),
    ),
  ).toMatchObject({
    status: "not_in_commit",
    commit: expected.commit,
    blob: null,
  });
});

test("does not infer an exported tree's revision from a manifest", async () => {
  await using root = await scopedTemporaryDirectory(
    "dependency-source-export-",
  );
  const bytes = Buffer.from("codec.decode(input);\n");
  const file = join(root.path, "codec.ts");
  await writeFile(file, bytes);
  await writeFile(
    join(root.path, "source-manifest.json"),
    JSON.stringify({ commit: "a".repeat(40) }),
  );
  expect(
    await createDependencySourceIdentityReader(root.path)(file, bytes),
  ).toMatchObject({
    status: "unavailable",
    commit: null,
    blob: null,
    repositoryRoot: null,
    contentSha256: sha256(bytes),
    reason: expect.stringContaining("not a git repository"),
  });
});

test("hashes the guarded raw file once without UTF8 replacement or newline normalization", async () => {
  await using root = await scopedTemporaryDirectory("dependency-source-bytes-");
  const bytes = Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from("codec.decode(input);\r\n"),
    Buffer.from([0xff, 0x0a]),
  ]);
  await initialize(root.path, bytes);
  const file = join(root.path, "codec.ts");
  expect(await readRegularInputFileBytes(file, root.path)).toEqual(bytes);
  expect(await readRegularInputFile(file, root.path)).toBe(
    bytes.toString("utf8"),
  );
  const excerpts: DependencyExcerpt[] = [];
  await readDependencyEvidence(
    [{ path: "codec.ts", startLine: 1, endLine: 1, supports: [] }],
    root.path,
    undefined,
    (excerpt) => excerpts.push(excerpt),
  );
  expect(excerpts[0]!.sourceIdentity).toMatchObject({
    status: "verified",
    contentSha256: sha256(bytes),
  });
  expect(sha256(bytes)).not.toBe(sha256(Buffer.from(bytes.toString("utf8"))));
  const normalized = Buffer.from(
    bytes.toString("utf8").replace(/\r\n/gu, "\n"),
  );
  expect(
    await createDependencySourceIdentityReader(root.path)(file, normalized),
  ).toMatchObject({ status: "modified", contentSha256: sha256(normalized) });
});

test("disables replacement objects when binding the attested commit and its file", async () => {
  await using root = await scopedTemporaryDirectory(
    "dependency-source-replace-",
  );
  const first = Buffer.from("export const patched = true;\n");
  const expected = await initialize(root.path, first);
  const changed = Buffer.from("export const patched = false;\n");
  const file = join(root.path, "codec.ts");
  await writeFile(file, changed);
  git(root.path, "add", "codec.ts");
  git(root.path, "commit", "-qm", "Replacement fixture");
  const replacement = git(root.path, "rev-parse", "HEAD");
  git(root.path, "reset", "--hard", expected.commit);
  git(root.path, "replace", expected.commit, replacement);
  expect(git(root.path, "show", "HEAD:codec.ts")).toBe(
    changed.toString("utf8").trim(),
  );
  const readIdentity = createDependencySourceIdentityReader(root.path);
  expect(await readIdentity(file, first)).toMatchObject({
    ...expected,
    status: "verified",
  });
  await writeFile(file, changed);
  expect(await readIdentity(file, changed)).toMatchObject({
    ...expected,
    status: "modified",
  });
});

test("reports a missing local blob without retrieving it from its configured promisor", async () => {
  await using root = await scopedTemporaryDirectory(
    "dependency-source-missing-",
  );
  const origin = join(root.path, "origin");
  const repository = join(root.path, "checkout");
  const bytes = Buffer.from("codec.decode(input);\n");
  const expected = await initialize(origin, bytes);
  await cp(origin, repository, { recursive: true });
  git(repository, "config", "extensions.partialClone", "origin");
  git(repository, "config", "remote.origin.promisor", "true");
  git(repository, "config", "remote.origin.url", origin);
  const object = join(
    repository,
    ".git",
    "objects",
    expected.blob.slice(0, 2),
    expected.blob.slice(2),
  );
  await rm(object);
  const identity = await createDependencySourceIdentityReader(repository)(
    join(repository, "codec.ts"),
    bytes,
  );
  expect(identity).toMatchObject({
    ...expected,
    status: "unavailable",
    contentSha256: sha256(bytes),
    reason: expect.stringContaining("fatal:"),
  });
  await expect(readFile(object)).rejects.toMatchObject({ code: "ENOENT" });
  expect(await readFile(join(repository, "codec.ts"))).toEqual(bytes);
});

test("propagates cancellation instead of turning it into unavailable provenance", async () => {
  await using root = await scopedTemporaryDirectory("dependency-source-abort-");
  const reason = new Error("Stop this inspection");
  const readIdentity = createDependencySourceIdentityReader(root.path);
  await expect(
    readIdentity(
      join(root.path, "codec.ts"),
      Buffer.from("source"),
      AbortSignal.abort(reason),
    ),
  ).rejects.toBe(reason);
});

test("captures historical Git objects and exact range receipts without changing the checkout", async () => {
  await using root = await scopedTemporaryDirectory(
    "dependency-historical-git-",
  );
  const original = Buffer.from("const fix = true;\n");
  const pinned = await initialize(root.path, original);
  const file = join(root.path, "codec.ts");
  await writeFile(file, "const fix = false;\nconst added = true;\n");
  git(root.path, "add", "codec.ts");
  git(root.path, "commit", "-qm", "A different tree");
  const current = git(root.path, "rev-parse", "HEAD");
  const requests: object[] = [];
  const source = createDependencySourceEvidence({
    repository: root.path,
    directory: join(root.path, "receipts"),
    fetcher: async () => {
      throw new Error("A local source lookup must not use the network.");
    },
    recordExcerpt(excerpt) {
      requests.push(excerpt);
      return evidenceKey(excerpt);
    },
  });
  const request = { kind: "git", ...pinned, path: "codec.ts" };
  const { sourceId } = await source.fetch({
    kind: request.kind,
    commit: request.commit,
    path: request.path,
  });
  expect(await source.excerpt({ sourceId, search: "fix" })).toMatchObject({
    matchingLines: [1],
  });
  expect(requests).toHaveLength(0);
  const clamped = await source.excerpt({ sourceId, startLine: 1, endLine: 2 });
  expect(clamped).toMatchObject({
    requestedRange: { startLine: 1, endLine: 2 },
    startLine: 1,
    endLine: 1,
    lineCount: 1,
    git: { repositoryRoot: root.path, blob: pinned.blob },
    request: { kind: "git", commit: pinned.commit, path: "codec.ts" },
    sha256: sha256(original),
    text: original.toString("utf8"),
  });
  expect(requests).toHaveLength(1);
  expect(requests[0]).toMatchObject({ startLine: 1, endLine: 1 });
  const exact = await source.excerpt({ sourceId, startLine: 1, endLine: 1 });
  const receiptId = evidenceKey(requests[0]);
  expect(exact).toMatchObject({ receiptId });
  expect(clamped).toMatchObject({ receiptId });
  expect(requests[1]).toEqual(requests[0]);
  await expect(
    source.excerpt({ sourceId, startLine: 2, endLine: 3 }),
  ).rejects.toThrow("Invalid source range");

  const range = { path: "codec.ts", startLine: 1, endLine: 1, supports: [] };
  await expect(
    readDependencyEvidence(
      [{ ...range, commit: pinned.commit, endLine: 2 }],
      root.path,
    ),
  ).rejects.toThrow("Invalid evidence range");
  const excerpts: DependencyExcerpt[] = [];
  await readDependencyEvidence(
    [range, { ...range, commit: pinned.commit }],
    root.path,
    undefined,
    (excerpt) => excerpts.push(excerpt),
  );
  expect(excerpts[0]).toMatchObject({
    text: "const fix = false;",
    sourceIdentity: { commit: current },
  });
  expect(excerpts[1]).toMatchObject({
    text: "const fix = true;",
    commit: pinned.commit,
    sourceIdentity: {
      ...pinned,
      status: "verified",
      contentSha256: sha256(original),
    },
  });
  expect(git(root.path, "rev-parse", "HEAD")).toBe(current);
  await expect(
    source.fetch({ kind: "git", commit: "HEAD", path: "codec.ts" }),
  ).rejects.toThrow();
  await expect(
    source.fetch({ kind: "git", commit: pinned.blob, path: "codec.ts" }),
  ).rejects.toThrow();
  await expect(
    source.fetch({ kind: "git", commit: pinned.commit, path: "../codec.ts" }),
  ).rejects.toThrow();
  await expect(
    source.fetch({ kind: "git", commit: pinned.commit, path: "absent.ts" }),
  ).rejects.toThrow();
});

test("reviews the historical caller at its exact commit and refuses a lookalike graph candidate", async () => {
  await using root = await scopedTemporaryDirectory("historical-review-");
  const historical = await initialize(root.path, "decode(checkedInput);\n");
  await writeFile(join(root.path, "codec.ts"), "decode(uncheckedInput);\n");
  const item = {
    id: "immutable-caller",
    kind: "use",
    candidateIds: [],
    use: {
      location: "Historical caller codec.ts:1",
      component: "codec",
      version: null,
      verdict: "ruled_out",
      deployment: "unknown",
      reason: "The historical caller enforces the check.",
      evidence: [
        {
          path: "codec.ts",
          commit: historical.commit,
          startLine: 1,
          endLine: 1,
          supports: [],
        },
      ],
      observations: [],
    },
  };
  const advisory = { cve: "CVE-2024-1000", advisories: [] };
  const candidates = await createDependencyCandidates(root.path);
  const [candidate] = await candidates.observeGraph(
    "query_codex_security_graph",
    {
      paths: [{ relation: "candidate_call", source: "codec.ts", line: 1 }],
    },
  );
  expect(candidate).toBeDefined();
  const rejected = createDependencyReportSubmission({
    repository: root.path,
    advisory,
    candidates,
    review: async () => {
      throw new Error("Mismatched source must not enter the reviewer.");
    },
  });
  try {
    expect(
      await rejected.queue({
        items: [{ ...item, candidateIds: [candidate!.id] }],
      }),
    ).toMatchObject({
      queued: false,
      feedback: expect.stringContaining(
        "does not match the current graph candidate",
      ),
    });
  } finally {
    await rejected.close();
  }
  const state = createDependencyReportSubmission({
    repository: root.path,
    advisory,
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
      const [reviewed] = packet.items;
      expect(packet.excerpts[reviewed.excerptIds[0]]).toMatchObject({
        text: "decode(checkedInput);",
        commit: historical.commit,
        sourceIdentity: { ...historical, status: "verified" },
      });
      return JSON.stringify({
        items: [
          {
            id: reviewed.id,
            revision: reviewed.revision,
            hash: reviewed.hash,
            accepted: true,
            reason: "The bound source shows a checked input.",
            citedVersion: null,
            evidenceIds: reviewed.excerptIds,
          },
        ],
      });
    },
  });
  try {
    expect(
      await state.queue({
        items: [
          {
            ...item,
            use: {
              ...item.use,
              evidence: [{ ...item.use.evidence[0], endLine: 2 }],
            },
          },
        ],
      }),
    ).toMatchObject({
      queued: false,
      feedback: expect.stringContaining("Invalid evidence range"),
    });
    expect(await state.queue({ items: [item] })).toMatchObject({
      queued: true,
    });
    expect(
      await state.submit({
        reviewItems: [{ id: item.id, revision: 1 }],
        candidateGeneration: state.readStatus().candidateGeneration,
        limitations: [],
      }),
    ).toMatchObject({ accepted: true });
    const saved = state.publicReport();
    expect(saved.uses[0]!.decidingEvidence).toEqual([
      {
        kind: "source",
        path: "codec.ts",
        commit: historical.commit,
        startLine: 1,
        endLine: 1,
      },
    ]);
    const code = await readDependencyReportCode(
      {
        ...saved,
        cve: advisory.cve,
        advisories: [],
        usage: null,
      },
      root.path,
    );
    expect([...code.values()]).toEqual(["decode(checkedInput);"]);
  } finally {
    await state.close();
  }
});

test.each([
  {
    name: "rejects a deciding historical mismatch with a current excerpt offered as context",
    currentCall: "decode(uncheckedInput);",
    ranges: [
      { line: 1, historical: false, deciding: false },
      { line: 1, historical: true, deciding: true },
    ],
    accepted: false,
  },
  {
    name: "accepts a deciding current caller with separate historical metadata",
    currentCall: "decode(uncheckedInput);",
    ranges: [
      { line: 1, historical: false, deciding: true },
      { line: 2, historical: true, deciding: true },
    ],
    accepted: true,
  },
  {
    name: "accepts a deciding historical caller with the same captured file bytes",
    currentCall: "decode(checkedInput);",
    ranges: [{ line: 1, historical: true, deciding: true }],
    accepted: true,
  },
  {
    name: "rejects a historical caller whose line matches but file bytes differ",
    currentCall: "decode(checkedInput);",
    currentRelease: 2,
    ranges: [
      { line: 1, historical: false, deciding: false },
      { line: 1, historical: true, deciding: true },
    ],
    accepted: false,
  },
])("$name", async ({ currentCall, currentRelease = 1, ranges, accepted }) => {
  await using root = await scopedTemporaryDirectory("historical-candidate-");
  const pinned = await initialize(
    root.path,
    "decode(checkedInput);\nconst historicalRelease = 1;\n",
  );
  const current = Buffer.from(
    currentCall + "\nconst historicalRelease = " + currentRelease + ";\n",
  );
  await writeFile(join(root.path, "codec.ts"), current);
  git(root.path, "add", "codec.ts");
  git(root.path, "commit", "--allow-empty", "-qm", "Current caller");

  const candidates = await createDependencyCandidates(root.path);
  const [candidate] = await candidates.observeGraph(
    "query_codex_security_graph",
    { paths: [{ relation: "candidate_call", source: "codec.ts", line: 1 }] },
  );
  expect(candidate).toMatchObject({
    sourceSha256: sha256(Buffer.from(currentCall)),
    sourceFileSha256: sha256(current),
  });
  const evidence = ranges.map(({ line, historical }) => ({
    path: "codec.ts",
    ...(historical && { commit: pinned.commit }),
    startLine: line,
    endLine: line,
    supports: [],
  }));
  const selectedRanges = ranges.filter(({ deciding }) => deciding);
  const state = createDependencyReportSubmission({
    repository: root.path,
    advisory: { cve: "CVE-2024-1000", advisories: [] },
    candidates,
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
      const [item] = packet.items;
      const evidenceIds = (item.excerptIds as string[]).filter((id) => {
        const excerpt = packet.excerpts[id] as DependencyExcerpt;
        return selectedRanges.some(
          ({ line, historical }) =>
            excerpt.startLine === line &&
            excerpt.commit === (historical ? pinned.commit : undefined),
        );
      });
      expect(evidenceIds).toHaveLength(selectedRanges.length);
      return JSON.stringify({
        items: [
          {
            id: item.id,
            revision: item.revision,
            hash: item.hash,
            accepted: true,
            reason: "The selected excerpts support the submitted source claim.",
            citedVersion: null,
            evidenceIds,
          },
        ],
      });
    },
  });
  try {
    const queued = await state.queue({
      items: [
        {
          id: "caller",
          kind: "use",
          candidateIds: [candidate!.id],
          use: {
            location: "codec.ts:1",
            component: "codec",
            version: null,
            verdict: "unknown",
            deployment: "unknown",
            reason:
              "The source call is known. The selected native copy is open.",
            evidence,
            observations: [],
          },
        },
      ],
    });
    expect(queued.queued).toBe(true);
    if (!queued.queued) throw new Error(queued.feedback);
    const submitted = await state.submit({
      reviewItems: queued.items,
      candidateGeneration: state.readStatus().candidateGeneration,
      limitations: [],
    });
    expect(submitted.accepted, submitted.feedback).toBe(accepted);
    if (accepted) {
      expect(state.publicReport().uses[0]!.decidingEvidence).toEqual(
        expect.arrayContaining(
          selectedRanges.map(({ line, historical }) => ({
            kind: "source",
            path: "codec.ts",
            ...(historical && { commit: pinned.commit }),
            startLine: line,
            endLine: line,
          })),
        ),
      );
    } else {
      expect(submitted.feedback).toContain(
        "does not match the current graph candidate's source",
      );
    }
  } finally {
    await state.close();
  }
});
