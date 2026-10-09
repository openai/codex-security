import { modelResponseText } from "./support/model-response-text.js";
import { execFile as execFileCallback } from "node:child_process";
import { cp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { delimiter, dirname, join, relative } from "node:path";
import { promisify } from "node:util";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { InvalidTargetError } from "../src/errors.js";
import type { OwnerContext } from "../src/owner-evidence.js";
import {
  suggestOwners,
  type OwnerFinding,
  type SuggestOwnersOptions,
} from "../src/suggest-owners.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const execFile = promisify(execFileCallback);
const { temporaryDirectory, cleanup } =
  createApiTestFixtures("owner-repository-");
afterEach(cleanup);

const finding: OwnerFinding = {
  findingId: "finding-one",
  title: "Missing authorization",
  summary: "Check access before reading a record.",
  locations: [{ path: "handler.ts", startLine: 2, endLine: 3 }],
};

async function repository() {
  const path = await temporaryDirectory();
  const git = async (...args: string[]) =>
    (await execFile("git", ["-C", path, ...args])).stdout.trim();
  await git("init", "-q");
  await git("config", "user.name", "Alex Example");
  await git("config", "user.email", "alex@example.test");
  await git("config", "commit.gpgsign", "false");
  await writeFile(
    join(path, "handler.ts"),
    "// Records\nexport function readRecord(id) {\n  return records[id];\n}\n",
  );
  await git("add", ".");
  await git("commit", "-qm", "Add record handler");
  const original = await git("rev-parse", "HEAD");
  await writeFile(
    join(path, "handler.ts"),
    "// Record access\nexport function readRecord(id) {\n  return records[id];\n}\n",
  );
  await git(
    "-c",
    "user.name=Blair Example",
    "-c",
    "user.email=blair@example.test",
    "commit",
    "-qam",
    "Clarify comment",
  );
  return { path, git, original, revision: await git("rev-parse", "HEAD") };
}

function fakeCodex(decide: (context: OwnerContext) => unknown = chooseAlex) {
  const calls: {
    context: OwnerContext;
    thread: ThreadOptions;
    turn: TurnOptions;
  }[] = [];
  const codex: NonNullable<SuggestOwnersOptions["codex"]> = {
    startThread(thread) {
      return {
        async run(prompt, turn) {
          const context = JSON.parse(
            prompt.split("\n\n").at(-1)!,
          ) as OwnerContext;
          calls.push({ context, thread, turn });
          const result = decide(context);
          return { finalResponse: modelResponseText(result) };
        },
      };
    },
  };
  return { codex, calls };
}

function chooseAlex(context: OwnerContext) {
  const index = context.identities.findIndex(
    ({ email }) => email === "alex@example.test",
  );
  return {
    identityIndex: index,
    reason:
      "Alex maintains the record handler; Blair only changed its comment.",
    evidenceIds: context.evidence
      .filter((item) => item.identityIndex === index)
      .map(({ id }) => id),
  };
}

test.each(["ISO-8859-1", "UTF-16LE"])(
  "preserves blame and history identities with %s Git output configured",
  async (encoding) => {
    const repo = await repository();
    for (const [name, email, version, subject] of [
      ["Renée Example", "renee@example.test", 1, "Ancienne révision"],
      ["Zoë Example", "zoe@example.test", 2, "Nouvelle révision"],
    ] as const) {
      await writeFile(
        join(repo.path, "handler.ts"),
        `// façade\nexport const version = ${version};\n`,
      );
      await repo.git(
        "-c",
        `user.name=${name}`,
        "-c",
        `user.email=${email}`,
        "commit",
        "-qam",
        subject,
      );
    }
    await repo.git("config", "i18n.logOutputEncoding", encoding);
    for (const [name, email] of [
      ["Renée Example", "renee@example.test"],
      ["Zoë Example", "zoe@example.test"],
    ]) {
      const { codex, calls } = fakeCodex((context) => {
        const identityIndex = context.identities.findIndex(
          (identity) => identity.email === email,
        );
        return {
          identityIndex,
          reason: "Synthetic ownership selection.",
          evidenceIds: context.evidence
            .filter((item) => item.identityIndex === identityIndex)
            .map(({ id }) => id),
        };
      });
      const report = await suggestOwners(repo.path, [finding], { codex });
      expect(report.results[0]).toMatchObject({
        status: "identified",
        owner: { name, email },
      });
      const { context } = calls[0]!;
      expect(
        context.evidence.some((item) => item.content.includes("façade")),
      ).toBe(true);
      for (const subject of ["Ancienne révision", "Nouvelle révision"])
        expect(
          context.evidence.some((item) => item.content.endsWith(subject)),
        ).toBe(true);
    }
    expect(await repo.git("config", "--get", "i18n.logOutputEncoding")).toBe(
      encoding,
    );
  },
);

test.each(["borrowed-gitfile", "forged-commondir"])(
  "rejects %s before sending another checkout's evidence to Codex",
  async (kind) => {
    const other = await repository();
    const selected = await temporaryDirectory("owner-unbound-");
    const metadata = await other.git("rev-parse", "--absolute-git-dir");
    if (kind === "borrowed-gitfile") {
      await writeFile(join(selected, ".git"), `gitdir: ${metadata}\n`);
    } else {
      await mkdir(join(selected, ".git"));
      await writeFile(
        join(selected, ".git", "HEAD"),
        await readFile(join(metadata, "HEAD")),
      );
      await writeFile(join(selected, ".git", "commondir"), `${metadata}\n`);
      await writeFile(
        join(selected, ".git", "gitdir"),
        `${join(selected, ".git")}\n`,
      );
    }
    const { codex, calls } = fakeCodex();
    await expect(suggestOwners(selected, [finding], { codex })).rejects.toThrow(
      InvalidTargetError,
    );
    expect(calls).toHaveLength(0);
  },
);

test.each(["refs", "refs/heads", "HEAD", "packed-refs"])(
  "rejects borrowed %s before sending another checkout's evidence to Codex",
  async (reference) => {
    const other = await repository();
    const selected = await temporaryDirectory("owner-borrowed-ref-");
    const branch = await other.git("symbolic-ref", "--short", "HEAD");
    await execFile("git", [
      "init",
      "--quiet",
      "--initial-branch",
      branch,
      selected,
    ]);
    const metadata = await other.git("rev-parse", "--absolute-git-dir");
    if (reference === "packed-refs") await other.git("pack-refs", "--all");
    await cp(join(metadata, "objects"), join(selected, ".git", "objects"), {
      recursive: true,
    });
    const target =
      reference === "HEAD" ? join("refs", "heads", branch) : reference;
    const path = join(selected, ".git", reference);
    await rm(path, { recursive: true, force: true });
    await symlink(
      join(metadata, target),
      path,
      reference.startsWith("refs")
        ? process.platform === "win32"
          ? "junction"
          : "dir"
        : "file",
    );
    const { codex, calls } = fakeCodex();
    await expect(suggestOwners(selected, [finding], { codex })).rejects.toThrow(
      InvalidTargetError,
    );
    expect(calls).toHaveLength(0);
  },
);

test.each([
  "absolute-alternate",
  "quoted-relative-alternate",
  "nested-alternate",
  "objects-link",
  "pack-link",
  "alternate-pack-link",
])("rejects %s before collecting another checkout's objects", async (kind) => {
  const other = await repository();
  const selected = await temporaryDirectory("owner-borrowed-objects-");
  await execFile("git", ["init", "--quiet", selected]);
  const objects = join(selected, ".git", "objects");
  const borrowed = join(
    await other.git("rev-parse", "--absolute-git-dir"),
    "objects",
  );
  if (kind.endsWith("link")) {
    if (kind !== "objects-link") await other.git("repack", "-ad");
    let path = kind === "objects-link" ? objects : join(objects, "pack");
    if (kind === "alternate-pack-link") {
      const alternate = join(selected, ".git", "nested-objects");
      await mkdir(alternate);
      await writeFile(join(objects, "info", "alternates"), `${alternate}\n`);
      path = join(alternate, "pack");
    }
    await rm(path, { recursive: true, force: true });
    await symlink(
      kind === "objects-link" ? borrowed : join(borrowed, "pack"),
      path,
      process.platform === "win32" ? "junction" : "dir",
    );
  } else {
    let alternate = borrowed;
    if (kind === "quoted-relative-alternate") {
      alternate = JSON.stringify(relative(objects, borrowed));
    } else if (kind === "nested-alternate") {
      alternate = join(selected, ".git", "nested-objects");
      await mkdir(join(alternate, "info"), { recursive: true });
      await writeFile(join(alternate, "info", "alternates"), `${borrowed}\n`);
    }
    await writeFile(join(objects, "info", "alternates"), `${alternate}\n`);
  }
  // A regular local HEAD is enough to select a commit in the borrowed store.
  await writeFile(join(selected, ".git", "HEAD"), `${other.revision}\n`);
  const { codex, calls } = fakeCodex();
  await expect(suggestOwners(selected, [finding], { codex })).rejects.toThrow(
    InvalidTargetError,
  );
  expect(calls).toHaveLength(0);
});

test.each([
  "linked-worktree",
  "separate-git-directory",
  "source-subdirectory",
  "local-clone",
  "in-tree-alternate",
])("supports a bound %s", async (kind) => {
  const repo = await repository();
  const root = await temporaryDirectory("owner-bound-");
  let selected = repo.path;
  if (kind === "linked-worktree") {
    selected = join(root, "checkout");
    await repo.git("worktree", "add", "--quiet", "--detach", selected);
  } else if (kind === "separate-git-directory") {
    await repo.git("init", "--quiet", "--separate-git-dir", join(root, "git"));
    await repo.git("config", "core.worktree", repo.path);
  } else if (kind === "local-clone") {
    selected = join(root, "checkout");
    await repo.git("clone", "--quiet", repo.path, selected);
  } else if (kind === "in-tree-alternate") {
    const objects = join(repo.path, ".git", "objects");
    const alternate = join(repo.path, ".git", "shared-objects");
    await cp(objects, alternate, { recursive: true });
    await rm(objects, { recursive: true });
    await mkdir(join(objects, "info"), { recursive: true });
    await writeFile(join(objects, "info", "alternates"), `${alternate}\n`);
  } else {
    selected = join(repo.path, "src");
    await mkdir(selected);
  }
  const { codex, calls } = fakeCodex();
  const report = await suggestOwners(selected, [finding], { codex });
  expect(report.revision).toBe(repo.revision);
  expect(report.results[0]).toMatchObject({
    status: "identified",
    owner: { name: "Alex Example", email: "alex@example.test" },
  });
  expect(calls).toHaveLength(1);
});

test("combines source, affected-line authorship, and history through the restricted model runner", async () => {
  const repo = await repository();
  const dirty = "uncommitted source must remain untouched\n";
  await writeFile(join(repo.path, "handler.ts"), dirty);
  await writeFile(
    join(repo.path, ".mailmap"),
    "Imposter <imposter@example.test> Alex Example <alex@example.test>\n",
  );
  const input = structuredClone(finding);
  const { codex, calls } = fakeCodex();
  const signal = new AbortController().signal;
  const report = await suggestOwners(repo.path, [input], {
    codex,
    signal,
    model: "synthetic-model",
    reasoningEffort: "future-effort",
  });
  expect(report).toMatchObject({
    revision: repo.revision,
    model: "synthetic-model",
    reasoningEffort: "future-effort",
    results: [
      {
        findingId: finding.findingId,
        status: "identified",
        owner: { name: "Alex Example", email: "alex@example.test" },
      },
    ],
  });
  expect(
    report.results[0]!.evidence.find(({ kind }) => kind === "blame"),
  ).toMatchObject({
    path: "handler.ts",
    commit: repo.revision,
    startLine: 2,
    endLine: 3,
  });
  expect(
    calls[0]!.context.evidence.find(({ kind }) => kind === "source")!.content,
  ).toContain("return records[id]");
  expect(calls[0]!.context.identities).toHaveLength(2);
  expect(calls[0]!.thread).toMatchObject({
    threadSource: "security_suggest_owners",
    model: "synthetic-model",
    modelReasoningEffort: "future-effort",
    sandboxMode: "read-only",
    approvalPolicy: "never",
    networkAccessEnabled: false,
    webSearchMode: "disabled",
  });
  expect(calls[0]!.turn.signal).toBe(signal);
  expect(await readFile(join(repo.path, "handler.ts"), "utf8")).toBe(dirty);
  expect(input).toEqual(finding);
});

test("abstains without a model call when locations do not identify committed regular source", async () => {
  const repo = await repository();
  await repo.git(
    "update-index",
    "--add",
    "--cacheinfo",
    `120000,${await repo.git("rev-parse", "HEAD:handler.ts")},alias.ts`,
  );
  await writeFile(join(repo.path, "binary.dat"), Buffer.from([0, 1, 2]));
  await repo.git("add", "binary.dat");
  await repo.git("commit", "-qm", "Add non-source entries");
  await writeFile(join(repo.path, "untracked.ts"), "local source");
  const { codex, calls } = fakeCodex();
  const locations = [
    [],
    [{ path: "missing.ts" }],
    [{ path: "../outside.ts" }],
    [{ path: ":(glob)*" }],
    [{ path: "handler.ts", startLine: 100 }],
    [{ path: "alias.ts" }],
    [{ path: "binary.dat" }],
    [{ path: "untracked.ts" }],
  ];
  const report = await suggestOwners(
    repo.path,
    locations.map((locations, index) => ({
      ...finding,
      findingId: `finding-${index}`,
      locations,
    })),
    { codex },
  );
  expect(calls).toHaveLength(0);
  expect(
    report.results.every(
      ({ status, owner, limitations }) =>
        status === "abstained" && owner === null && limitations.length > 0,
    ),
  ).toBe(true);
});

// Keep Unicode coverage even where raw-byte fixture names are unsupported.
for (const rawByteNames of [false, true]) {
  test.skipIf(rawByteNames && ["win32", "darwin"].includes(process.platform))(
    `matches committed ${rawByteNames ? "raw-byte" : "Unicode"} filenames without aliasing replacement characters`,
    async () => {
      const repo = await repository();
      const path = "name-�.ts";
      if (rawByteNames) {
        await writeFile(
          Buffer.concat([
            Buffer.from(join(repo.path, "name-")),
            Buffer.from([0xff]),
            Buffer.from(".ts"),
          ]),
          "export const unrelated = 1;\n",
        );
        await repo.git("add", ".");
        await repo.git("commit", "-qm", "Add raw-byte filename");
      }
      const { codex, calls } = fakeCodex();
      const input = [{ ...finding, locations: [{ path, startLine: 1 }] }];
      const missing = await suggestOwners(repo.path, input, { codex });
      expect(missing.results[0]!.status).toBe("abstained");
      expect(missing.results[0]!.limitations).toContain(
        `Not a regular file at HEAD: ${path}`,
      );
      expect(calls).toHaveLength(0);

      await writeFile(
        join(repo.path, path),
        "export const actualUnicodeFile = 2;\n",
      );
      await repo.git("add", ".");
      await repo.git("commit", "-qm", "Add Unicode filename");
      const report = await suggestOwners(repo.path, input, { codex });
      expect(report.results[0]!.status).toBe("identified");
      expect(
        calls[0]!.context.evidence.find(({ kind }) => kind === "source")!
          .content,
      ).toBe("1: export const actualUnicodeFile = 2;");
      const malformed = await suggestOwners(
        repo.path,
        [{ ...finding, locations: [{ path: "name-\ud800.ts" }] }],
        { codex },
      );
      expect(malformed.results[0]!.status).toBe("abstained");
      expect(calls).toHaveLength(1);

      if (process.platform === "win32") return;
      const tools = await temporaryDirectory();
      const diagnostic = "Permission denied: café/東/😀";
      await writeFile(
        join(tools, "git"),
        `#!/bin/sh
for argument; do
  if [ "$argument" = ls-tree ]; then
    printf '%s\\n' "$SYNTHETIC_GIT_DIAGNOSTIC" >&2
    exit 13
  fi
done
exec "$SYNTHETIC_REAL_GIT" "$@"
`,
        { mode: 0o700 },
      );
      await expect(
        suggestOwners(repo.path, input, {
          codex,
          environment: {
            ...process.env,
            PATH: `${tools}${delimiter}${process.env["PATH"] ?? ""}`,
            SYNTHETIC_REAL_GIT: Bun.which("git")!,
            SYNTHETIC_GIT_DIAGNOSTIC: diagnostic,
          },
        }),
      ).rejects.toThrow(diagnostic);
    },
  );
}

test("keeps renamed-file blame citations at HEAD and inherits SDK model settings", async () => {
  const repo = await repository();
  const path = "record [1].ts";
  await repo.git("mv", "handler.ts", path);
  await repo.git("commit", "-qm", "Rename record handler");
  const { codex, calls } = fakeCodex();
  const report = await suggestOwners(
    repo.path,
    [{ ...finding, locations: [{ path, startLine: 2, endLine: 3 }] }],
    {
      codex,
      config: {
        codexOverrides: {
          model: "configured-model",
          model_reasoning_effort: "low",
        },
      },
    },
  );
  expect(report.results[0]!.status).toBe("identified");
  expect(
    report.results[0]!.evidence.find(({ kind }) => kind === "blame"),
  ).toMatchObject({
    path,
    commit: await repo.git("rev-parse", "HEAD"),
    startLine: 2,
    endLine: 3,
  });
  expect(calls[0]!.thread).toMatchObject({
    model: "configured-model",
    modelReasoningEffort: "low",
  });
  expect(report).toMatchObject({
    model: "configured-model",
    reasoningEffort: "low",
  });
});

test("rejects invented identities and citations and preserves later results", async () => {
  const repo = await repository();
  const invalid: ((context: OwnerContext) => unknown)[] = [
    () => "not JSON",
    (context) => ({
      ...chooseAlex(context),
      identityIndex: context.identities.length,
    }),
    (context) => ({ ...chooseAlex(context), evidenceIds: ["invented"] }),
    (context) => ({ ...chooseAlex(context), evidenceIds: [] }),
    (context) => ({
      ...chooseAlex(context),
      evidenceIds: [
        context.evidence.find(({ identityIndex }) => identityIndex === 1)!.id,
      ],
    }),
    (context) => ({ ...chooseAlex(context), reason: " " }),
    (context) => ({
      ...chooseAlex(context),
      owner: { email: "invented@example.test" },
    }),
  ];
  let index = 0;
  const { codex } = fakeCodex((context) =>
    (invalid[index++] ?? chooseAlex)(context),
  );
  const report = await suggestOwners(
    repo.path,
    Array.from({ length: invalid.length + 1 }, (_, index) => ({
      ...finding,
      findingId: `finding-${index}`,
    })),
    { codex },
  );
  expect(
    report.results
      .slice(0, -1)
      .every(
        ({ status, owner, evidence }) =>
          status === "error" && owner === null && evidence.length === 0,
      ),
  ).toBe(true);
  expect(report.results.at(-1)!.status).toBe("identified");
});

test("ignores stale line ranges, reports shallow history, and preserves model abstentions", async () => {
  const repo = await repository();
  await writeFile(join(repo.path, ".git", "shallow"), `${repo.revision}\n`);
  const { codex, calls } = fakeCodex(() => ({
    identityIndex: -1,
    reason: "History is incomplete.",
    evidenceIds: [],
  }));
  const report = await suggestOwners(
    repo.path,
    [
      {
        ...finding,
        sourceRevision: repo.original,
        locations: [{ path: "handler.ts", startLine: 200 }],
      },
    ],
    { codex },
  );
  expect(calls).toHaveLength(1);
  expect(report.results[0]).toMatchObject({
    status: "abstained",
    owner: null,
    reason: "History is incomplete.",
  });
  expect(report.results[0]!.limitations.join(" ")).toMatch(/shallow/u);
  expect(report.results[0]!.limitations.join(" ")).toMatch(
    /line ranges were not used/u,
  );
  expect(
    calls[0]!.context.evidence.find(({ kind }) => kind === "source"),
  ).toMatchObject({ startLine: 1, endLine: 4 });
});

test("propagates cancellation", async () => {
  const repo = await repository();
  const controller = new AbortController();
  const canceled = fakeCodex(() => {
    controller.abort(new Error("Canceled by caller"));
    throw controller.signal.reason;
  });
  await expect(
    suggestOwners(repo.path, [finding], {
      codex: canceled.codex,
      signal: controller.signal,
    }),
  ).rejects.toThrow("Canceled by caller");
});

test("prioritizes the first committed declared owner without a model call", async () => {
  const repo = await repository();
  await mkdir(join(repo.path, ".github"));
  await mkdir(join(repo.path, "docs"));
  await writeFile(
    join(repo.path, ".github", "CODEOWNERS"),
    "* @default\n/handler.ts @example/maintainers @reviewer alex@example.test\n",
  );
  await writeFile(join(repo.path, "CODEOWNERS"), "* @wrong-root\n");
  await writeFile(join(repo.path, "docs", "CODEOWNERS"), "* @wrong-docs\n");
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owners");
  const revision = await repo.git("rev-parse", "HEAD");
  await writeFile(join(repo.path, ".github", "CODEOWNERS"), "* @uncommitted\n");
  const { codex, calls } = fakeCodex(() => {
    throw new Error("A declared owner does not require a model.");
  });
  const report = await suggestOwners(repo.path, [finding], { codex });
  expect(calls).toHaveLength(0);
  expect(report.revision).toBe(revision);
  expect(report.results[0]).toMatchObject({
    findingId: finding.findingId,
    status: "identified",
    owner: {
      kind: "group",
      provider: "github",
      handle: "example/maintainers",
    },
    evidence: [
      {
        kind: "codeowners",
        path: ".github/CODEOWNERS",
        commit: revision,
        startLine: 2,
        endLine: 2,
        rule: "/handler.ts @example/maintainers @reviewer alex@example.test",
        matchedPath: "handler.ts",
      },
    ],
  });
  expect(report.results[0]!.evidence).toHaveLength(1);
});

test.each([
  ["src/main.ts", "/src/ @alex_corp", "alex_corp", 2],
  [
    "src/main.ts",
    "/src/ @example/maintainers @alex_corp",
    "example/maintainers",
    2,
  ],
  ["lib/main.rb", "***/*.rb @ruby-team", "default", 1],
  ["app/[id]/page.ts", "/app/\\[id\\]/page.ts @routes-team", "routes-team", 2],
] as const)(
  "selects the committed owner for %s using %s",
  async (path, rule, handle, line) => {
    const repo = await repository();
    await mkdir(join(repo.path, dirname(path)), { recursive: true });
    await writeFile(join(repo.path, path), "// Ownership fixture\n");
    await writeFile(join(repo.path, "CODEOWNERS"), `* @default\n${rule}\n`);
    await repo.git("add", ".");
    await repo.git("commit", "-qm", "Declare owners");
    const { codex, calls } = fakeCodex();
    const report = await suggestOwners(
      repo.path,
      [{ ...finding, locations: [{ path }] }],
      { codex },
    );
    expect(report.results[0]).toMatchObject({
      status: "identified",
      owner: { handle },
      evidence: [
        {
          kind: "codeowners",
          startLine: line,
          matchedPath: path,
          commit: report.revision,
          rule: line === 1 ? "* @default" : rule,
        },
      ],
    });
    expect(calls).toHaveLength(0);
  },
);

test("loads CODEOWNERS once per invocation while matching each finding separately", async () => {
  const repo = await repository();
  await writeFile(join(repo.path, "other.ts"), "// Another owned file\n");
  await writeFile(
    join(repo.path, "CODEOWNERS"),
    "/handler.ts @handler-owner\n/other.ts @other-owner\n",
  );
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owners");
  const trace = join(await temporaryDirectory("owner-trace-"), "git.jsonl");
  const { codex, calls } = fakeCodex();
  const options = {
    codex,
    environment: { ...process.env, GIT_TRACE2_EVENT: trace },
  };
  const findings = [
    finding,
    {
      ...finding,
      findingId: "finding-two",
      locations: [{ path: "other.ts" }],
    },
  ];
  const first = await suggestOwners(repo.path, findings, options);
  expect(first.results).toMatchObject([
    {
      owner: { handle: "handler-owner" },
      evidence: [{ matchedPath: "handler.ts", startLine: 1 }],
    },
    {
      owner: { handle: "other-owner" },
      evidence: [{ matchedPath: "other.ts", startLine: 2 }],
    },
  ]);
  await writeFile(join(repo.path, "CODEOWNERS"), "* @new-owner\n");
  await repo.git("commit", "-qam", "Update owners");
  const second = await suggestOwners(repo.path, findings, options);
  expect(second.revision).not.toBe(first.revision);
  expect(second.results.map(({ owner }) => owner)).toEqual([
    { kind: "person", provider: "github", handle: "new-owner" },
    { kind: "person", provider: "github", handle: "new-owner" },
  ]);
  const reads = (await readFile(trace, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as { event: string; argv?: string[] })
    .filter(
      ({ event, argv }) => event === "start" && argv?.includes("cat-file"),
    );
  expect(reads.map(({ argv }) => argv!.at(-1))).toEqual([
    `${first.revision}:CODEOWNERS`,
    `${second.revision}:CODEOWNERS`,
  ]);
  expect(calls).toHaveLength(0);
});

test("reports a lazy CODEOWNERS load failure for each finding", async () => {
  const repo = await repository();
  await writeFile(join(repo.path, "CODEOWNERS"), "* @owner\n");
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owner");
  const blob = await repo.git("rev-parse", "HEAD:CODEOWNERS");
  await rm(join(repo.path, ".git", "objects", blob.slice(0, 2), blob.slice(2)));
  const { codex, calls } = fakeCodex();
  expect((await suggestOwners(repo.path, [], { codex })).results).toEqual([]);
  const report = await suggestOwners(
    repo.path,
    [finding, { ...finding, findingId: "finding-two" }],
    { codex },
  );
  expect(
    report.results.map(({ findingId, status }) => ({ findingId, status })),
  ).toEqual([
    { findingId: finding.findingId, status: "error" },
    { findingId: "finding-two", status: "error" },
  ]);
  expect(report.results[0]!.reason).toContain("cat-file");
  expect(calls).toHaveLength(0);
});

test.each([
  ["@reviewer", { kind: "person", provider: "github", handle: "reviewer" }],
  ["alex@example.test", { kind: "person", email: "alex@example.test" }],
] as const)("returns the declared person %s", async (declaration, owner) => {
  const repo = await repository();
  await writeFile(join(repo.path, "CODEOWNERS"), `* ${declaration}\n`);
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owner");
  const { codex, calls } = fakeCodex();
  const report = await suggestOwners(repo.path, [finding], { codex });
  expect(report.results[0]!.owner).toEqual(owner);
  expect(report.results[0]!.status).toBe("identified");
  expect(calls).toHaveLength(0);
});

test.each(["CODEOWNERS", "docs/CODEOWNERS"])(
  "uses %s when no higher-priority ownership file exists",
  async (path) => {
    const repo = await repository();
    await mkdir(join(repo.path, "docs"));
    await writeFile(join(repo.path, path), "* @example/maintainers\n");
    await repo.git("add", ".");
    await repo.git("commit", "-qm", "Declare owner");
    const report = await suggestOwners(repo.path, [finding]);
    expect(report.results[0]!.evidence[0]!.path).toBe(path);
    expect(report.results[0]!.owner).toEqual({
      kind: "group",
      provider: "github",
      handle: "example/maintainers",
    });
  },
);

test.each([
  "/elsewhere/ @example/maintainers\n",
  "* @default\n/handler.ts\n",
  "/handler.ts invalid-owner\n",
])(
  "falls back to Git when CODEOWNERS has no applicable owner: %s",
  async (source) => {
    const repo = await repository();
    await mkdir(join(repo.path, ".github"));
    await writeFile(join(repo.path, ".github", "CODEOWNERS"), source);
    await writeFile(join(repo.path, "CODEOWNERS"), "* @wrong-root\n");
    await repo.git("add", ".");
    await repo.git("commit", "-qm", "Declare owners");
    const { codex, calls } = fakeCodex();
    const report = await suggestOwners(repo.path, [finding], { codex });
    expect(calls).toHaveLength(1);
    expect(report.results[0]!.status).toBe("identified");
    expect(report.results[0]!.owner).toEqual({
      name: "Alex Example",
      email: "alex@example.test",
    });
    expect(
      report.results[0]!.evidence.every(({ kind }) => kind !== "codeowners"),
    ).toBe(true);
  },
);

test("selects the first affected path with a declared owner", async () => {
  const repo = await repository();
  await writeFile(join(repo.path, "other.ts"), "export const other = 1;\n");
  await writeFile(
    join(repo.path, "CODEOWNERS"),
    "/handler.ts @handler-owner\n/other.ts @other-owner\n",
  );
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owners");
  const report = await suggestOwners(repo.path, [
    {
      ...finding,
      locations: [
        { path: "missing.ts" },
        { path: "other.ts" },
        ...finding.locations,
      ],
    },
  ]);
  expect(report.results[0]!.owner).toEqual({
    kind: "person",
    provider: "github",
    handle: "other-owner",
  });
  expect(report.results[0]!.evidence[0]!.matchedPath).toBe("other.ts");
});

test("ignores a CODEOWNERS symlink and uses the next regular ownership file", async () => {
  const repo = await repository();
  await mkdir(join(repo.path, ".github"));
  await writeFile(join(repo.path, ".github", "CODEOWNERS"), "../CODEOWNERS\n");
  await writeFile(join(repo.path, "CODEOWNERS"), "* @reviewer\n");
  const blob = await repo.git("hash-object", "-w", ".github/CODEOWNERS");
  await repo.git("add", ".");
  await repo.git(
    "update-index",
    "--cacheinfo",
    `120000,${blob},.github/CODEOWNERS`,
  );
  await repo.git("commit", "-qm", "Declare owner through regular file");
  const report = await suggestOwners(repo.path, [finding]);
  expect(report.results[0]!.evidence[0]!.path).toBe("CODEOWNERS");
  expect(report.results[0]!.owner).toEqual({
    kind: "person",
    provider: "github",
    handle: "reviewer",
  });
});

test("ignores CODEOWNERS at GitHub's file-size limit and falls back to Git", async () => {
  const repo = await repository();
  const source = "* @reviewer\n#";
  await writeFile(join(repo.path, "CODEOWNERS"), source.padEnd(3_000_000, "x"));
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owner in oversized file");
  const { codex, calls } = fakeCodex();
  const report = await suggestOwners(repo.path, [finding], { codex });
  expect(calls).toHaveLength(1);
  expect(report.results[0]!.owner).toEqual({
    name: "Alex Example",
    email: "alex@example.test",
  });
  expect(report.results[0]!.limitations.join(" ")).toContain("3 MB");
});

test("matches CODEOWNERS for Unicode repository-relative paths from a subdirectory", async () => {
  const repo = await repository();
  const subdir = join(repo.path, "src");
  await mkdir(subdir);
  await writeFile(join(repo.path, "café.ts"), "export const root = 1;\n");
  await writeFile(join(subdir, "café.ts"), "export const nested = 2;\n");
  await writeFile(
    join(repo.path, "CODEOWNERS"),
    "/café.ts @root-owner\n/src/café.ts @example/nested-team\n",
  );
  await repo.git("add", ".");
  await repo.git("commit", "-qm", "Declare owners for Unicode paths");
  const { codex, calls } = fakeCodex();
  const report = await suggestOwners(
    subdir,
    [
      {
        ...finding,
        findingId: "root-finding",
        locations: [{ path: "café.ts" }],
      },
      {
        ...finding,
        findingId: "nested-finding",
        locations: [{ path: "src/café.ts" }],
      },
    ],
    { codex },
  );
  expect(report.results.map((result) => result.owner)).toEqual([
    { kind: "person", provider: "github", handle: "root-owner" },
    { kind: "group", provider: "github", handle: "example/nested-team" },
  ]);
  expect(
    report.results.map((result) => result.evidence[0]!.matchedPath),
  ).toEqual(["café.ts", "src/café.ts"]);
  expect(calls).toHaveLength(0);
});

test("subdirectory roots retain repository-relative paths when filenames collide", async () => {
  const repo = await repository();
  const subdir = join(repo.path, "src");
  await mkdir(subdir);
  await writeFile(
    join(subdir, "handler.ts"),
    "// Subdirectory handler\nexport function readOther(id) {\n  return other[id];\n}\n",
  );
  await repo.git("add", "src/handler.ts");
  await repo.git(
    "-c",
    "user.name=Casey Example",
    "-c",
    "user.email=casey@example.test",
    "commit",
    "-qm",
    "Add subdirectory handler",
  );
  const { codex, calls } = fakeCodex((context) => {
    const identityIndex = context.identities.findIndex(
      (identity) =>
        identity.email ===
        (context.evidence[0]!.path.startsWith("src/")
          ? "casey@example.test"
          : "alex@example.test"),
    );
    return {
      identityIndex,
      reason: "Author of the affected committed lines.",
      evidenceIds: context.evidence
        .filter((item) => item.identityIndex === identityIndex)
        .map((item) => item.id),
    };
  });
  const report = await suggestOwners(
    subdir,
    [
      finding,
      {
        ...finding,
        findingId: "subdirectory-finding",
        locations: [{ path: "src/handler.ts", startLine: 2, endLine: 3 }],
      },
    ],
    { codex },
  );
  expect(report.results.map((result) => result.owner)).toEqual([
    { name: "Alex Example", email: "alex@example.test" },
    { name: "Casey Example", email: "casey@example.test" },
  ]);
  expect(calls).toHaveLength(2);
});
