import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
type Flow = "saved patch" | "scan threshold";
type Report =
  "empty" | "unrelated" | "actual" | "directory" | "subset" | "preexisting";

async function checkVerifiedFiles(
  flow: Flow,
  report: Report,
  location:
    "root" | "subdirectory" | "linked root" | "non-Git" | "raw alias" = "root",
) {
  const repository =
    location === "non-Git" ? undefined : await publicationRepository(fixtures);
  const directory =
    repository?.directory ?? (await fixtures.create("verified-files-"));
  if (!repository) {
    await mkdir(join(directory, "src"));
    await writeFile(join(directory, "src/finding-1.ts"), "original\n");
  }
  const git = repository?.git;
  await writeFile(join(directory, "unrelated.ts"), "unrelated baseline\n");
  const raw = Buffer.concat([
    Buffer.from(join(directory, "src", "raw-")),
    Buffer.from([0xff]),
  ]);
  const displayedRaw = "src/raw-\ufffd";
  if (location === "raw alias") {
    await writeFile(raw, "original raw\n");
    await writeFile(
      join(directory, displayedRaw),
      "distinct Unicode baseline\n",
    );
  }
  if (git) {
    git("add", ".");
    git("commit", "-m", "Synthetic verification baseline");
  }
  await writeFile(join(directory, "local.txt"), "staged local work\n");
  git?.("add", "local.txt");
  await writeFile(join(directory, "local.txt"), "unstaged local work\n");
  let target = location === "subdirectory" ? join(directory, "src") : directory;
  if (location === "linked root") {
    const links = await fixtures.create("verified-target-links-");
    target = join(links, "target");
    await symlink(
      directory,
      target,
      process.platform === "win32" ? "junction" : "dir",
    );
  }
  const changedFile =
    report === "preexisting" ? "incidental.ts" : "src/finding-1.ts";
  const reportedActual =
    location === "subdirectory" ? "finding-1.ts" : changedFile;
  const files =
    report === "empty"
      ? []
      : report === "unrelated"
        ? ["unrelated.ts"]
        : report === "preexisting"
          ? ["local.txt"]
          : report === "directory"
            ? ["src"]
            : location === "raw alias"
              ? [displayedRaw]
              : [reportedActual];
  const invalid =
    ["empty", "unrelated", "preexisting"].includes(report) ||
    location === "raw alias";
  const publish =
    flow === "saved patch" &&
    repository !== undefined &&
    location !== "linked root";
  const head = git?.("rev-parse", "HEAD");
  const refs = git?.("ls-remote", "origin");
  const indexPath = git?.(
    "rev-parse",
    "--path-format=absolute",
    "--git-path",
    "index",
  );
  let indexBefore: Buffer<ArrayBuffer> | undefined;
  let turns = 0;
  let publications = 0;
  const result = resultWithFindings(["high"]);
  result.findings.findings[0]!.locations[0]!.path =
    location === "subdirectory" ? "finding-1.ts" : "src/finding-1.ts";
  const outcome = await runWorkflow(
    [
      ...(flow === "saved patch"
        ? ["patch", "--scan", "scan-1"]
        : ["scan", "--patch", "--fail-on-severity", "high"]),
      ...(publish ? ["--create-pr"] : []),
      "--json",
    ],
    {
      currentDirectory: target,
      result,
      onWorkbench: () => savedScan(result, "scan-1", target),
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command === "git")
          return runGitRepositoryCommand(command, args, cwd, options);
        if (args[1] === "create") publications++;
        return args[1] === "list"
          ? "[]"
          : "https://github.example.test/example/repository/pull/1";
      },
      onCodex: async (_args, output) => {
        turns++;
        if (indexPath) indexBefore = await readFile(indexPath);
        await writeFile(
          location === "raw alias" ? raw : join(directory, changedFile),
          "verified edit\n",
        );
        if (report === "subset")
          await writeFile(
            join(directory, "extra.ts"),
            "unreported turn edit\n",
          );
        output?.stdout.write(
          JSON.stringify({
            patches: [
              {
                occurrenceId: "occ_1",
                status: "verified",
                files,
                verification: "Synthetic focused verification passed.",
              },
            ],
          }),
        );
        return 0;
      },
    },
  );
  expect(turns).toBe(1);
  expect(outcome.exitCode, outcome.stderr).toBe(invalid ? 2 : 0);
  const value = JSON.parse(outcome.stdout);
  expect(value.patches[0]).toMatchObject(
    invalid
      ? {
          occurrenceId: "occ_1",
          status: "failed",
          reason: "Patch verification did not identify any changed files.",
        }
      : { occurrenceId: "occ_1", status: "verified", files },
  );
  if (invalid && flow === "saved patch")
    expect(value.error.code).toBe("PATCH_FAILED");
  expect(publications).toBe(!invalid && publish ? 1 : 0);
  if (invalid || !publish) {
    expect(value).not.toHaveProperty("pullRequest");
    if (git && indexPath) {
      expect(git("rev-parse", "HEAD")).toBe(head!);
      expect(git("branch", "--show-current")).toBe("main");
      expect(git("ls-remote", "origin")).toBe(refs!);
      expect(await readFile(indexPath)).toEqual(indexBefore!);
    }
  } else if (git) {
    expect(git("show", `HEAD:${changedFile}`)).toBe("verified edit");
    expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
    if (report === "subset")
      expect(git("ls-tree", "HEAD", "extra.ts")).toBe("");
  }
  if (git) expect(git("show", ":local.txt")).toBe("staged local work");
  expect(await readFile(join(directory, "local.txt"), "utf8")).toBe(
    "unstaged local work\n",
  );
  expect(
    await readFile(
      location === "raw alias" ? raw : join(directory, changedFile),
      "utf8",
    ),
  ).toBe("verified edit\n");
  if (report === "subset")
    expect(await readFile(join(directory, "extra.ts"), "utf8")).toBe(
      "unreported turn edit\n",
    );
  if (location === "raw alias")
    expect(await readFile(join(directory, displayedRaw), "utf8")).toBe(
      "distinct Unicode baseline\n",
    );
}

for (const flow of ["saved patch", "scan threshold"] as const) {
  test.each([
    "empty",
    "unrelated",
    "actual",
    "directory",
    "subset",
    "preexisting",
  ] as const)(
    `${flow} verifies reported %s paths against the current turn`,
    async (report) => checkVerifiedFiles(flow, report),
  );
}
test("saved patch matches changes beneath a scanned Git subdirectory", async () =>
  checkVerifiedFiles("saved patch", "actual", "subdirectory"));
test("saved patch matches changes through a linked target root", async () =>
  checkVerifiedFiles("saved patch", "actual", "linked root"));
test.each(["empty", "actual"] as const)(
  "scan threshold verifies %s paths without Git",
  async (report) => checkVerifiedFiles("scan threshold", report, "non-Git"),
);
test.skipIf(process.platform !== "linux")(
  "scan threshold distinguishes raw Git paths from a Unicode filename",
  async () => checkVerifiedFiles("scan threshold", "actual", "raw alias"),
);
