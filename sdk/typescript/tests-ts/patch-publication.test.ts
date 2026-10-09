import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  createGitLabPatchPublisher,
  publishPatchReview,
  resolvePatchReviewPublisher,
  type PatchReviewPublisher,
} from "../src/patch-publication.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const request = {
  branch: "patch/example",
  title: "Fix a synthetic issue",
  body: "Verified with a synthetic regression test.",
};

test("publishes a local Git branch using a separate review project and browser URL", async () => {
  const root = await temporaryDirectory("patch-publication-");
  const repository = join(root, "working tree");
  const transport = join(root, "bare remote.git");
  const output = join(root, "provider output");
  const project = "https://forge.example.test/team/subgroup/project.git";
  const url = "https://reviews.example.test/review/42";
  const events: string[] = [];
  const git = (...args: string[]) =>
    execFileSync("git", args, {
      cwd: repository,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  try {
    await mkdir(repository);
    await mkdir(output);
    git("init", "--initial-branch=main");
    git("init", "--bare", transport);
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    git(
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--allow-empty",
      "-m",
      "Fixture",
    );
    git("checkout", "-b", request.branch);
    git("remote", "add", "origin", transport);

    const client = join(output, "review-client.mjs");
    await writeFile(
      client,
      `import assert from "node:assert/strict";
const [serialized, project, url] = process.argv.slice(2);
const args = JSON.parse(serialized);
assert.equal(args[0], "mr");
assert.equal(args[args.indexOf("--repo") + 1], project);
if (args[1] === "create") {
  assert.equal(args[args.indexOf("--head") + 1], project);
  process.stdout.write(url);
} else {
  assert.equal(args[1], "list");
}
`,
    );
    const publisher = createGitLabPatchPublisher({
      project,
      run: async (command, args) => {
        expect(command).toBe("glab");
        events.push(args[1]!);
        if (args[1] === "create")
          expect(git("--git-dir", transport, "rev-parse", request.branch)).toBe(
            git("rev-parse", "HEAD"),
          );
        return execFileSync(
          process.execPath,
          [client, JSON.stringify(args), project, url],
          { encoding: "utf8" },
        );
      },
    });

    const result = await publishPatchReview({
      ...request,
      publisher,
      pushBranch: async (branch) => {
        events.push("push");
        git("push", "--set-upstream", "origin", branch);
      },
    });

    expect(result).toBe(url);
    expect(git("remote", "get-url", "--push", "origin")).toBe(transport);
    expect(events).toEqual(["list", "push", "create"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("reuses an existing review without pushing or creating another", async () => {
  const events: string[] = [];
  const url = "https://reviews.example.test/review/42";
  const result = await publishPatchReview({
    ...request,
    publisher: {
      label: "Review request",
      findExisting: async (branch) => {
        events.push(`find ${branch}`);
        return url;
      },
      createDraft: async () => {
        events.push("create");
        return "";
      },
    },
    pushBranch: async () => {
      events.push("push");
    },
  });
  expect(result).toBe(url);
  expect(events).toEqual([`find ${request.branch}`]);
});

test("stops before pushing when review lookup fails", async () => {
  const failure = new Error("Synthetic review service unavailable");
  const events: string[] = [];
  await expect(
    publishPatchReview({
      ...request,
      publisher: {
        label: "Review request",
        findExisting: async () => {
          events.push("find");
          throw failure;
        },
        createDraft: async () => {
          events.push("create");
          return "";
        },
      },
      pushBranch: async () => {
        events.push("push");
      },
    }),
  ).rejects.toBe(failure);
  expect(events).toEqual(["find"]);
});

test("rechecks the provider after a create response is lost", async () => {
  const url = "https://reviews.example.test/review/42";
  const failure = new Error("Synthetic connection closed after creation");
  let existing = "";
  const events: string[] = [];
  const publisher: PatchReviewPublisher = {
    label: "Review request",
    findExisting: async (branch) => {
      expect(branch).toBe(request.branch);
      events.push("find");
      return existing;
    },
    createDraft: async (received) => {
      expect(received).toEqual(request);
      events.push("create");
      existing = url;
      throw failure;
    },
  };
  const options = {
    ...request,
    publisher,
    pushBranch: async (branch: string) => {
      expect(branch).toBe(request.branch);
      events.push("push");
    },
  };

  await expect(publishPatchReview(options)).rejects.toBe(failure);
  expect(await publishPatchReview(options)).toBe(url);
  expect(events).toEqual(["find", "push", "create", "find"]);
});

test("keeps native gh repository resolution for an unrecognized remote host", async () => {
  const url = "https://forge.example.test/team/project/pull/42";
  const calls: Array<readonly string[]> = [];
  const publisher = resolvePatchReviewPublisher(
    "ssh://git@forge.example.test/team/project.git",
    {},
    async (command, args) => {
      expect(command).toBe("gh");
      calls.push(args);
      return args[1] === "create" ? url : "";
    },
  );
  expect(await publisher.findExisting(request.branch)).toBe("");
  expect(await publisher.createDraft(request)).toBe(url);
  expect(calls.map((args) => args.slice(0, 2))).toEqual([
    ["pr", "list"],
    ["pr", "create"],
  ]);
  for (const args of calls) expect(args).not.toContain("--repo");
  const create = calls[1]!;
  expect(create[create.indexOf("--body") + 1]).toBe(request.body);
});
