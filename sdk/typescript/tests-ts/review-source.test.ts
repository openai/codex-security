import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import {
  ReviewSource,
  ReviewSourceError,
} from "../src/deduplication/review-source.js";

interface SourceFixture {
  root: string;
  repository: string;
  firstRevision: string;
  secondRevision: string;
}

async function sourceFixture(): Promise<SourceFixture> {
  const root = await mkdtemp(join(tmpdir(), "codex-review-source-tool-"));
  const repository = join(root, "repository");
  await mkdir(join(repository, "src"), { recursive: true });
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repository, encoding: "utf8" }).trim();
  git("init", "--quiet");
  await writeFile(
    join(repository, "src", "app.ts"),
    "first line\nhistorical needle\nthird line\n",
  );
  await writeFile(
    join(repository, "src", "large.txt"),
    `${"x".repeat(70 * 1024)}\n`,
  );
  await writeFile(
    join(repository, "src", "matches.txt"),
    Array.from({ length: 120 }, () => "bounded needle").join("\n"),
  );
  git("add", ".");
  git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.test",
    "commit",
    "--quiet",
    "-m",
    "First synthetic revision",
  );
  const firstRevision = git("rev-parse", "HEAD");
  await writeFile(
    join(repository, "src", "app.ts"),
    "first line\ncurrent needle\nthird line\n",
  );
  git("add", ".");
  git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.test",
    "commit",
    "--quiet",
    "-m",
    "Second synthetic revision",
  );
  return {
    root,
    repository,
    firstRevision,
    secondRevision: git("rev-parse", "HEAD"),
  };
}

test("reads and searches historical source without using the working tree", async () => {
  const fixture = await sourceFixture();
  try {
    const source = await ReviewSource.open(fixture.repository);
    expect(
      await source.call("read_file", {
        revision: fixture.firstRevision,
        path: "src/app.ts",
        startLine: 2,
        endLine: 2,
      }),
    ).toEqual({
      revision: fixture.firstRevision,
      path: "src/app.ts",
      startLine: 2,
      endLine: 2,
      content: "historical needle",
      truncated: false,
    });
    expect(
      await source.call("search", {
        revision: fixture.firstRevision,
        query: "historical needle",
        paths: ["src"],
        limit: 10,
      }),
    ).toEqual({
      revision: fixture.firstRevision,
      query: "historical needle",
      matches: [{ path: "src/app.ts", line: 2, text: "historical needle" }],
      truncated: false,
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each([
  ["absolute path", "/etc/passwd"],
  ["parent traversal", "../outside.txt"],
  ["Git metadata", ".git/config"],
  ["nested Git metadata", "src/.GIT/config"],
  ["NUL", "src/app.ts\0outside"],
  ["option", "--help"],
  ["Windows absolute path", "C:\\outside.txt"],
])("rejects %s source paths", async (_name, path) => {
  const fixture = await sourceFixture();
  try {
    const source = await ReviewSource.open(fixture.repository);
    await expect(
      source.call("read_file", {
        revision: fixture.secondRevision,
        path,
      }),
    ).rejects.toThrow();
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("rejects repository and option injection in source requests", async () => {
  const fixture = await sourceFixture();
  try {
    const source = await ReviewSource.open(fixture.repository);
    await expect(
      source.call("read_file", {
        revision: fixture.secondRevision,
        path: "src/app.ts",
        repository: join(fixture.root, "other"),
      }),
    ).rejects.toThrow();
    await expect(
      source.call("search", {
        revision: fixture.secondRevision,
        query: "--cached",
      }),
    ).rejects.toThrow();
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("rejects an external Git object store", async () => {
  const fixture = await sourceFixture();
  const other = join(fixture.root, "other");
  try {
    await mkdir(other);
    execFileSync("git", ["init", "--quiet"], { cwd: other });
    await mkdir(join(fixture.repository, ".git", "objects", "info"), {
      recursive: true,
    });
    await writeFile(
      join(fixture.repository, ".git", "objects", "info", "alternates"),
      `${join(other, ".git", "objects")}\n`,
    );
    const failure = await ReviewSource.open(fixture.repository).catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(ReviewSourceError);
    expect((failure as ReviewSourceError).observation).toEqual({
      kind: "source",
      outcome: "access-unavailable",
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("bounds read bytes, line ranges, search results, and path prefixes", async () => {
  const fixture = await sourceFixture();
  try {
    const source = await ReviewSource.open(fixture.repository);
    expect(
      await source.call("read_file", {
        revision: fixture.secondRevision,
        path: "src/large.txt",
      }),
    ).toMatchObject({ truncated: true });
    await expect(
      source.call("read_file", {
        revision: fixture.secondRevision,
        path: "src/app.ts",
        startLine: 1,
        endLine: 401,
      }),
    ).rejects.toThrow("at most 400 lines");
    expect(
      await source.call("search", {
        revision: fixture.secondRevision,
        query: "bounded needle",
        limit: 3,
      }),
    ).toMatchObject({ truncated: true, matches: [{}, {}, {}] });
    await expect(
      source.call("search", {
        revision: fixture.secondRevision,
        query: "needle",
        paths: Array.from({ length: 21 }, () => "src"),
      }),
    ).rejects.toThrow();

    const inFlight = source.call("read_file", {
      revision: fixture.secondRevision,
      path: "src/app.ts",
    });
    await expect(
      source.call("search", {
        revision: fixture.secondRevision,
        query: "needle",
      }),
    ).rejects.toThrow("already running");
    await expect(inFlight).resolves.toMatchObject({ path: "src/app.ts" });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("classifies missing and changed revisions from host observations", async () => {
  const fixture = await sourceFixture();
  try {
    const source = await ReviewSource.open(fixture.repository);
    const missing = await source
      .call("read_file", {
        revision: "0".repeat(40),
        path: "src/app.ts",
      })
      .catch((error: unknown) => error);
    expect(missing).toBeInstanceOf(ReviewSourceError);
    expect((missing as ReviewSourceError).observation).toEqual({
      kind: "source",
      outcome: "revision-unavailable",
    });

    execFileSync(
      "git",
      [
        "-c",
        "user.name=Example",
        "-c",
        "user.email=example@example.test",
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Changed checkout",
      ],
      { cwd: fixture.repository },
    );
    const changed = await source
      .call("search", {
        revision: fixture.secondRevision,
        query: "needle",
      })
      .catch((error: unknown) => error);
    expect(changed).toBeInstanceOf(ReviewSourceError);
    expect((changed as ReviewSourceError).observation).toEqual({
      kind: "source",
      outcome: "revision-unavailable",
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.skipIf(process.platform === "win32")(
  "classifies Git EACCES as unavailable source access",
  async () => {
    const fixture = await sourceFixture();
    const bin = join(fixture.root, "bin");
    const wrapper = join(bin, "git");
    const git = Bun.which("git");
    expect(git).not.toBeNull();
    try {
      await mkdir(bin);
      await writeFile(wrapper, `#!/bin/sh\nexec ${JSON.stringify(git)} "$@"\n`);
      await chmod(wrapper, 0o755);
      const source = await ReviewSource.open(fixture.repository, {
        ...process.env,
        PATH: bin,
      });
      await chmod(wrapper, 0o644);
      const failure = await source
        .call("read_file", {
          revision: fixture.secondRevision,
          path: "src/app.ts",
        })
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ReviewSourceError);
      expect((failure as ReviewSourceError).observation).toEqual({
        kind: "source",
        outcome: "access-unavailable",
      });
      expect((failure as Error & { cause?: unknown }).cause).toBeDefined();
    } finally {
      await chmod(wrapper, 0o755).catch(() => undefined);
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);
