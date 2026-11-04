import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import {
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test("streams captured blob bytes through the selected Git context", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  const payload = Buffer.alloc(4 * 1024 * 1024, 0xff);
  const file = join(directory, "blob.bin");
  await writeFile(file, payload);
  const object = git("hash-object", "-w", file);
  const other = await fixtures.create("patch-blob-caller-");
  const digest = createHash("sha256");
  const output = await runRepositoryCommand(
    "git",
    ["cat-file", "blob", object],
    other,
    {
      maxBuffer: 1024,
      environment: {
        GIT_DIR: join(directory, ".git"),
        GIT_WORK_TREE: directory,
      },
      onStdout: (chunk) => digest.update(chunk),
    },
  );
  expect(output.length).toBe(0);
  expect(digest.digest("hex")).toBe(
    createHash("sha256").update(payload).digest("hex"),
  );
});

test.each(["scrubbed copy", "filtered copy", "transform", "independent"])(
  "checks ignored content in the assessed publication snapshot: %s",
  async (mode) => {
    const { directory, git } = await publicationRepository(fixtures);
    const ignored = "SYNTHETIC_IGNORED_CONTENT\n";
    const captured =
      mode === "independent" ? "Synthetic fixed content\n" : ignored;
    const file = "src/finding-1.ts";
    await writeFile(join(directory, ".gitignore"), ".env\n");
    const filtered = mode === "filtered copy" || mode === "transform";
    const environment: NodeJS.ProcessEnv = {};
    if (filtered) {
      const support = await fixtures.create("patch-publication-filter-");
      const script = join(support, "clean.cjs");
      const output =
        mode === "transform"
          ? Buffer.from(ignored).toString("base64")
          : ignored;
      await writeFile(
        script,
        `const fs = require("node:fs"); const input = fs.readFileSync(0, "utf8"); process.stdout.write(input === "Synthetic filter input\\n" ? ${JSON.stringify(output)} : input);\n`,
      );
      const configuration: string[] = [];
      if (mode === "filtered copy") {
        const global = join(support, "global");
        environment["GIT_CONFIG_GLOBAL"] = global;
        configuration.push("--file", global);
      }
      git(
        "config",
        ...configuration,
        "filter.synthetic.clean",
        `node ${JSON.stringify(script.replaceAll("\\", "/"))}`,
      );
      git("config", ...configuration, "filter.synthetic.required", "true");
      await writeFile(
        join(directory, ".gitattributes"),
        `${file} filter=synthetic\n`,
      );
    }
    git("add", ".");
    git("commit", "-m", "Synthetic publication baseline");
    await writeFile(join(directory, ".env"), ignored);
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    let assessments = 0;
    let pushes = 0;
    const outcome = await runWorkflow(
      [
        "patch",
        "Synthetic issue",
        "--assess-patch-risk",
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: directory,
        environment,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git")
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          if (args[0] === "push") {
            pushes++;
            return "";
          }
          return runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
        onCodex: async (_args, output) => {
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            assessments++;
            await writeFile(
              join(directory, file),
              "Synthetic scrubbed working copy\n",
            );
            output!.stdout.write(patchRiskAssessment().report);
          } else {
            await writeFile(
              join(directory, file),
              filtered ? "Synthetic filter input\n" : captured,
            );
            output!.stdout.write("Synthetic patch complete.\n");
          }
          return 0;
        },
      },
    );
    if (mode === "transform") {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("checkout-selected Git filter");
      expect(assessments).toBe(0);
      expect(pushes).toBe(0);
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(directory, file), "utf8")).toBe("original\n");
      return;
    }
    expect(assessments).toBe(1);
    expect(outcome.exitCode, outcome.stderr).toBe(
      mode === "independent" ? 0 : 2,
    );
    if (mode === "independent") {
      expect(pushes).toBe(1);
      expect(git("show", `HEAD:${file}`)).toBe(captured.trim());
    } else {
      expect(outcome.stderr).toContain("matches pre-existing ignored content");
      expect(pushes).toBe(0);
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
    }
    expect(await readFile(join(directory, file), "utf8")).toBe(
      "Synthetic scrubbed working copy\n",
    );
  },
);

test.each(["root", "nested", "disabled"])(
  "checks clean filters before the publication snapshot: %s",
  async (mode) => {
    const { directory, git } = await publicationRepository(fixtures);
    const checkout = mode === "nested" ? join(directory, "child") : directory;
    const selected = repositoryGit(checkout);
    if (mode === "nested") {
      await mkdir(checkout);
      selected("init", "--initial-branch=main");
      selected("config", "user.name", "Synthetic User");
      selected("config", "user.email", "synthetic@example.test");
    }
    selected("config", "filter.passthrough.clean", "cat");
    if (mode === "disabled")
      selected("config", "--add", "filter.passthrough.clean", "");
    await writeFile(
      join(checkout, ".gitattributes"),
      "plain.txt filter=passthrough\n",
    );
    await writeFile(join(checkout, ".gitignore"), "local-note.txt\n");
    await writeFile(join(checkout, "plain.txt"), "Plain fixture.\n");
    selected("add", ".gitattributes", ".gitignore", "plain.txt");
    selected("commit", "-m", "Configure a pass-through clean filter");
    if (mode === "nested") {
      git("add", "child");
      git("commit", "-m", "Track the child repository");
    }
    await writeFile(join(checkout, "local-note.txt"), "Ordinary local note.\n");
    const operations: string[] = [];
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onRepositoryCommand(command, args, cwd, options) {
          if (command !== "git")
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          for (const operation of ["add", "status", "push"])
            if (args.includes(operation)) operations.push(operation);
          if (args[0] === "push") return "";
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        async onCodex(_args, output) {
          operations.push("model");
          await writeFile(
            join(directory, "src/finding-1.ts"),
            "Independent edit.\n",
          );
          output!.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
    );
    if (mode === "disabled") {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(operations).toContain("push");
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("Independent edit.");
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(operations).toEqual([]);
    }
  },
);
