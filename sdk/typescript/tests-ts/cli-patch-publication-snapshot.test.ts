import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import {
  patchRiskAssessment,
  publicationRepository,
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
  let chunks = 0;
  const output = await runRepositoryCommand(
    "git",
    ["cat-file", "blob", object],
    other,
    {
      environment: {
        GIT_DIR: join(directory, ".git"),
        GIT_WORK_TREE: directory,
      },
      onStdout: (chunk) => {
        chunks++;
        digest.update(chunk);
      },
    },
  );
  expect(output.length).toBe(0);
  expect(chunks).toBeGreaterThan(1);
  expect(digest.digest("hex")).toBe(
    createHash("sha256").update(payload).digest("hex"),
  );
});

test.each(["scrubbed copy", "filtered copy", "independent"])(
  "checks ignored content in the assessed publication snapshot: %s",
  async (mode) => {
    const { directory, git } = await publicationRepository(fixtures);
    const ignored = "SYNTHETIC_IGNORED_CONTENT\n";
    const captured =
      mode === "independent" ? "Synthetic fixed content\n" : ignored;
    const file = "src/finding-1.ts";
    await writeFile(join(directory, ".gitignore"), ".env\n");
    if (mode === "filtered copy") {
      const support = await fixtures.create("patch-publication-filter-");
      const script = join(support, "clean.cjs");
      await writeFile(
        script,
        `const fs = require("node:fs"); const input = fs.readFileSync(0, "utf8"); process.stdout.write(input === "Synthetic filter input\\n" ? ${JSON.stringify(ignored)} : input);\n`,
      );
      git(
        "config",
        "filter.synthetic.clean",
        `node ${JSON.stringify(script.replaceAll("\\", "/"))}`,
      );
      git("config", "filter.synthetic.required", "true");
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
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git")
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          if (args[0] === "push") {
            pushes++;
            return "";
          }
          return runGitRepositoryCommand(command, args, cwd, options);
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
              mode === "filtered copy" ? "Synthetic filter input\n" : captured,
            );
            output!.stdout.write("Synthetic patch complete.\n");
          }
          return 0;
        },
      },
    );
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
