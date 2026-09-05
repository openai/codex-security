import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  inspectSecurityPolicyPaths,
  readSecurityPolicy,
  resolveSecurityPolicyGuidance,
  resolveSecurityPolicyTarget,
  securityPolicyDiff,
  securityPolicyProtectedRoots,
  type SecurityPolicyStage,
} from "../src/security-policy.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { preparePersistentOutputRoot } from "../src/runtime.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import {
  POLICY,
  PYTHON,
  addPolicySubmodule,
  policyFixture,
  policyGit,
  stageResult,
} from "./support/security-policy.js";

const fixtures: Awaited<ReturnType<typeof policyFixture>>[] = [];
async function fixture() {
  const value = await policyFixture();
  fixtures.push(value);
  return value;
}
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((value) => value.cleanup()));
});

describe("security policy generation", () => {
  test("stores policy drafts separately from scans and rejects linked state children", async () => {
    const f = await fixture();
    const state = join(f.root, "state");
    const directory = await preparePersistentOutputRoot(
      state,
      "policies",
      "sample project",
    );
    expect(directory).toBe(join(state, "policies", "sample-project"));
    if (process.platform !== "win32")
      expect((await stat(directory)).mode & 0o777).toBe(0o700);
    await symlink(
      f.repository,
      join(state, "policies", "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      preparePersistentOutputRoot(state, "policies", "linked"),
    ).rejects.toThrow("Persistent policy output must use real directories");
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("keeps architecture, threat model, and policy separate and leaves source unchanged", async () => {
    const f = await fixture();
    const original = "# Existing policy\n\nReport privately.\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const reportingPolicy = join(f.repository, ".github", "SECURITY.md");
    await mkdir(join(f.repository, ".github"));
    await symlink("../SECURITY.md", reportingPolicy, "file");
    const stages: SecurityPolicyStage[] = [];
    const prompts: string[] = [];
    const draft = await f.generate({
      answerQuestions: async (questions) => {
        expect(questions).toEqual(["Is this service internet-facing?"]);
        return "Only authenticated clients can reach it.";
      },
      run: async (stage, prompt) => {
        stages.push(stage);
        prompts.push(prompt);
        if (stage === "threat_model")
          expect(
            await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
          ).toContain("src/service.ts:1");
        if (stage === "policy")
          expect(
            await readFile(join(f.outputDir, "THREAT_MODEL.md"), "utf8"),
          ).toContain("src/service.ts:1");
        return stageResult(stage);
      },
    });
    expect(stages).toEqual(["architecture", "threat_model", "policy"]);
    expect(prompts[0]).toContain("Synthetic inherited guidance");
    expect(prompts[1]).toContain("Only authenticated clients can reach it.");
    expect(prompts[2]).toContain("Only authenticated clients can reach it.");
    expect(await readFile(draft.targetPath, "utf8")).toBe(original);
    expect(await readFile(reportingPolicy, "utf8")).toBe(original);
    expect(draft.previousContent).toBe(original);
    expect(await readFile(draft.draftPath, "utf8")).toBe(POLICY);
    if (process.platform !== "win32")
      expect((await stat(draft.draftPath)).mode & 0o777).toBe(0o600);
  });

  test("keeps generated artifacts readable and editable under a restrictive umask", async () => {
    if (
      runTestInSubprocess(
        import.meta.path,
        "keeps generated artifacts readable and editable under a restrictive umask",
      )
    )
      return;
    const f = await fixture();
    const previous = process.umask(0o600);
    try {
      await f.generate({
        run: async (stage) => {
          if (stage !== "architecture")
            expect(
              await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
            ).toContain("src/service.ts:1");
          return stageResult(stage);
        },
      });
    } finally {
      process.umask(previous);
    }
    for (const name of await readdir(f.outputDir)) {
      const path = join(f.outputDir, name);
      expect((await stat(path)).mode & 0o600).toBe(0o600);
      if (process.platform !== "win32")
        expect((await stat(path)).mode & 0o077).toBe(0);
      await writeFile(path, await readFile(path));
    }
  });

  test("infers the Git root while keeping a component as the policy scope", async () => {
    const f = await fixture();
    execFileSync("git", ["init", "--quiet", f.repository]);
    const component = join(f.repository, "services", "api");
    await mkdir(component, { recursive: true });
    await writeFile(
      join(f.repository, "SECURITY.md"),
      "# Root policy\nRoot invariant.\n",
    );
    const target = await resolveSecurityPolicyTarget(component);
    expect(target).toEqual({
      repository: f.repository,
      scope: "services/api",
      targetPath: join(component, "SECURITY.md"),
    });
    expect(
      await resolveSecurityPolicyGuidance(target, PYTHON, PLUGIN_ROOT),
    ).toContain("Root invariant.");
    expect(
      await resolveSecurityPolicyTarget(f.repository, "services/api"),
    ).toEqual(target);
  });

  test("rejects a nested checkout that is re-rooted after target resolution", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    const nested = join(f.repository, "nested");
    await mkdir(nested);
    policyGit(nested, "init", "--quiet");
    const target = await resolveSecurityPolicyTarget(nested);

    await rm(join(nested, ".git"), { recursive: true, force: true });

    await expect(securityPolicyProtectedRoots(target)).rejects.toThrow(
      "Git metadata changed",
    );
  });

  test("does not complete a draft after its Git binding changes during generation", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    await expect(
      f.generate({
        run: async (stage) => {
          if (stage === "policy")
            await rename(
              join(f.repository, ".git"),
              join(f.root, "previous-git"),
            );
          return stageResult(stage);
        },
      }),
    ).rejects.toThrow("Git metadata changed");
    expect((await readdir(f.outputDir)).sort()).toEqual([
      "SECURITY.md",
      "THREAT_MODEL.md",
      "previous-SECURITY.md",
      "project-spec.md",
    ]);
  });

  test("rejects Git configuration that redirects the selected checkout", async () => {
    for (const indirect of [false, true]) {
      for (const location of ["sibling", "ancestor"]) {
        const f = await fixture();
        const outside = join(f.root, "outside");
        await mkdir(outside);
        execFileSync("git", [
          "init",
          "--quiet",
          ...(indirect ? ["--separate-git-dir", join(f.root, "git-data")] : []),
          f.repository,
        ]);
        execFileSync("git", [
          "-C",
          f.repository,
          "config",
          "core.worktree",
          location === "sibling" ? outside : f.root,
        ]);
        await expect(resolveSecurityPolicyTarget(f.repository)).rejects.toThrow(
          "does not match the selected checkout",
        );
        expect(await readdir(f.outputDir)).toEqual([]);
      }
    }
  });

  test("requires a worktree binding for a separate Git directory outside the checkout", async () => {
    for (const external of [false, true]) {
      const f = await fixture();
      const metadata = join(external ? f.root : f.repository, "git-data");
      policyGit(
        f.repository,
        "init",
        "--quiet",
        "--separate-git-dir",
        metadata,
      );
      if (external) {
        await expect(resolveSecurityPolicyTarget(f.repository)).rejects.toThrow(
          "core.worktree",
        );
        policyGit(f.repository, "config", "core.worktree", f.repository);
      }
      expect(await resolveSecurityPolicyTarget(f.repository)).toEqual({
        repository: f.repository,
        scope: ".",
        targetPath: join(f.repository, "SECURITY.md"),
      });
    }
  });

  test("rejects policy targets inside Git metadata", async () => {
    for (const kind of ["traditional", "separate", "bare"]) {
      const f = await fixture();
      const metadata =
        kind === "traditional"
          ? join(f.repository, ".git")
          : join(f.root, "git-data");
      execFileSync("git", [
        "init",
        "--quiet",
        ...(kind === "bare"
          ? ["--bare", metadata]
          : [
              ...(kind === "separate" ? ["--separate-git-dir", metadata] : []),
              f.repository,
            ]),
      ]);
      const refs = join(metadata, "refs", "heads");
      await expect(resolveSecurityPolicyTarget(refs)).rejects.toThrow(
        "inside Git metadata",
      );
      await expect(
        resolveSecurityPolicyTarget(metadata, "refs/heads"),
      ).rejects.toThrow("inside Git metadata");
      if (kind === "traditional")
        await expect(
          resolveSecurityPolicyTarget(f.repository, ".git/refs/heads"),
        ).rejects.toThrow("inside Git metadata");
      expect(await readdir(refs)).toEqual([]);
    }
  });

  test("excludes separately named Git directories from policy discovery", async () => {
    for (const nested of [false, true]) {
      const f = await fixture();
      const checkout = nested ? join(f.repository, "a-checkout") : f.repository;
      const metadata = join(f.repository, nested ? "docs" : ".metadata");
      if (nested) {
        policyGit(f.repository, "init", "--quiet");
        await mkdir(checkout);
      }
      policyGit(checkout, "init", "--quiet", "--separate-git-dir", metadata);
      if (nested) policyGit(checkout, "config", "core.worktree", checkout);
      await writeFile(join(f.repository, "SECURITY.md"), POLICY);
      if (nested) await writeFile(join(checkout, "SECURITY.md"), POLICY);
      await writeFile(join(metadata, "SECURITY.md"), "Not policy guidance\n");
      await writeFile(
        join(metadata, "refs", "heads", "SECURITY.md"),
        "Not policy guidance\n",
      );
      expect(
        await inspectSecurityPolicyPaths(
          await resolveSecurityPolicyTarget(f.repository),
        ),
      ).toEqual(
        nested ? ["SECURITY.md", "a-checkout/SECURITY.md"] : ["SECURITY.md"],
      );
    }
  });

  test("keeps linked worktrees and submodules as their own policy roots", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    policyGit(
      f.repository,
      "commit",
      "--allow-empty",
      "--quiet",
      "-m",
      "initial",
    );
    const linked = join(f.root, "linked-worktree");
    policyGit(
      f.repository,
      "worktree",
      "add",
      "--quiet",
      "--detach",
      linked,
      "HEAD",
    );
    await mkdir(join(linked, "component"));
    expect(
      await resolveSecurityPolicyTarget(join(linked, "component")),
    ).toEqual({
      repository: linked,
      scope: "component",
      targetPath: join(linked, "component", "SECURITY.md"),
    });
    const linkedMetadata = execFileSync(
      "git",
      ["-C", linked, "rev-parse", "--absolute-git-dir"],
      { encoding: "utf8" },
    ).trim();
    const backlink = join(linkedMetadata, "gitdir");
    const originalBacklink = await readFile(backlink);
    await writeFile(
      backlink,
      `${relative(linkedMetadata, join(linked, ".git"))}\n`,
    );
    expect((await resolveSecurityPolicyTarget(linked)).repository).toBe(linked);
    await writeFile(backlink, originalBacklink);
    const submodule = await addPolicySubmodule(
      f.repository,
      join(f.root, "submodule-source"),
    );
    await writeFile(join(f.repository, "SECURITY.md"), "# Parent policy\n");
    await writeFile(join(submodule, "SECURITY.md"), "# Submodule policy\n");
    const direct = await resolveSecurityPolicyTarget(submodule);
    expect(direct).toEqual({
      repository: submodule,
      scope: ".",
      targetPath: join(submodule, "SECURITY.md"),
    });
    expect(
      await resolveSecurityPolicyTarget(f.repository, "services/api"),
    ).toEqual(direct);
    const guidance = await resolveSecurityPolicyGuidance(
      direct,
      PYTHON,
      PLUGIN_ROOT,
    );
    expect(guidance).toContain("Submodule policy");
    expect(guidance).not.toContain("Parent policy");
    await mkdir(join(submodule, "component"));
    expect(
      await resolveSecurityPolicyTarget(f.repository, "services/api/component"),
    ).toEqual({
      repository: submodule,
      scope: "component",
      targetPath: join(submodule, "component", "SECURITY.md"),
    });
  });

  test("does not silently drop inherited policies when Git is unavailable", async () => {
    const name =
      "does not silently drop inherited policies when Git is unavailable";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const checkout = await fixture();
    const standalone = await fixture();
    execFileSync("git", ["init", "--quiet", checkout.repository]);
    const component = join(checkout.repository, "component");
    await mkdir(component);
    await writeFile(join(checkout.repository, "SECURITY.md"), POLICY);
    const pathEntries = Object.entries(process.env).filter(
      ([key]) => key.toUpperCase() === "PATH",
    );
    try {
      for (const [key] of pathEntries) delete process.env[key];
      process.env["PATH"] = "";
      await expect(resolveSecurityPolicyTarget(component)).rejects.toThrow(
        "Could not determine the Git worktree root",
      );
      expect(
        (await resolveSecurityPolicyTarget(standalone.repository)).repository,
      ).toBe(standalone.repository);
    } finally {
      delete process.env["PATH"];
      for (const [key, value] of pathEntries) process.env[key] = value;
    }
  });

  test("asks every material owner question in groups of at most three", async () => {
    const f = await fixture();
    const questions = [
      "Which endpoints are public?",
      "Who can deploy the service?",
      "Who can read backups?",
      "Which operators are trusted?",
      "Are tenants isolated?",
      "Who controls the identity provider?",
      "Which data needs retention limits?",
    ];
    const batches: string[][] = [];
    const draft = await f.generate({
      answerQuestions: async (batch) => {
        batches.push([...batch]);
        return ["yes", undefined, "no"][batches.length - 1];
      },
      run: async (stage, prompt) => {
        if (stage === "architecture")
          return { ...stageResult(stage), questions };
        for (const question of questions) expect(prompt).toContain(question);
        expect(prompt).toContain(
          JSON.stringify([
            { questions: questions.slice(0, 3), answer: "yes" },
            { questions: questions.slice(6), answer: "no" },
          ]),
        );
        return stageResult(stage);
      },
    });
    expect(batches).toEqual([
      questions.slice(0, 3),
      questions.slice(3, 6),
      questions.slice(6),
    ]);
    for (const question of questions)
      expect(draft.reviewNotes).toContain(question);
  });

  test("carries unanswered questions and review decisions into the final policy", async () => {
    const f = await fixture();
    const draft = await f.generate({
      run: async (stage, prompt) => {
        if (stage === "architecture") {
          return {
            ...stageResult(stage),
            questions: ["Who can deploy the service?"],
            reviewNotes: ["Confirm the operator trust boundary."],
          };
        }
        expect(prompt).toContain("Who can deploy the service?");
        expect(prompt).toContain("Confirm the operator trust boundary.");
        if (stage === "threat_model") {
          return {
            ...stageResult(stage),
            questions: ["Are backups isolated by tenant?"],
            reviewNotes: ["Review backup access."],
          };
        }
        expect(prompt).toContain("Are backups isolated by tenant?");
        expect(prompt).toContain("Review backup access.");
        return {
          ...stageResult(stage),
          questions: ["Confirm backup isolation."],
          reviewNotes: [
            "Review deployment scope.",
            "Confirm backup isolation.",
          ],
        };
      },
    });
    expect(draft.reviewNotes).toEqual([
      "Review deployment scope.",
      "Confirm backup isolation.",
      "Confirm the operator trust boundary.",
      "Who can deploy the service?",
      "Review backup access.",
      "Are backups isolated by tenant?",
    ]);
    expect(
      JSON.parse(await readFile(join(f.outputDir, "policy-draft.json"), "utf8"))
        .reviewNotes,
    ).toEqual(draft.reviewNotes);
  });

  test("rejects files, outside paths, and outside directory links", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "source.ts"), "export {};\n");
    await symlink(
      f.outputDir,
      join(f.repository, "external"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      resolveSecurityPolicyTarget(f.repository, "source.ts"),
    ).rejects.toThrow("must be a directory");
    await expect(
      resolveSecurityPolicyTarget(f.repository, ".."),
    ).rejects.toThrow("outside the repository");
    await expect(
      resolveSecurityPolicyTarget(f.repository, "external"),
    ).rejects.toThrow("outside the repository");
  });

  test("retains completed evidence when a later stage is interrupted", async () => {
    const f = await fixture();
    const controller = new AbortController();
    await expect(
      f.generate({
        signal: controller.signal,
        run: async (stage) => {
          if (stage === "threat_model") controller.abort(new Error("stop"));
          return stageResult(stage);
        },
      }),
    ).rejects.toThrow("stop");
    expect(
      await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
    ).toContain("src/service.ts:1");
    expect(await readdir(f.repository)).toEqual([]);
    expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
  });

  test("retains completed evidence without saving invalid policy documents", async () => {
    for (const markdown of [
      "",
      " \n\t",
      "# Policy\n\ud800",
      `# Policy\n${"x".repeat(1024 * 1024)}`,
    ]) {
      const f = await fixture();
      await expect(
        f.generate({
          run: async (stage) => ({
            ...stageResult(stage),
            ...(stage === "policy" ? { markdown } : {}),
          }),
        }),
      ).rejects.toThrow();
      expect(await readdir(f.repository)).toEqual([]);
      expect((await readdir(f.outputDir)).sort()).toEqual([
        "THREAT_MODEL.md",
        "previous-SECURITY.md",
        "project-spec.md",
      ]);
    }
  });

  test("enforces the resolver byte limit on existing policies", async () => {
    const header = "# Policy\n";
    const maximum =
      header + "x".repeat(1024 * 1024 - Buffer.byteLength(header));
    const existing = await fixture();
    const target = join(existing.repository, "SECURITY.md");
    await writeFile(target, maximum);
    expect(await readSecurityPolicy(target)).toBe(maximum);
    await writeFile(target, `${maximum}x`);
    await expect(existing.generate()).rejects.toThrow("1 MiB limit");
    expect(await readdir(existing.outputDir)).toEqual([]);
  });

  test.each(["architecture", "threat_model"] as const)(
    "rejects malformed Unicode in %s evidence before saving it",
    async (invalidStage) => {
      const f = await fixture();
      const stages: SecurityPolicyStage[] = [];
      await expect(
        f.generate({
          run: async (stage) => {
            stages.push(stage);
            return {
              ...stageResult(stage),
              ...(stage === invalidStage
                ? { markdown: "# Evidence\n\ud800" }
                : {}),
            };
          },
        }),
      ).rejects.toThrow("valid Unicode");
      expect(stages.at(-1)).toBe(invalidStage);
      expect((await readdir(f.outputDir)).sort()).toEqual(
        invalidStage === "architecture"
          ? ["previous-SECURITY.md"]
          : ["previous-SECURITY.md", "project-spec.md"],
      );
      expect(await readdir(f.repository)).toEqual([]);
    },
  );

  test("does not apply the policy byte limit to supporting evidence", async () => {
    const f = await fixture();
    const document = `# Evidence\n${"x".repeat(1024 * 1024)}`;
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy" ? {} : { markdown: document }),
      }),
    });
    expect(await readFile(draft.specificationPath, "utf8")).toBe(document);
    expect(await readFile(draft.threatModelPath, "utf8")).toBe(document);
    expect(draft.content).toBe(POLICY);
  });
});

describe("security policy preview", () => {
  test("accepts policy Markdown without a hash-style heading", async () => {
    for (const content of [
      "Security policy\n===============\n\nReport vulnerabilities privately.\n",
      "Report vulnerabilities privately.\n",
    ]) {
      const f = await fixture();
      const draft = await f.generate({
        run: async (stage) => ({
          ...stageResult(stage),
          ...(stage === "policy" ? { markdown: content } : {}),
        }),
      });
      expect(draft.content).toBe(content);
      expect(await readFile(draft.draftPath, "utf8")).toBe(content);
      expect(await securityPolicyDiff(draft, PYTHON)).toContain(
        "+Report vulnerabilities privately.",
      );
      expect(await readdir(f.repository)).toEqual([]);
    }
  });

  test("previews the exact proposed policy without changing source", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("--- /dev/null\n+++ b/SECURITY.md\n");
    expect(diff).toContain("+Requests must be authorized");
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("rejects preview after a component changes Git roots", async () => {
    for (const change of ["add", "remove"] as const) {
      const f = await fixture();
      policyGit(f.repository, "init", "--quiet");
      const component = join(f.repository, "component");
      await mkdir(component);
      if (change === "remove") policyGit(component, "init", "--quiet");
      const draft = await f.generate({ path: "component" });
      if (change === "add") policyGit(component, "init", "--quiet");
      else await rename(join(component, ".git"), join(f.root, "previous-git"));
      await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
        "destination changed",
      );
      expect(await readSecurityPolicy(draft.targetPath)).toBe(null);
    }
  });

  test("shows missing final newlines in the exact diff", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Old policy");
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy" ? { markdown: "# New policy" } : {}),
      }),
    });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("-# Old policy\n\\ No newline at end of file\n");
    expect(diff).toContain("+# New policy\n\\ No newline at end of file\n");
  });

  test("keeps non-LF separators inside their original diff lines", async () => {
    const f = await fixture();
    const before = "Old\rpolicy\u0085with\u2028separators\u2029";
    const after = "New\rpolicy\u0085with\u2028separators\u2029";
    await writeFile(join(f.repository, "SECURITY.md"), before);
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy" ? { markdown: after } : {}),
      }),
    });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("@@ -1 +1 @@\n");
    expect(diff).toContain(`-${before}\n\\ No newline at end of file\n`);
    expect(diff).toContain(`+${after}\n\\ No newline at end of file\n`);
    expect(diff.match(/No newline at end of file/gu)).toHaveLength(2);
  });

  test("reports an early diff subprocess exit without an unhandled stdin error", async () => {
    const name =
      "reports an early diff subprocess exit without an unhandled stdin error";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const draft = await f.generate();
    const node = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    await expect(
      securityPolicyDiff(
        { ...draft, content: `# Policy\n${"x".repeat(900_000)}` },
        node,
      ),
    ).rejects.toThrow();
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("preserves UTF-8 text and CRLF content independently of Python's locale", async () => {
    const f = await fixture();
    await writeFile(
      join(f.repository, "SECURITY.md"),
      "# Policy\r\n\r\nOld naïve 🔒\r\n",
    );
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy"
          ? { markdown: "# Policy\r\n\r\nNew π 🛡️\r\n" }
          : {}),
      }),
    });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("--- a/SECURITY.md\n+++ b/SECURITY.md\n");
    expect(diff).toContain("-Old naïve 🔒\r\n");
    expect(diff).toContain("+New π 🛡️\r\n");
    expect(diff).not.toContain("\r\r\n");
  });

  test.skipIf(process.platform === "win32")(
    "quotes control characters in repository-controlled diff labels",
    async () => {
      const f = await fixture();
      const scope = "component\n+++ forged\tname";
      await mkdir(join(f.repository, scope));
      const draft = await f.generate({ path: scope });
      const diff = await securityPolicyDiff(draft, PYTHON);
      expect(diff).toContain(
        `+++ ${JSON.stringify(`b/${scope}/SECURITY.md`)}\n`,
      );
      expect(diff).not.toContain("\n+++ forged");
      expect(diff).not.toContain("\tname");
    },
  );

  test("escapes every Unicode direction control in diff labels", async () => {
    const f = await fixture();
    const controls =
      "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069";
    const scope = `component${controls}name`;
    await mkdir(join(f.repository, scope));
    const draft = await f.generate({ path: scope });
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).not.toMatch(/\p{Bidi_Control}/u);
    for (const character of controls)
      expect(diff).toContain(
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
  });

  test("checks source freshness even for an unchanged draft", async () => {
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), POLICY);
    const draft = await f.generate();
    expect(
      await securityPolicyDiff(draft, async () => {
        throw new Error("An unchanged preview must not resolve Python");
      }),
    ).toBe("");
    await writeFile(draft.targetPath, "# Concurrent policy\n");
    await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
      "changed after",
    );
  });

  test("rejects changes made while preparing a policy diff", async () => {
    for (const changed of ["target", "inherited"]) {
      const f = await fixture();
      await mkdir(join(f.repository, "component"));
      const rootPolicy = join(f.repository, "SECURITY.md");
      await writeFile(rootPolicy, "# Original root policy\n");
      const draft = await f.generate({ path: "component" });
      await expect(
        securityPolicyDiff(draft, async () => {
          await writeFile(
            changed === "target" ? draft.targetPath : rootPolicy,
            "# Concurrent policy\n",
          );
          return PYTHON;
        }),
      ).rejects.toThrow("changed after");
    }
  });

  test("invalidates component previews when inherited policies change", async () => {
    for (const change of ["edit", "add", "remove"] as const) {
      const f = await fixture();
      const component = join(f.repository, "services", "api");
      const rootPolicy = join(f.repository, "SECURITY.md");
      await mkdir(component, { recursive: true });
      await writeFile(rootPolicy, "# Root policy\n");
      if (change === "edit")
        await writeFile(join(component, "SECURITY.md"), POLICY);
      const draft = await f.generate({ path: "services/api" });
      if (change === "edit") await writeFile(rootPolicy, "# New root policy\n");
      else if (change === "add")
        await writeFile(
          join(f.repository, "services", "SECURITY.md"),
          "# New intermediate policy\n",
        );
      else await rm(rootPolicy);
      await expect(securityPolicyDiff(draft, "missing-python")).rejects.toThrow(
        "inherited SECURITY.md changed",
      );
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        draft.previousContent,
      );
    }
  });

  test("rejects inherited aliases that would widen the policy scope", async () => {
    for (const [ancestor, existing, chained, name] of [
      [".", false, false, "SECURITY.md"],
      [".", true, false, "SECURITY.md"],
      ["services", true, true, "SECURITY.md"],
      ["services", false, true, "\u017fECURITY.md"],
    ] as const) {
      const f = await fixture();
      const component = join(f.repository, "services", "api");
      await mkdir(component, { recursive: true });
      if (existing)
        await writeFile(join(component, "SECURITY.md"), "# Original policy\n");
      let destination = join(component, name);
      if (chained) {
        const intermediate = join(f.repository, "policy-link.md");
        await symlink(destination, intermediate, "file");
        destination = intermediate;
      }
      await symlink(
        destination,
        join(f.repository, ancestor, "SECURITY.md"),
        "file",
      );
      await expect(f.generate({ path: "services/api" })).rejects.toThrow(
        "outside the selected component",
      );
      expect(await readdir(f.outputDir)).toEqual([]);
    }
  });

  test("tracks safe inherited policy links and rejects outside links", async () => {
    const f = await fixture();
    const linkedPolicy = join(f.repository, ".github", "SECURITY.md");
    await mkdir(dirname(linkedPolicy));
    await mkdir(join(f.repository, "component"));
    await writeFile(linkedPolicy, "# Owner policy\n");
    await symlink(linkedPolicy, join(f.repository, "SECURITY.md"), "file");
    const draft = await f.generate({ path: "component" });
    expect(await securityPolicyDiff(draft, PYTHON)).toContain(
      "b/component/SECURITY.md",
    );
    await writeFile(linkedPolicy, "# Changed owner policy\n");
    await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
      "inherited SECURITY.md changed",
    );

    const outside = await fixture();
    await mkdir(join(outside.repository, "component"));
    const outsidePolicy = join(outside.root, "outside-policy.md");
    await writeFile(outsidePolicy, "# Outside policy\n");
    await symlink(
      outsidePolicy,
      join(outside.repository, "SECURITY.md"),
      "file",
    );
    await expect(outside.generate({ path: "component" })).rejects.toThrow(
      "outside the repository",
    );
    expect(await readdir(outside.outputDir)).toEqual([]);
  });

  test("treats inherited links through regular files as absent", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    await mkdir(join(f.repository, "component"));
    await writeFile(join(f.repository, "not-a-directory"), "source\n");
    await symlink(
      join(f.repository, "not-a-directory", "policy.md"),
      join(f.repository, "SECURITY.md"),
      "file",
    );
    const draft = await f.generate({ path: "component" });
    expect(await securityPolicyDiff(draft, PYTHON)).toContain(
      "b/component/SECURITY.md",
    );
  });

  test("invalidates component drafts when inherited links change", async () => {
    for (const change of ["add", "remove", "retarget", "dangle"] as const) {
      const f = await fixture();
      const component = join(f.repository, "component");
      const target = join(component, "SECURITY.md");
      const inherited = join(f.repository, "SECURITY.md");
      const ownerPolicy = join(f.repository, ".github", "SECURITY.md");
      const intermediate = join(f.repository, "policy-link.md");
      await mkdir(dirname(ownerPolicy));
      await mkdir(component);
      await writeFile(target, "# Original policy\n");
      await writeFile(ownerPolicy, "# Owner policy\n");
      if (change !== "add") await symlink(ownerPolicy, inherited, "file");
      const draft = await f.generate({ path: "component" });
      if (change === "add") await symlink(ownerPolicy, inherited, "file");
      if (change === "remove") await rm(inherited);
      if (change === "retarget") {
        await symlink(ownerPolicy, intermediate, "file");
        await rm(inherited);
        await symlink(intermediate, inherited, "file");
      }
      if (change === "dangle") await rm(ownerPolicy);
      await expect(securityPolicyDiff(draft, "missing-python")).rejects.toThrow(
        "inherited SECURITY.md changed",
      );
      expect(await readFile(target, "utf8")).toBe("# Original policy\n");
    }
  });

  test("rejects cycles in inherited policy links", async () => {
    const f = await fixture();
    await mkdir(join(f.repository, "component"));
    const inherited = join(f.repository, "SECURITY.md");
    const intermediate = join(f.repository, "policy-link.md");
    await symlink(intermediate, inherited, "file");
    await symlink(inherited, intermediate, "file");
    await expect(f.generate({ path: "component" })).rejects.toThrow("cycle");
    expect(await readdir(f.outputDir)).toEqual([]);
  });
});
