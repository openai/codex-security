import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import {
  SecurityPolicyRecoveryError,
  SecurityPolicyVerificationError,
} from "../src/errors.js";
import {
  applySecurityPolicy,
  inspectSecurityPolicyPaths,
  loadSecurityPolicyDraft,
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
  policyPlugin,
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
});

describe("security policy review and application", () => {
  test("protects enclosing-checkout policies when a nested checkout is selected", async () => {
    for (const kind of ["repository", "submodule", "worktree"]) {
      for (const existing of [false, true]) {
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
        const nested = join(f.repository, "services", "api");
        if (kind === "submodule")
          await addPolicySubmodule(
            f.repository,
            join(f.root, "submodule-source"),
          );
        else if (kind === "worktree")
          policyGit(
            f.repository,
            "worktree",
            "add",
            "--quiet",
            "--detach",
            nested,
            "HEAD",
          );
        else {
          await mkdir(nested, { recursive: true });
          policyGit(nested, "init", "--quiet");
        }
        const target = join(nested, "SECURITY.md");
        const original = "# Existing nested policy\n";
        if (existing) await writeFile(target, original);
        const alias = join(f.repository, "SECURITY.md");
        await symlink(target, alias, "file");
        const draft = await f.generate({ path: "services/api" });
        expect(await securityPolicyDiff(draft, PYTHON)).toContain(
          "b/SECURITY.md",
        );
        await expect(applySecurityPolicy(draft)).rejects.toThrow(
          "outside the selected component",
        );
        expect(await readSecurityPolicy(target)).toBe(
          existing ? original : null,
        );
        expect((await lstat(alias)).isSymbolicLink()).toBe(true);
      }
    }
  });

  test("protects reporting-policy aliases in enclosing checkouts", async () => {
    const f = await fixture();
    const middle = join(f.repository, "services");
    const nested = join(middle, "api");
    await mkdir(nested, { recursive: true });
    for (const repository of [f.repository, middle, nested])
      policyGit(repository, "init", "--quiet");
    await symlink(
      nested,
      join(middle, ".github"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const draft = await f.generate({ path: "services/api" });
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "separate vulnerability-reporting policy",
    );
    expect(await readSecurityPolicy(draft.targetPath)).toBe(null);
  });

  test("allows an explicitly selected reporting policy", async () => {
    for (const path of ["docs", "Docs", ".github", ".GITHUB"]) {
      for (const existing of [false, true]) {
        const f = await fixture();
        const directory = join(f.repository, path);
        await mkdir(directory);
        if (existing)
          await writeFile(
            join(directory, "SECURITY.md"),
            "# Existing policy\n",
          );
        const draft = await f.generate({ path });
        await applySecurityPolicy(draft);
        expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      }
    }
  });

  test("keeps linked reporting directories distinct from the selected directory", async () => {
    const f = await fixture();
    const component = join(f.repository, "Docs");
    await mkdir(component);
    const lowerCaseExists = await lstat(join(f.repository, "docs")).then(
      () => true,
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return false;
        throw error;
      },
    );
    const draft = await f.generate({ path: "Docs" });
    await symlink(
      component,
      join(f.repository, lowerCaseExists ? ".github" : "docs"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "separate vulnerability-reporting policy",
    );
    expect(await readSecurityPolicy(draft.targetPath)).toBe(null);
  });

  test("enforces the resolver byte limit on saved draft files", async () => {
    const header = "# Policy\n";
    const maximum =
      header + "x".repeat(1024 * 1024 - Buffer.byteLength(header));
    const saved = await fixture();
    const draft = await saved.generate();
    await writeFile(draft.draftPath, `${maximum}x`);
    await expect(
      loadSecurityPolicyDraft(saved.repository, saved.outputDir),
    ).rejects.toThrow("1 MiB limit");
    await writeFile(draft.draftPath, POLICY);
    await writeFile(
      join(saved.outputDir, "previous-SECURITY.md"),
      `${maximum}x`,
    );
    await expect(
      loadSecurityPolicyDraft(saved.repository, saved.outputDir),
    ).rejects.toThrow("1 MiB limit");
  });

  test("accepts policy Markdown without a hash-style heading", async () => {
    for (const content of [
      "Security policy\n===============\n\nReport vulnerabilities privately.\n",
      "Report vulnerabilities privately.\n",
    ]) {
      const f = await fixture();
      await f.generate({
        run: async (stage) => ({
          ...stageResult(stage),
          ...(stage === "policy" ? { markdown: content } : {}),
        }),
      });
      const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir);
      expect(draft.content).toBe(content);
      await applySecurityPolicy(draft, { pythonPath: PYTHON });
      expect(await readFile(draft.targetPath, "utf8")).toBe(content);
      expect(
        await resolveSecurityPolicyGuidance(draft, PYTHON, PLUGIN_ROOT),
      ).toContain(content);
    }
  });

  test("previews a real diff and applies a new policy accepted by the resolver", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const diff = await securityPolicyDiff(draft, PYTHON);
    expect(diff).toContain("--- /dev/null\n+++ b/SECURITY.md\n");
    expect(diff).toContain("+Requests must be authorized");
    expect(await applySecurityPolicy(draft)).toEqual({
      status: "written",
      targetPath: draft.targetPath,
      recoveryPath: null,
    });
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    expect(
      await resolveSecurityPolicyGuidance(draft, PYTHON, PLUGIN_ROOT),
    ).toContain(POLICY.trim());
    expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
  });

  test("creates new policies as a distinct destination inode", async () => {
    const name = "creates new policies as a distinct destination inode";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const draft = await f.generate();
    const originalOpen = fsPromises.open;
    let stagedIdentity: string | undefined;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      open: async (...args: Parameters<typeof originalOpen>) => {
        const handle = await originalOpen(...args);
        if (String(args[0]).startsWith(join(f.repository, ".SECURITY.md."))) {
          const metadata = await handle.stat({ bigint: true });
          stagedIdentity = `${metadata.dev}:${metadata.ino}`;
        }
        return handle;
      },
    }));
    try {
      await applySecurityPolicy(draft);
      const installed = await stat(draft.targetPath, { bigint: true });
      expect(stagedIdentity).toBeDefined();
      expect(`${installed.dev}:${installed.ino}`).not.toBe(stagedIdentity);
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        open: originalOpen,
      }));
    }
  });

  test("allows edits to a saved draft and writes the exact reviewed bytes", async () => {
    const f = await fixture();
    const original = "# Security Policy\n\nOriginal guidance.\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    if (process.platform !== "win32")
      await chmod(join(f.repository, "SECURITY.md"), 0o640);
    await f.generate();
    const originalAlias = join(f.root, "original-policy.md");
    await link(join(f.repository, "SECURITY.md"), originalAlias);
    const edited = `${POLICY}\nOwner-confirmed scope.\n`;
    await writeFile(join(f.outputDir, "SECURITY.md"), edited);
    const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    await writeFile(draft.draftPath, "# Later unreviewed edit\n");
    await applySecurityPolicy(draft);
    expect(await readFile(draft.targetPath, "utf8")).toBe(edited);
    expect(await readFile(originalAlias, "utf8")).toBe(original);
    if (process.platform !== "win32")
      expect((await stat(draft.targetPath)).mode & 0o777).toBe(0o640);
  });

  test("rejects linked saved-draft inputs before reading them", async () => {
    const f = await fixture();
    await f.generate();
    const alias = join(f.root, "linked-policy");
    await symlink(
      f.outputDir,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(loadSecurityPolicyDraft(f.repository, alias)).rejects.toThrow(
      "non-symlink directory",
    );
    for (const name of ["SECURITY.md", "previous-SECURITY.md"]) {
      const path = join(f.outputDir, name);
      const outside = join(f.root, `outside-${name}`);
      await rename(path, outside);
      await link(outside, path);
      await expect(
        loadSecurityPolicyDraft(f.repository, f.outputDir),
      ).rejects.toThrow("hard-linked");
      await rm(path);
      await rename(outside, path);
    }
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("applies the SDK draft snapshot that was validated", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const target = draft.targetPath;
    const other = join(f.repository, "unreviewed.md");
    const application = applySecurityPolicy(draft);
    draft.content = "";
    draft.previousContent = POLICY;
    draft.targetPath = other;
    expect(await application).toMatchObject({
      status: "written",
      targetPath: target,
    });
    expect(await readFile(target, "utf8")).toBe(POLICY);
    await expect(lstat(other)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects malformed UTF-8 in existing policies and saved drafts", async () => {
    const f = await fixture();
    const malformed = Buffer.concat([
      Buffer.from("# Policy\n"),
      Buffer.from([0xe9]),
    ]);
    const draft = await f.generate();
    await writeFile(draft.draftPath, malformed);
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow("valid UTF-8");
    expect(await readdir(f.repository)).toEqual([]);
    await writeFile(draft.targetPath, malformed);
    await expect(resolveSecurityPolicyTarget(f.repository)).rejects.toThrow(
      "valid UTF-8",
    );
    expect(await readFile(draft.targetPath)).toEqual(malformed);
  });

  test("preserves a valid UTF-8 byte-order mark in a reviewed draft", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const bytes = Buffer.from(
      "\uFEFF# Security Policy\r\n\r\nReviewed text.\r\n",
    );
    await writeFile(draft.draftPath, bytes);
    const loaded = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    await applySecurityPolicy(loaded);
    expect(await readFile(draft.targetPath)).toEqual(bytes);
  });

  test("uses the selected plugin and requires an explicit selection for saved custom drafts", async () => {
    const f = await fixture();
    const log = join(f.root, "resolver.log");
    const pluginPath = await policyPlugin(
      f.root,
      [
        "import os, pathlib",
        "with pathlib.Path(os.environ['POLICY_TEST_LOG']).open('a') as output:",
        "    output.write('custom resolver\\n')",
        "print('custom guidance')",
      ].join("\n"),
    );
    const draft = await f.generate({ pluginPath });
    const manifestPath = join(f.outputDir, "policy-draft.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    expect(manifest.customPlugin).toBe(true);
    expect(manifest).not.toHaveProperty("pluginPath");
    await writeFile(
      manifestPath,
      JSON.stringify({ ...manifest, pluginPath: "/unapproved/plugin" }),
    );
    const saved = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    expect(saved.pluginPath).toBeUndefined();
    await expect(applySecurityPolicy(saved)).rejects.toThrow(
      "Select it explicitly",
    );
    expect(await readdir(f.repository)).toEqual([]);
    const temporaryVariables = ["TMPDIR", "TMP", "TEMP"] as const;
    const previousTemporary = temporaryVariables.map((key) => process.env[key]);
    try {
      for (const key of temporaryVariables) process.env[key] = f.repository;
      await applySecurityPolicy(draft, {
        pythonPath: PYTHON,
        environment: { ...process.env, POLICY_TEST_LOG: log },
      });
    } finally {
      for (const [index, key] of temporaryVariables.entries()) {
        const previous = previousTemporary[index];
        if (previous === undefined) delete process.env[key];
        else process.env[key] = previous;
      }
    }
    expect((await readFile(log, "utf8")).trimEnd().split(/\r?\n/u)).toEqual([
      "custom resolver",
      "custom resolver",
    ]);
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
  });

  test("applies a saved draft with an explicitly selected plugin ZIP", async () => {
    const f = await fixture();
    const log = join(f.root, "resolver-paths.log");
    const archive = join(f.root, "policy-plugin.zip");
    const script = [
      "import os, pathlib",
      "with pathlib.Path(os.environ['POLICY_TEST_LOG']).open('a') as output:",
      "    output.write(str(pathlib.Path(__file__).resolve()) + '\\n')",
      "print('custom guidance')",
    ].join("\n");
    await writeFile(
      archive,
      zipSync({
        ".codex-plugin/plugin.json": strToU8(
          JSON.stringify({
            name: "codex-security",
            version: "test-policy-plugin",
          }),
        ),
        "scripts/resolve_security_md.py": strToU8(script),
      }),
    );
    await f.generate({ pluginPath: archive });
    const saved = await loadSecurityPolicyDraft(f.repository, f.outputDir);
    await applySecurityPolicy(saved, {
      pluginPath: archive,
      pythonPath: PYTHON,
      environment: { ...process.env, POLICY_TEST_LOG: log },
    });
    expect(await readFile(saved.targetPath, "utf8")).toBe(POLICY);
    const resolverPaths = (await readFile(log, "utf8")).trim().split(/\r?\n/u);
    expect(resolverPaths).toHaveLength(2);
    for (const path of resolverPaths)
      await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("checks the selected resolver before changing repository files", async () => {
    const f = await fixture();
    const pluginPath = await policyPlugin(
      f.root,
      "raise SystemExit('synthetic preflight failure')\n",
    );
    const draft = await f.generate({ pluginPath });
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "synthetic preflight failure",
    );
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("reports a committed policy when verification fails or is interrupted", async () => {
    for (const failure of [
      "raise SystemExit('synthetic verification failure')",
      "signal.raise_signal(signal.SIGINT)",
    ]) {
      const f = await fixture();
      const pluginPath = await policyPlugin(
        f.root,
        [
          "import pathlib, signal, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          `if (root / 'SECURITY.md').exists(): ${failure}`,
          "print('preflight passed')",
        ].join("\n"),
      );
      const draft = await f.generate({ pluginPath });
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect(error).toMatchObject({ targetPath: draft.targetPath });
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    }
  });

  test("retries verification without replacing an already-installed draft", async () => {
    for (const existing of [false, true]) {
      const f = await fixture();
      if (existing)
        await writeFile(
          join(f.repository, "SECURITY.md"),
          "# Existing policy\n",
        );
      const blocked = join(f.root, "block-verification");
      await writeFile(blocked, "");
      const pluginPath = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "target = pathlib.Path(sys.argv[sys.argv.index('--scope') + 1]) / 'SECURITY.md'",
          `if target.exists() and target.read_text() == ${JSON.stringify(POLICY)} and pathlib.Path(${JSON.stringify(blocked)}).exists():`,
          "    raise SystemExit('synthetic verification failure')",
          "print('resolver accepted the policy')",
        ].join("\n"),
      );
      const draft = await f.generate({ pluginPath });
      await expect(applySecurityPolicy(draft)).rejects.toBeInstanceOf(
        SecurityPolicyVerificationError,
      );
      const installed = await stat(draft.targetPath);
      const artifacts = (await readdir(f.outputDir)).sort();
      const saved = await loadSecurityPolicyDraft(f.repository, f.outputDir);
      expect(await securityPolicyDiff(draft, PYTHON)).toBe("");
      await expect(applySecurityPolicy(draft)).rejects.toBeInstanceOf(
        SecurityPolicyVerificationError,
      );
      for (const options of [
        { pythonPath: PYTHON },
        { pythonPath: join(f.root, "missing-python"), pluginPath },
        { pythonPath: PYTHON, pluginPath: join(f.root, "missing-plugin.zip") },
      ])
        await expect(
          applySecurityPolicy(saved, options),
        ).rejects.toBeInstanceOf(SecurityPolicyVerificationError);
      await rm(blocked);
      expect(
        await applySecurityPolicy(saved, { pythonPath: PYTHON, pluginPath }),
      ).toEqual({
        status: "unchanged",
        targetPath: draft.targetPath,
        recoveryPath: null,
      });
      expect((await stat(draft.targetPath)).ino).toBe(installed.ino);
      expect((await readdir(f.outputDir)).sort()).toEqual(artifacts);
    }
  });

  test("rechecks the reviewed bytes after the resolver returns", async () => {
    for (const change of ["remove", "replace"] as const) {
      const f = await fixture();
      const original = "# Original policy\n";
      await writeFile(join(f.repository, "SECURITY.md"), original);
      const pluginPath = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          "target = root / 'SECURITY.md'",
          `if target.read_text() == ${JSON.stringify(POLICY)}:`,
          change === "remove"
            ? "    target.unlink()"
            : "    target.write_bytes(b'# Concurrent policy\\n')",
          "print('resolver accepted the current policy chain')",
        ].join("\n"),
      );
      const draft = await f.generate({ pluginPath });
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      const recovery = error as SecurityPolicyVerificationError;
      expect(await readFile(recovery.recoveryPath!, "utf8")).toBe(original);
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        change === "remove" ? null : "# Concurrent policy\n",
      );
    }
  });

  test("rechecks retained recovery contents when retrying an installed policy", async () => {
    const name =
      "rechecks retained recovery contents when retrying an installed policy";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Existing policy\n");
    const draft = await f.generate();
    const applied = await applySecurityPolicy(draft);
    const recovery = applied.recoveryPath!;
    const originalStat = fsPromises.stat;
    let changedRecovery = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      stat: async (...args: Parameters<typeof originalStat>) => {
        const result = await originalStat(...args);
        if (!changedRecovery && args[0] === recovery) {
          changedRecovery = true;
          await writeFile(recovery, "# Concurrent recovery edit\n");
        }
        return result;
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(changedRecovery).toBe(true);
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect((error as SecurityPolicyVerificationError).recoveryPath).toBe(
        recovery,
      );
      expect(await readFile(recovery, "utf8")).toBe(
        "# Concurrent recovery edit\n",
      );
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        stat: originalStat,
      }));
    }
  });

  test("rechecks installed policy contents after final permission verification", async () => {
    const name =
      "rechecks installed policy contents after final permission verification";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Existing policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const applied = await applySecurityPolicy(draft);
    const recovery = applied.recoveryPath!;
    const writer = await open(draft.targetPath, "r+");
    const originalStat = fsPromises.stat;
    let changedTarget = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      stat: async (...args: Parameters<typeof originalStat>) => {
        const metadata = await originalStat(...args);
        if (!changedTarget && args[0] === recovery) {
          changedTarget = true;
          await writer.truncate(0);
          await writer.writeFile("# Concurrent installed edit\n");
        }
        return metadata;
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(changedTarget).toBe(true);
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect((error as SecurityPolicyVerificationError).recoveryPath).toBe(
        recovery,
      );
      expect(await readFile(draft.targetPath, "utf8")).toBe(
        "# Concurrent installed edit\n",
      );
      expect(await readFile(recovery, "utf8")).toBe(original);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        stat: originalStat,
      }));
    }
  });

  test("rechecks policy links after final permission verification", async () => {
    const name = "rechecks policy links after final permission verification";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const component = join(f.repository, "component");
    const sibling = join(f.repository, "sibling");
    await mkdir(component);
    await mkdir(sibling);
    const original = "# Existing component policy\n";
    const target = join(component, "SECURITY.md");
    const alias = join(sibling, "SECURITY.md");
    await writeFile(target, original);
    const draft = await f.generate({ path: "component" });
    const applied = await applySecurityPolicy(draft);
    const recovery = applied.recoveryPath!;
    const originalStat = fsPromises.stat;
    let createdAlias = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      stat: async (...args: Parameters<typeof originalStat>) => {
        const metadata = await originalStat(...args);
        if (!createdAlias && args[0] === recovery) {
          createdAlias = true;
          await symlink(target, alias, "file");
        }
        return metadata;
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(createdAlias).toBe(true);
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect((error as SecurityPolicyVerificationError).recoveryPath).toBe(
        recovery,
      );
      expect(String((error as Error).cause)).toContain(
        "outside the selected component",
      );
      expect(await readFile(target, "utf8")).toBe(draft.content);
      expect(await readFile(recovery, "utf8")).toBe(original);
      expect((await lstat(alias)).isSymbolicLink()).toBe(true);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        stat: originalStat,
      }));
    }
  });

  test("chooses whether to write from the validated policy snapshot", async () => {
    const name = "chooses whether to write from the validated policy snapshot";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const target = join(f.repository, "SECURITY.md");
    const previous = "# Existing policy\n";
    await writeFile(target, previous);
    const draft = await f.generate();
    await writeFile(target, draft.content);
    const originalOpen = fsPromises.open;
    let restoredOriginal = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      open: async (...args: Parameters<typeof originalOpen>) => {
        if (
          !restoredOriginal &&
          args[0] === target &&
          new Error().stack?.includes("readDraftContent")
        ) {
          restoredOriginal = true;
          await writeFile(target, previous);
        }
        return originalOpen(...args);
      },
    }));
    try {
      const applied = await applySecurityPolicy(draft);
      expect(restoredOriginal).toBe(true);
      expect(applied.status).toBe("written");
      expect(await readFile(target, "utf8")).toBe(draft.content);
      expect(await readFile(applied.recoveryPath!, "utf8")).toBe(previous);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        open: originalOpen,
      }));
    }
  });

  test("preserves policies across hard-link and copy failures", async () => {
    const name = "preserves policies across hard-link and copy failures";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const originalLink = fsPromises.link;
    const originalCopyFile = fsPromises.copyFile;
    let linkErrorCode = "ENOTSUP";
    let collision = false;
    let copyFailure = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async () => {
        throw Object.assign(new Error("hard links are unsupported"), {
          code: linkErrorCode,
        });
      },
      copyFile: async (source: string, destination: string, mode?: number) => {
        if (collision) await writeFile(destination, "# Concurrent policy\n");
        if (copyFailure) {
          await writeFile(destination, "# Partial policy\n", { flag: "wx" });
          throw Object.assign(new Error("synthetic copy failure"), {
            code: "EIO",
          });
        }
        await originalCopyFile(source, destination, mode);
      },
    }));
    try {
      for (linkErrorCode of ["ENOTSUP", "EISDIR"]) {
        const existing = await fixture();
        await writeFile(
          join(existing.repository, "SECURITY.md"),
          "# Existing policy\n",
        );
        const replacement = await existing.generate();
        await applySecurityPolicy(replacement);
        expect(await readFile(replacement.targetPath, "utf8")).toBe(POLICY);
        expect(await readdir(existing.repository)).toEqual(["SECURITY.md"]);
      }
      linkErrorCode = "ENOTSUP";
      const other = await fixture();
      const racing = await other.generate();
      collision = true;
      await expect(applySecurityPolicy(racing)).rejects.toMatchObject({
        code: "EEXIST",
      });
      expect(await readFile(racing.targetPath, "utf8")).toBe(
        "# Concurrent policy\n",
      );
      collision = false;
      copyFailure = true;
      const failed = await fixture();
      const partial = await failed.generate();
      const error = await applySecurityPolicy(partial).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect(error).toMatchObject({
        targetPath: partial.targetPath,
        cause: { code: "EIO" },
      });
      expect(await readFile(partial.targetPath, "utf8")).toBe(
        "# Partial policy\n",
      );
      expect(await readdir(failed.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
        copyFile: originalCopyFile,
      }));
    }
  });

  test("restores a concurrent save captured immediately before replacement", async () => {
    const name =
      "restores a concurrent save captured immediately before replacement";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const concurrent = "# Concurrent save\n";
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        if (source === draft.targetPath) await writeFile(source, concurrent);
        await originalRename(source, destination);
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      const recovery = error as SecurityPolicyRecoveryError;
      expect(dirname(recovery.recoveryPath)).toBe(f.outputDir);
      expect(await readFile(recovery.recoveryPath, "utf8")).toBe(concurrent);
      expect(await readFile(draft.targetPath, "utf8")).toBe(concurrent);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test("keeps both files when a concurrent writer claims the destination", async () => {
    const name =
      "keeps both files when a concurrent writer claims the destination";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    const concurrent = "# Concurrent save\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        if (destination === draft.targetPath && source.endsWith(".tmp"))
          await writeFile(destination, concurrent);
        await originalLink(source, destination);
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      const recovery = error as SecurityPolicyRecoveryError;
      expect(recovery.targetPath).toBe(draft.targetPath);
      expect(dirname(recovery.recoveryPath)).toBe(f.outputDir);
      expect(await readFile(recovery.recoveryPath, "utf8")).toBe(original);
      expect(await readFile(draft.targetPath, "utf8")).toBe(concurrent);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("keeps a recovery copy changed through an already-open file", async () => {
    const name = "keeps a recovery copy changed through an already-open file";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const concurrent = "# Concurrent in-place save\n";
    const writer = await open(draft.targetPath, "r+");
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        await originalLink(source, destination);
        if (destination === draft.targetPath && source.endsWith(".tmp")) {
          await writer.truncate(0);
          await writer.writeFile(concurrent);
        }
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      const recovery = error as SecurityPolicyVerificationError;
      expect(recovery.targetPath).toBe(draft.targetPath);
      expect(dirname(recovery.recoveryPath!)).toBe(f.outputDir);
      expect(await readFile(recovery.recoveryPath!, "utf8")).toBe(concurrent);
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("retains late writes to the displaced file after successful application", async () => {
    const f = await fixture();
    const original = "# Original policy\n";
    const late = "# Save after application completed\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    try {
      const applied = await applySecurityPolicy(draft);
      expect(applied.targetPath).toBe(draft.targetPath);
      expect(dirname(applied.recoveryPath!)).toBe(f.outputDir);
      await writer.truncate(0);
      await writer.writeFile(late);
      expect(await readFile(applied.recoveryPath!, "utf8")).toBe(late);
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      expect(
        await readFile(join(f.outputDir, "previous-SECURITY.md"), "utf8"),
      ).toBe(original);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      await writer.close();
    }
  });

  test("keeps the original inode beside the target across filesystem boundaries", async () => {
    const name =
      "keeps the original inode beside the target across filesystem boundaries";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        if (
          source.endsWith(".previous") &&
          dirname(destination) === f.outputDir
        )
          throw Object.assign(new Error("different filesystem"), {
            code: "EXDEV",
          });
        await originalRename(source, destination);
      },
    }));
    try {
      const applied = await applySecurityPolicy(draft);
      expect(dirname(applied.recoveryPath!)).toBe(f.repository);
      expect(await applySecurityPolicy(draft)).toEqual({
        status: "unchanged",
        targetPath: draft.targetPath,
        recoveryPath: null,
      });
      await writer.truncate(0);
      await writer.writeFile("# Late save\n");
      expect(await readFile(applied.recoveryPath!, "utf8")).toBe(
        "# Late save\n",
      );
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      expect(
        (await readdir(f.outputDir)).filter((path) =>
          path.startsWith("recovery-SECURITY-"),
        ),
      ).toEqual([]);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test("retains open-writer data when rollback must copy instead of hard-link", async () => {
    const name =
      "retains open-writer data when rollback must copy instead of hard-link";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    let windowsDescriptor: (() => string) | undefined;
    let windowsIntegrity: (() => string) | undefined;
    let unixDescriptor:
      | (() => Promise<{ uid: number; gid: number; mode: number; acl: string }>)
      | undefined;
    if (process.platform === "darwin") {
      const initial = await stat(draft.targetPath);
      const secondaryGroup = (process.getgroups?.() ?? []).find(
        (group) => group !== initial.gid,
      );
      if (secondaryGroup !== undefined)
        await fsPromises.chown(draft.targetPath, initial.uid, secondaryGroup);
      await chmod(draft.targetPath, 0o2750);
      execFileSync("/bin/chmod", [
        "+a",
        "everyone allow read",
        draft.targetPath,
      ]);
      unixDescriptor = async () => {
        const metadata = await stat(draft.targetPath);
        return {
          uid: metadata.uid,
          gid: metadata.gid,
          mode: metadata.mode & 0o7777,
          acl: execFileSync("/bin/ls", ["-ledn", draft.targetPath], {
            encoding: "utf8",
          })
            .split(/\r?\n/u)
            .slice(1)
            .join("\n"),
        };
      };
    }
    if (process.platform === "win32") {
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const environment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([name]) => name.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_PATH: draft.targetPath,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      execFileSync(join(systemDirectory, "icacls.exe"), [
        draft.targetPath,
        "/setintegritylevel",
        "L",
      ]);
      execFileSync(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
            "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit",
            "$acl.SetAuditRuleProtection($true, $false)",
            "$audit = [System.Security.AccessControl.FileSystemAuditRule]::new($identity.User, 'Read', 'Success')",
            "$acl.AddAuditRule($audit)",
            "Microsoft.PowerShell.Security\\Set-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -AclObject $acl",
          ].join("; "),
        ],
        { env: environment, windowsHide: true },
      );
      windowsDescriptor = () =>
        execFileSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl",
          ],
          { encoding: "utf8", env: environment, windowsHide: true },
        ).trim();
      windowsIntegrity = () =>
        execFileSync(join(systemDirectory, "icacls.exe"), [draft.targetPath], {
          encoding: "utf8",
          windowsHide: true,
        });
    }
    const previousWindowsDescriptor = windowsDescriptor?.();
    const previousWindowsIntegrity = windowsIntegrity?.();
    const previousUnixDescriptor = await unixDescriptor?.();
    if (process.platform === "win32") {
      expect(previousWindowsDescriptor).toContain("S:P");
      expect(previousWindowsDescriptor).toContain("(AU;SA;");
      expect(previousWindowsIntegrity).toContain("(NW)");
    }
    const controller = new AbortController();
    const originalRename = fsPromises.rename;
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        await originalRename(source, destination);
        if (source === draft.targetPath)
          controller.abort("cancel before install");
      },
      link: async () => {
        throw Object.assign(new Error("hard links are unsupported"), {
          code: "ENOTSUP",
        });
      },
    }));
    try {
      const error = await applySecurityPolicy(draft, {
        signal: controller.signal,
      }).catch((value: unknown) => value);
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      const recovery = error as SecurityPolicyRecoveryError;
      if (process.platform === "darwin")
        expect(await unixDescriptor!()).toEqual(previousUnixDescriptor!);
      await writer.truncate(0);
      await writer.writeFile("# Late rollback save\n");
      expect(await readFile(recovery.recoveryPath, "utf8")).toBe(
        "# Late rollback save\n",
      );
      expect(await readFile(draft.targetPath, "utf8")).toBe(original);
      if (process.platform === "win32") {
        expect(windowsDescriptor!()).toBe(previousWindowsDescriptor!);
        expect(windowsIntegrity!()).toBe(previousWindowsIntegrity!);
      }
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
        link: originalLink,
      }));
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects a recovery snapshot changed while rollback copies it",
    async () => {
      const name =
        "rejects a recovery snapshot changed while rollback copies it";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const original = "# Original policy\n";
      await writeFile(join(f.repository, "SECURITY.md"), original);
      const draft = await f.generate();
      const writer = await open(draft.targetPath, "r+");
      const controller = new AbortController();
      const originalRename = fsPromises.rename;
      const originalLink = fsPromises.link;
      const originalStat = fsPromises.stat;
      let changed = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: async (source: string, destination: string) => {
          await originalRename(source, destination);
          if (source === draft.targetPath)
            controller.abort("cancel before install");
        },
        link: async () => {
          throw Object.assign(new Error("hard links are unsupported"), {
            code: "ENOTSUP",
          });
        },
        stat: async (path: string, ...options: []) => {
          const metadata = await originalStat(path, ...options);
          if (!changed && path.endsWith(".previous.restore")) {
            changed = true;
            await writer.truncate(0);
            await writer.writeFile("# Complete concurrent save\n");
          }
          return metadata;
        },
      }));
      try {
        const error = await applySecurityPolicy(draft, {
          signal: controller.signal,
        }).catch((value: unknown) => value);
        expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
        expect(changed).toBe(true);
        expect(await readSecurityPolicy(draft.targetPath)).toBeNull();
        expect(
          await readFile(
            (error as SecurityPolicyRecoveryError).recoveryPath,
            "utf8",
          ),
        ).toBe("# Complete concurrent save\n");
        expect(
          (await readdir(f.repository)).some((path) =>
            path.endsWith(".restore"),
          ),
        ).toBe(false);
      } finally {
        await writer.close();
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          rename: originalRename,
          link: originalLink,
          stat: originalStat,
        }));
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "rejects a Windows recovery snapshot changed while rollback copies it",
    async () => {
      const name =
        "rejects a Windows recovery snapshot changed while rollback copies it";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const original = "# Original policy\n";
      await writeFile(join(f.repository, "SECURITY.md"), original);
      const draft = await f.generate();
      const writer = await open(draft.targetPath, "r+");
      const controller = new AbortController();
      const originalRename = fsPromises.rename;
      const originalLink = fsPromises.link;
      const originalCopy = fsPromises.copyFile;
      let changed = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: async (source: string, destination: string) => {
          await originalRename(source, destination);
          if (source === draft.targetPath)
            controller.abort("cancel before install");
        },
        link: async () => {
          throw Object.assign(new Error("hard links are unsupported"), {
            code: "ENOTSUP",
          });
        },
        copyFile: async (
          source: string,
          destination: string,
          mode?: number,
        ) => {
          await originalCopy(source, destination, mode);
          if (!changed && destination.endsWith(".previous.restore")) {
            changed = true;
            await writer.truncate(0);
            await writer.writeFile("# Complete concurrent save\n");
          }
        },
      }));
      try {
        const error = await applySecurityPolicy(draft, {
          signal: controller.signal,
        }).catch((value: unknown) => value);
        expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
        expect(changed).toBe(true);
        expect(await readSecurityPolicy(draft.targetPath)).toBeNull();
        expect(
          await readFile(
            (error as SecurityPolicyRecoveryError).recoveryPath,
            "utf8",
          ),
        ).toBe("# Complete concurrent save\n");
        expect(
          (await readdir(f.repository)).some((path) =>
            path.endsWith(".restore"),
          ),
        ).toBe(false);
      } finally {
        await writer.close();
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          rename: originalRename,
          link: originalLink,
          copyFile: originalCopy,
        }));
      }
    },
  );

  test("rejects recovery metadata changed after snapshot verification", async () => {
    const name =
      "rejects recovery metadata changed after snapshot verification";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    if (process.platform !== "win32")
      await chmod(join(f.repository, "SECURITY.md"), 0o644);
    const draft = await f.generate();
    const writer = await open(draft.targetPath, "r+");
    const controller = new AbortController();
    const originalRename = fsPromises.rename;
    const originalLink = fsPromises.link;
    const originalOpen = fsPromises.open;
    let changed = false;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        await originalRename(source, destination);
        if (source === draft.targetPath)
          controller.abort("cancel before install");
      },
      link: async () => {
        throw Object.assign(new Error("hard links are unsupported"), {
          code: "ENOTSUP",
        });
      },
      open: async (...args: Parameters<typeof originalOpen>) => {
        const handle = await originalOpen(...args);
        if (!changed && String(args[0]).endsWith(".previous.restore")) {
          changed = true;
          const recovery = String(args[0]).slice(0, -".restore".length);
          const before = (await stat(recovery, { bigint: true })).ctimeNs;
          if (process.platform === "win32") {
            const icacls = join(
              process.env["SystemRoot"] ?? "C:\\Windows",
              "System32",
              "icacls.exe",
            );
            execFileSync(icacls, [recovery, "/grant", "*S-1-1-0:R"], {
              windowsHide: true,
            });
          } else await writer.chmod(0o600);
          expect((await stat(recovery, { bigint: true })).ctimeNs).not.toBe(
            before,
          );
        }
        return handle;
      },
    }));
    try {
      const error = await applySecurityPolicy(draft, {
        signal: controller.signal,
      }).catch((value: unknown) => value);
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      expect(changed).toBe(true);
      expect(await readSecurityPolicy(draft.targetPath)).toBeNull();
      const recovery = (error as SecurityPolicyRecoveryError).recoveryPath;
      expect(await readFile(recovery, "utf8")).toBe(original);
      if (process.platform !== "win32")
        expect((await stat(recovery)).mode & 0o777).toBe(0o600);
      expect(
        (await readdir(f.repository)).some((path) => path.endsWith(".restore")),
      ).toBe(false);
    } finally {
      await writer.close();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
        link: originalLink,
        open: originalOpen,
      }));
    }
  });

  test("keeps recovery files outside checkouts and Git metadata", async () => {
    for (const kind of ["root", "submodule", "external_git"]) {
      const f = await fixture();
      const path = kind === "submodule" ? "services/api" : ".";
      let inside = join(f.repository, "artifacts");
      if (kind === "submodule") {
        policyGit(f.repository, "init", "--quiet");
        await addPolicySubmodule(
          f.repository,
          join(f.root, "submodule-source"),
        );
      } else if (kind === "external_git") {
        const metadata = join(f.root, "git-data");
        policyGit(
          f.repository,
          "init",
          "--quiet",
          "--separate-git-dir",
          metadata,
        );
        policyGit(f.repository, "config", "core.worktree", f.repository);
        inside = join(metadata, "artifacts");
      }
      const original = "# Original policy\n";
      await writeFile(join(f.repository, path, "SECURITY.md"), original);
      const draft = await f.generate({ path });
      await mkdir(inside, { mode: 0o700 });
      await writeFile(
        join(inside, "policy-draft.json"),
        await readFile(join(f.outputDir, "policy-draft.json")),
      );
      const before = (await readdir(f.repository)).sort();
      await expect(
        applySecurityPolicy({ ...draft, outputDir: inside }),
      ).rejects.toThrow("outside the protected scan root");
      expect(await readFile(draft.targetPath, "utf8")).toBe(original);
      expect((await readdir(f.repository)).sort()).toEqual(before);
      expect(await readdir(inside)).toEqual(["policy-draft.json"]);
    }
  });

  test("restores the original policy when canceled after moving it", async () => {
    const name = "restores the original policy when canceled after moving it";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const controller = new AbortController();
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        await originalRename(source, destination);
        if (source === draft.targetPath)
          controller.abort(new Error("cancel before install"));
      },
    }));
    try {
      const error = await applySecurityPolicy(draft, {
        signal: controller.signal,
      }).catch((value: unknown) => value);
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      expect(
        await readFile(
          (error as SecurityPolicyRecoveryError).recoveryPath,
          "utf8",
        ),
      ).toBe(original);
      expect(await readFile(draft.targetPath, "utf8")).toBe(original);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test("does not follow a symlink that races with an existing policy", async () => {
    const name = "does not follow a symlink that races with an existing policy";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
    const draft = await f.generate();
    const outside = join(f.root, "outside-policy.md");
    await writeFile(outside, "# Outside policy\n");
    const originalRename = fsPromises.rename;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      rename: async (source: string, destination: string) => {
        if (source === draft.targetPath) {
          await rm(source);
          await symlink(outside, source, "file");
        }
        await originalRename(source, destination);
      },
    }));
    try {
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
      expect(
        (
          await lstat((error as SecurityPolicyRecoveryError).recoveryPath)
        ).isSymbolicLink(),
      ).toBe(true);
      expect(await readFile(outside, "utf8")).toBe("# Outside policy\n");
      await expect(lstat(draft.targetPath)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: originalRename,
      }));
    }
  });

  test.skipIf(process.platform === "win32")(
    "preserves an existing policy mode under a restrictive umask",
    async () => {
      const name =
        "preserves an existing policy mode under a restrictive umask";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      await chmod(target, 0o644);
      const draft = await f.generate();
      const previous = process.umask(0o077);
      try {
        await applySecurityPolicy(draft);
        expect((await stat(target)).mode & 0o777).toBe(0o644);
      } finally {
        process.umask(previous);
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves an ordinary Windows policy without rewriting its audit settings",
    async () => {
      const name =
        "preserves an ordinary Windows policy without rewriting its audit settings";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const environment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([key]) => key.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_PATH: target,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      const descriptor = () =>
        JSON.parse(
          execFileSync(
            powershell,
            [
              "-NoLogo",
              "-NoProfile",
              "-NonInteractive",
              "-Command",
              [
                "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit",
                "[pscustomobject]@{ Protected = $acl.AreAuditRulesProtected; Rules = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]).Count; Sddl = $acl.Sddl } | Microsoft.PowerShell.Utility\\ConvertTo-Json -Compress",
              ].join("; "),
            ],
            { encoding: "utf8", env: environment, windowsHide: true },
          ),
        ) as { Protected: boolean; Rules: number; Sddl: string };
      const before = descriptor();
      expect(before.Rules).toBe(0);
      const draft = await f.generate();
      await applySecurityPolicy(draft);
      expect(await readFile(target, "utf8")).toBe(POLICY);
      expect(descriptor()).toEqual(before);
    },
  );

  test.skipIf(process.platform !== "darwin")(
    "preserves Unix ownership, special permissions, and access-control entries",
    async () => {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      const identity = await stat(target);
      const secondaryGroup = (process.getgroups?.() ?? []).find(
        (group) => group !== identity.gid,
      );
      if (secondaryGroup !== undefined)
        await fsPromises.chown(target, identity.uid, secondaryGroup);
      await chmod(target, 0o2750);
      execFileSync("/bin/chmod", ["+a", "everyone allow read", target]);
      const accessControl = (path: string) =>
        execFileSync("/bin/ls", ["-ledn", path], { encoding: "utf8" })
          .split(/\r?\n/u)
          .slice(1)
          .join("\n");
      const previous = await stat(target);
      const previousAccess = accessControl(target);
      expect(previousAccess).toContain("allow read");
      const draft = await f.generate();
      await applySecurityPolicy(draft);
      const installed = await stat(target);
      expect(installed.uid).toBe(previous.uid);
      expect(installed.gid).toBe(previous.gid);
      expect(installed.mode & 0o7777).toBe(previous.mode & 0o7777);
      expect(accessControl(target)).toBe(previousAccess);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves protected Windows discretionary access-control settings",
    async () => {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const environment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([key]) => key.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_PATH: target,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      execFileSync(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH",
            "$acl.SetAccessRuleProtection($true, $true)",
            "[System.IO.FileInfo]::new($env:CODEX_SECURITY_TEST_ACL_PATH).SetAccessControl($acl)",
          ].join("; "),
        ],
        { env: environment, windowsHide: true },
      );
      const descriptor = () =>
        JSON.parse(
          execFileSync(
            powershell,
            [
              "-NoLogo",
              "-NoProfile",
              "-NonInteractive",
              "-Command",
              [
                "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit",
                "$raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)",
                "$mask = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor [System.Security.AccessControl.ControlFlags]::DiscretionaryAclDefaulted -bor [System.Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInheritRequired -bor [System.Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited -bor [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected",
                "$bytes = [byte[]]::new($raw.DiscretionaryAcl.BinaryLength); $raw.DiscretionaryAcl.GetBinaryForm($bytes, 0)",
                "[pscustomobject]@{ Protected = $acl.AreAccessRulesProtected; Flags = [int]($raw.ControlFlags -band $mask); Rules = [System.Convert]::ToBase64String($bytes); AuditProtected = $acl.AreAuditRulesProtected; AuditCount = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]).Count } | Microsoft.PowerShell.Utility\\ConvertTo-Json -Compress",
              ].join("; "),
            ],
            { encoding: "utf8", env: environment, windowsHide: true },
          ),
        ) as {
          Protected: boolean;
          Flags: number;
          Rules: string;
          AuditProtected: boolean;
          AuditCount: number;
        };
      const before = descriptor();
      expect(before.Protected).toBe(true);
      expect(before.AuditCount).toBe(0);
      const draft = await f.generate();
      await applySecurityPolicy(draft);
      expect(await readFile(target, "utf8")).toBe(POLICY);
      expect(descriptor()).toEqual(before);
    },
  );

  test.skipIf(process.platform !== "darwin")(
    "preserves access-control entries when replacing a read-only Unix policy",
    async () => {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      await chmod(target, 0o440);
      execFileSync("/bin/chmod", ["+a", "everyone allow read", target]);
      const accessControl = (path: string) =>
        execFileSync("/bin/ls", ["-ledn", path], { encoding: "utf8" })
          .split(/\r?\n/u)
          .slice(1)
          .join("\n");
      const previousAccess = accessControl(target);
      expect(previousAccess).toContain("allow read");
      const draft = await f.generate();
      await applySecurityPolicy(draft);
      expect(await readFile(target, "utf8")).toBe(POLICY);
      expect((await stat(target)).mode & 0o777).toBe(0o440);
      expect(accessControl(target)).toBe(previousAccess);
    },
  );

  test.skipIf(process.platform !== "linux")(
    "rejects an existing Linux policy when its security context cannot be preserved",
    async () => {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const previous = "# Existing policy\n";
      await writeFile(target, previous);
      const draft = await f.generate();
      const python = join(f.root, "synthetic-python");
      await writeFile(
        python,
        [
          `#!${PYTHON}`,
          "import os, sys",
          `python = ${JSON.stringify(PYTHON)}`,
          "if len(sys.argv) > 4 and sys.argv[1:3] == ['-I', '-c'] and \"'security.selinux'\" in sys.argv[3]:",
          "    print('[null,\"c3ludGhldGljX3Q6czA=\"]' if sys.argv[4].endswith('/SECURITY.md') else '[null,null]')",
          "    raise SystemExit(0)",
          "os.execv(python, [python, *sys.argv[1:]])",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
      await expect(
        applySecurityPolicy(draft, { pythonPath: python }),
      ).rejects.toThrow();
      expect(await readFile(target, "utf8")).toBe(previous);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "never drops an existing Windows resource-attribute access-control entry",
    async () => {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const original = "# Existing policy\n";
      await writeFile(target, original);
      const draft = await f.generate();
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const methods = [
        '[System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]',
        "public static extern bool Convert(string sddl, uint revision, out System.IntPtr descriptor, out uint size);",
        '[System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint="GetSecurityDescriptorSacl", SetLastError=true)]',
        "public static extern bool Sacl(System.IntPtr descriptor, out int present, out System.IntPtr acl, out int defaulted);",
        '[System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint="GetNamedSecurityInfoW", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]',
        "public static extern uint Read(string path, uint type, uint information, System.IntPtr owner, System.IntPtr group, System.IntPtr dacl, System.IntPtr sacl, out System.IntPtr descriptor);",
        '[System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint="SetNamedSecurityInfoW", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]',
        "public static extern uint Write(string path, uint type, uint information, System.IntPtr owner, System.IntPtr group, System.IntPtr dacl, System.IntPtr sacl);",
        '[System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint="LocalFree")]',
        "public static extern System.IntPtr Free(System.IntPtr memory);",
      ].join(" ");
      const helper = `Microsoft.PowerShell.Utility\\Add-Type -Name PolicyResource -Namespace CodexSecurityTest -MemberDefinition '${methods}'`;
      const environment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([key]) => key.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_PATH: target,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      const script = [
        "$ErrorActionPreference = 'Stop'",
        helper,
        "$descriptor = [System.IntPtr]::Zero; [uint32]$size = 0",
        'if (-not [CodexSecurityTest.PolicyResource]::Convert(\'S:(RA;;;;;WD;("CodexSynthetic",TS,0,"protected"))\', 1, [ref]$descriptor, [ref]$size)) { throw [System.ComponentModel.Win32Exception]::new() }',
        "try { $present = 0; $acl = [System.IntPtr]::Zero; $defaulted = 0; if (-not [CodexSecurityTest.PolicyResource]::Sacl($descriptor, [ref]$present, [ref]$acl, [ref]$defaulted)) { throw [System.ComponentModel.Win32Exception]::new() }; $status = [CodexSecurityTest.PolicyResource]::Write($env:CODEX_SECURITY_TEST_ACL_PATH, 1, 32, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, $acl); if ($status -ne 0) { throw [System.ComponentModel.Win32Exception]::new([int]$status) } } finally { [void][CodexSecurityTest.PolicyResource]::Free($descriptor) }",
      ].join("; ");
      execFileSync(
        powershell,
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        { env: environment, windowsHide: true },
      );
      const resource = () =>
        execFileSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            [
              "$ErrorActionPreference = 'Stop'",
              helper,
              "$descriptor = [System.IntPtr]::Zero",
              "$status = [CodexSecurityTest.PolicyResource]::Read($env:CODEX_SECURITY_TEST_ACL_PATH, 1, 32, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [ref]$descriptor); if ($status -ne 0) { throw [System.ComponentModel.Win32Exception]::new([int]$status) }",
              "try { $present = 0; $acl = [System.IntPtr]::Zero; $defaulted = 0; if (-not [CodexSecurityTest.PolicyResource]::Sacl($descriptor, [ref]$present, [ref]$acl, [ref]$defaulted)) { throw [System.ComponentModel.Win32Exception]::new() }; if ($present -eq 0 -or $acl -eq [System.IntPtr]::Zero) { throw 'The synthetic resource attribute was not retained.' }; $bytes = [byte[]]::new([uint16][System.Runtime.InteropServices.Marshal]::ReadInt16($acl, 2)); [System.Runtime.InteropServices.Marshal]::Copy($acl, $bytes, 0, $bytes.Length); [System.Convert]::ToBase64String($bytes) } finally { [void][CodexSecurityTest.PolicyResource]::Free($descriptor) }",
            ].join("; "),
          ],
          { encoding: "utf8", env: environment, windowsHide: true },
        ).trim();
      const previous = resource();
      expect(previous).not.toBe("");
      const applied = await applySecurityPolicy(draft).catch(
        (error: unknown) => error,
      );
      if (applied instanceof Error) {
        expect(applied.message).toContain(
          "Cannot preserve the existing SECURITY.md security descriptor",
        );
        expect(await readFile(target, "utf8")).toBe(original);
      } else {
        expect(await readFile(target, "utf8")).toBe(POLICY);
      }
      expect(resource()).toBe(previous);
      expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves an existing Windows security descriptor",
    async () => {
      const name = "preserves an existing Windows security descriptor";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      execFileSync(join(systemDirectory, "icacls.exe"), [
        target,
        "/setintegritylevel",
        "L",
      ]);
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const powershellEnvironment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([name]) => name.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_PATH: target,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      execFileSync(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
            "$acl = [System.Security.AccessControl.FileSecurity]::new()",
            "$acl.SetOwner($identity.User)",
            "$acl.SetAccessRuleProtection($true, $false)",
            "$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity.User, 'Read', 'Allow')",
            "$acl.AddAccessRule($rule)",
            "$acl.SetAuditRuleProtection($true, $false)",
            "$audit = [System.Security.AccessControl.FileSystemAuditRule]::new($identity.User, 'Read', 'Success')",
            "$acl.AddAuditRule($audit)",
            "Microsoft.PowerShell.Security\\Set-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -AclObject $acl",
          ].join("; "),
        ],
        {
          env: powershellEnvironment,
          windowsHide: true,
        },
      );
      const descriptor = (path = target) =>
        execFileSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl",
          ],
          {
            encoding: "utf8",
            env: {
              ...powershellEnvironment,
              CODEX_SECURITY_TEST_ACL_PATH: path,
            },
            windowsHide: true,
          },
        ).trim();
      const integrity = (path = target) => {
        const lines = execFileSync(
          join(systemDirectory, "icacls.exe"),
          [path],
          {
            encoding: "utf8",
            windowsHide: true,
          },
        ).split(/\r?\n/u);
        expect(lines[0]?.toLowerCase().startsWith(path.toLowerCase())).toBe(
          true,
        );
        lines[0] = lines[0]!.slice(path.length);
        return lines.map((line) => line.trim()).join("\n");
      };
      const before = descriptor();
      const beforeIntegrity = integrity();
      expect(before).toContain("D:P");
      expect(before).toContain("S:P");
      expect(before).toContain("(AU;SA;");
      expect(beforeIntegrity).toContain("(NW)");
      const draft = await f.generate();
      const originalLink = fsPromises.link;
      const originalRename = fsPromises.rename;
      let inspectedTemporary = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: async () => {
          throw Object.assign(new Error("hard links are unsupported"), {
            code: "ENOTSUP",
          });
        },
        rename: async (...args: Parameters<typeof originalRename>) => {
          if (args[0] === target) {
            const temporaryName = (await readdir(f.repository)).find(
              (name) =>
                name.startsWith(".SECURITY.md.") && name.endsWith(".tmp"),
            );
            expect(temporaryName).toBeDefined();
            const temporary = join(f.repository, temporaryName!);
            expect(await readFile(temporary, "utf8")).toBe(POLICY);
            expect((await stat(temporary)).mode & 0o777).toBe(
              (await stat(target)).mode & 0o777,
            );
            expect(descriptor(temporary)).toBe(before);
            expect(integrity(temporary)).toBe(beforeIntegrity);
            const reopenError = await open(temporary, "r+").then(
              async (handle) => {
                await handle.close();
                return null;
              },
              (error: unknown) => error,
            );
            expect(reopenError).toBeInstanceOf(Error);
            const reopenCode = (reopenError as NodeJS.ErrnoException).code;
            expect(reopenCode === "EACCES" || reopenCode === "EPERM").toBe(
              true,
            );
            inspectedTemporary = true;
          }
          return originalRename(...args);
        },
      }));
      try {
        await applySecurityPolicy(draft);
        expect(inspectedTemporary).toBe(true);
        expect(await readFile(target, "utf8")).toBe(POLICY);
        expect(descriptor()).toBe(before);
        expect(integrity()).toBe(beforeIntegrity);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
          rename: originalRename,
        }));
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves inherited Windows audit rules while applying an existing policy",
    async () => {
      const name =
        "preserves inherited Windows audit rules while applying an existing policy";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const environment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([key]) => key.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_DIRECTORY: f.repository,
        CODEX_SECURITY_TEST_ACL_PATH: target,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      execFileSync(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
            "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_DIRECTORY -Audit",
            "$rule = [System.Security.AccessControl.FileSystemAuditRule]::new($identity.User, 'Read', 'ContainerInherit, ObjectInherit', 'None', 'Success')",
            "$acl.AddAuditRule($rule)",
            "Microsoft.PowerShell.Security\\Set-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_DIRECTORY -AclObject $acl",
          ].join("; "),
        ],
        { env: environment, windowsHide: true },
      );
      const audit = () =>
        execFileSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            [
              "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit",
              "$rules = @($acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Microsoft.PowerShell.Core\\ForEach-Object { '{0}:{1}:{2}:{3}:{4}:{5}' -f $_.IdentityReference.Value, [int]$_.FileSystemRights, [int]$_.AuditFlags, [int]$_.InheritanceFlags, [int]$_.PropagationFlags, [int]$_.IsInherited } | Microsoft.PowerShell.Utility\\Sort-Object)",
              "[string]::Join([System.Environment]::NewLine, [string[]]$rules)",
            ].join("; "),
          ],
          { encoding: "utf8", env: environment, windowsHide: true },
        ).trim();
      const before = audit();
      expect(before).toMatch(/:1(?:\r?\n|$)/u);
      const draft = await f.generate();
      await applySecurityPolicy(draft);
      expect(await readFile(target, "utf8")).toBe(POLICY);
      expect(audit()).toBe(before);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "removes an inherited Windows integrity label when the existing policy has none",
    async () => {
      const name =
        "removes an inherited Windows integrity label when the existing policy has none";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      await writeFile(target, "# Existing policy\n");
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const powershell = join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const powershellEnvironment = {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            ([name]) => name.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        CODEX_SECURITY_TEST_ACL_PATH: target,
        PSModulePath: join(
          systemDirectory,
          "WindowsPowerShell",
          "v1.0",
          "Modules",
        ),
      };
      execFileSync(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
            "$acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit",
            "$acl.SetAuditRuleProtection($true, $false)",
            "$audit = [System.Security.AccessControl.FileSystemAuditRule]::new($identity.User, 'Read', 'Success')",
            "$acl.AddAuditRule($audit)",
            "Microsoft.PowerShell.Security\\Set-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -AclObject $acl",
          ].join("; "),
        ],
        { env: powershellEnvironment, windowsHide: true },
      );
      execFileSync(join(systemDirectory, "icacls.exe"), [
        f.repository,
        "/setintegritylevel",
        "(OI)(CI)L",
      ]);
      const integrity = (path: string) =>
        execFileSync(join(systemDirectory, "icacls.exe"), [path], {
          encoding: "utf8",
          windowsHide: true,
        });
      expect(integrity(target)).not.toContain("(NW)");
      const descriptor = () =>
        execFileSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -Audit | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl",
          ],
          { encoding: "utf8", env: powershellEnvironment, windowsHide: true },
        ).trim();
      const before = descriptor();
      expect(before).toContain("S:P");
      expect(before).toContain("(AU;SA;");
      const draft = await f.generate();
      const originalOpen = fsPromises.open;
      let inheritedLabel = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        open: async (...args: Parameters<typeof originalOpen>) => {
          const handle = await originalOpen(...args);
          if (
            String(args[0]).startsWith(join(f.repository, ".SECURITY.md.")) &&
            String(args[0]).endsWith(".tmp")
          ) {
            expect(integrity(String(args[0]))).toContain("(NW)");
            inheritedLabel = true;
          }
          return handle;
        },
      }));
      try {
        await applySecurityPolicy(draft);
        expect(inheritedLabel).toBe(true);
        expect(await readFile(target, "utf8")).toBe(POLICY);
        expect(integrity(target)).not.toContain("(NW)");
        expect(descriptor()).toBe(before);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          open: originalOpen,
        }));
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "restores a Windows policy when its security descriptor changes during replacement",
    async () => {
      const name =
        "restores a Windows policy when its security descriptor changes during replacement";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const previous = "# Existing policy\n";
      await writeFile(target, previous);
      const draft = await f.generate();
      const icacls = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
        "icacls.exe",
      );
      const descriptor = () =>
        execFileSync(icacls, [target], {
          encoding: "utf8",
          windowsHide: true,
        });
      const originalRename = fsPromises.rename;
      let changedDescriptor: string | undefined;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        rename: async (...args: Parameters<typeof originalRename>) => {
          if (args[0] === target) {
            execFileSync(icacls, [target, "/grant", "*S-1-1-0:R"], {
              windowsHide: true,
            });
            changedDescriptor = descriptor();
          }
          return originalRename(...args);
        },
      }));
      try {
        await expect(applySecurityPolicy(draft)).rejects.toBeInstanceOf(
          SecurityPolicyRecoveryError,
        );
        expect(changedDescriptor).toBeDefined();
        expect(await readFile(target, "utf8")).toBe(previous);
        expect(descriptor()).toBe(changedDescriptor!);
        expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          rename: originalRename,
        }));
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "retains a recovery file when its permissions change during installation",
    async () => {
      const name =
        "retains a recovery file when its permissions change during installation";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const previous = "# Existing policy\n";
      await writeFile(target, previous, { mode: 0o644 });
      await chmod(target, 0o644);
      const draft = await f.generate();
      const writer = await open(target, "r+");
      const originalLink = fsPromises.link;
      let changedPermissions = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: async (...args: Parameters<typeof originalLink>) => {
          await originalLink(...args);
          if (args[1] === target && String(args[0]).endsWith(".tmp")) {
            await writer.chmod(0o600);
            changedPermissions = true;
          }
        },
      }));
      try {
        const error = await applySecurityPolicy(draft).catch(
          (value: unknown) => value,
        );
        expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
        const recovery = (error as SecurityPolicyVerificationError)
          .recoveryPath;
        expect(recovery).toBeDefined();
        expect(changedPermissions).toBe(true);
        expect(await readFile(target, "utf8")).toBe(POLICY);
        expect(await readFile(recovery!, "utf8")).toBe(previous);
        expect((await stat(target)).mode & 0o777).toBe(0o644);
        expect((await stat(recovery!)).mode & 0o777).toBe(0o600);
        expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
        const retry = await applySecurityPolicy(draft).catch(
          (value: unknown) => value,
        );
        expect(retry).toBeInstanceOf(SecurityPolicyVerificationError);
        expect((retry as SecurityPolicyVerificationError).recoveryPath).toBe(
          recovery,
        );
      } finally {
        await writer.close();
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
        }));
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "retains a Windows recovery file when its descriptor changes during installation",
    async () => {
      const name =
        "retains a Windows recovery file when its descriptor changes during installation";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const previous = "# Existing policy\n";
      await writeFile(target, previous);
      const draft = await f.generate();
      const icacls = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
        "icacls.exe",
      );
      const descriptor = (path: string) => {
        const lines = execFileSync(icacls, [path], {
          encoding: "utf8",
          windowsHide: true,
        }).split(/\r?\n/u);
        expect(lines[0]?.toLowerCase().startsWith(path.toLowerCase())).toBe(
          true,
        );
        lines[0] = lines[0]!.slice(path.length);
        return lines.map((line) => line.trim()).join("\n");
      };
      const originalLink = fsPromises.link;
      let changedDescriptor: string | undefined;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: async (...args: Parameters<typeof originalLink>) => {
          await originalLink(...args);
          if (args[1] === target && String(args[0]).endsWith(".tmp")) {
            const recovery = `${args[0]}.previous`;
            execFileSync(icacls, [recovery, "/grant", "*S-1-1-0:R"], {
              windowsHide: true,
            });
            changedDescriptor = descriptor(recovery);
          }
        },
      }));
      try {
        const error = await applySecurityPolicy(draft).catch(
          (value: unknown) => value,
        );
        expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
        const recovery = (error as SecurityPolicyVerificationError)
          .recoveryPath;
        expect(recovery).toBeDefined();
        expect(changedDescriptor).toBeDefined();
        expect(await readFile(target, "utf8")).toBe(POLICY);
        expect(await readFile(recovery!, "utf8")).toBe(previous);
        expect(descriptor(recovery!)).toBe(changedDescriptor!);
        expect(descriptor(target)).not.toBe(changedDescriptor!);
        expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
        }));
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "never replaces a concurrent Unix policy when native installation is required",
    async () => {
      const name =
        "never replaces a concurrent Unix policy when native installation is required";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const previous = "# Existing policy\n";
      const concurrent = "# Concurrent policy\n";
      await writeFile(target, previous);
      const draft = await f.generate();
      const originalLink = fsPromises.link;
      let attemptedNativeMove = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: async (...args: Parameters<typeof originalLink>) => {
          if (args[1] === target && String(args[0]).endsWith(".tmp")) {
            await writeFile(target, concurrent, { flag: "wx" });
            attemptedNativeMove = true;
            throw Object.assign(new Error("hard links are unsupported"), {
              code: "ENOTSUP",
            });
          }
          return originalLink(...args);
        },
      }));
      try {
        const error = await applySecurityPolicy(draft).catch(
          (value: unknown) => value,
        );
        expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
        expect(attemptedNativeMove).toBe(true);
        expect((error as SecurityPolicyRecoveryError).cause).toBeInstanceOf(
          AggregateError,
        );
        expect(
          ((error as SecurityPolicyRecoveryError).cause as AggregateError)
            .errors[0],
        ).toMatchObject({ code: "EEXIST" });
        expect(await readFile(target, "utf8")).toBe(concurrent);
        expect(
          await readFile(
            (error as SecurityPolicyRecoveryError).recoveryPath,
            "utf8",
          ),
        ).toBe(previous);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
        }));
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "never replaces a concurrent Windows policy when native installation is required",
    async () => {
      const name =
        "never replaces a concurrent Windows policy when native installation is required";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const previous = "# Existing policy\n";
      const concurrent = "# Concurrent policy\n";
      await writeFile(target, previous);
      const draft = await f.generate();
      const originalLink = fsPromises.link;
      let attemptedNativeMove = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: async (...args: Parameters<typeof originalLink>) => {
          if (args[1] === target && String(args[0]).endsWith(".tmp")) {
            await writeFile(target, concurrent, { flag: "wx" });
            attemptedNativeMove = true;
            throw Object.assign(new Error("hard links are unsupported"), {
              code: "ENOTSUP",
            });
          }
          return originalLink(...args);
        },
      }));
      try {
        const error = await applySecurityPolicy(draft).catch(
          (value: unknown) => value,
        );
        expect(error).toBeInstanceOf(SecurityPolicyRecoveryError);
        expect(attemptedNativeMove).toBe(true);
        expect((error as SecurityPolicyRecoveryError).cause).toBeInstanceOf(
          AggregateError,
        );
        expect(
          ((error as SecurityPolicyRecoveryError).cause as AggregateError)
            .errors[0],
        ).toMatchObject({ code: "EEXIST" });
        expect(await readFile(target, "utf8")).toBe(concurrent);
        expect(
          await readFile(
            (error as SecurityPolicyRecoveryError).recoveryPath,
            "utf8",
          ),
        ).toBe(previous);
        expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
        }));
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "leaves an existing Windows policy unchanged when its security descriptor cannot be copied",
    async () => {
      const name =
        "leaves an existing Windows policy unchanged when its security descriptor cannot be copied";
      if (runTestInSubprocess(import.meta.path, name)) return;
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      const original = "# Existing policy\n";
      await writeFile(target, original);
      const draft = await f.generate();
      const originalOpen = fsPromises.open;
      const systemRoot = process.env["SystemRoot"];
      let attemptedCopy = false;
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        open: async (...args: Parameters<typeof originalOpen>) => {
          const handle = await originalOpen(...args);
          if (String(args[0]).startsWith(join(f.repository, ".SECURITY.md."))) {
            attemptedCopy = true;
            process.env["SystemRoot"] = join(f.root, "unavailable-system");
          }
          return handle;
        },
      }));

      try {
        await expect(applySecurityPolicy(draft)).rejects.toThrow(
          "Cannot preserve the existing SECURITY.md security descriptor and audit settings",
        );
        expect(attemptedCopy).toBe(true);
        expect(await readFile(target, "utf8")).toBe(original);
        expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
        expect(
          (await readdir(f.outputDir)).some((entry) =>
            entry.startsWith("recovery-SECURITY-"),
          ),
        ).toBe(false);
      } finally {
        if (systemRoot === undefined) delete process.env["SystemRoot"];
        else process.env["SystemRoot"] = systemRoot;
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          open: originalOpen,
        }));
      }
    },
  );

  test("preserves read-only mode when temporary cleanup changes permissions", async () => {
    const name =
      "preserves read-only mode when temporary cleanup changes permissions";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const originalRm = fsPromises.rm;
    const originalCopyFile = fsPromises.copyFile;
    for (const existing of [false, true]) {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      if (existing) {
        await writeFile(target, "# Existing policy\n");
        await chmod(target, 0o444);
      }
      const draft = await f.generate();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        copyFile: async (...args: Parameters<typeof originalCopyFile>) => {
          if (!existing) await chmod(args[0], 0o444);
          return originalCopyFile(...args);
        },
        rm: async (path: string, options: Parameters<typeof originalRm>[1]) => {
          if (path.endsWith(".tmp")) await chmod(path, 0o666);
          return await originalRm(path, options);
        },
      }));
      try {
        await applySecurityPolicy(draft);
        expect(await readFile(target, "utf8")).toBe(POLICY);
        expect((await stat(target)).mode & 0o200).toBe(0);
        expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          rm: originalRm,
          copyFile: originalCopyFile,
        }));
        await chmod(target, 0o644).catch(() => undefined);
      }
    }
  });

  test("finishes verification when cancellation arrives after the write commits", async () => {
    const name =
      "finishes verification when cancellation arrives after the write commits";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const originalLink = fsPromises.link;
    const originalRename = fsPromises.rename;
    const originalCopyFile = fsPromises.copyFile;
    for (const existing of [false, true]) {
      const f = await fixture();
      if (existing)
        await writeFile(
          join(f.repository, "SECURITY.md"),
          "# Existing policy\n",
        );
      const draft = await f.generate();
      const controller = new AbortController();
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        copyFile: async (...args: Parameters<typeof originalCopyFile>) => {
          await originalCopyFile(...args);
          if (args[1] === draft.targetPath)
            controller.abort(new Error("cancel after commit"));
        },
        link: async (source: string, destination: string) => {
          await originalLink(source, destination);
          if (destination === draft.targetPath)
            controller.abort(new Error("cancel after commit"));
        },
        rename: async (source: string, destination: string) => {
          await originalRename(source, destination);
          if (destination === draft.targetPath)
            controller.abort(new Error("cancel after commit"));
        },
      }));
      try {
        const applied = await applySecurityPolicy(draft, {
          pythonPath: PYTHON,
          signal: controller.signal,
        });
        expect(applied.targetPath).toBe(draft.targetPath);
        expect(applied.recoveryPath === null).toBe(!existing);
        expect(controller.signal.aborted).toBe(true);
        expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      } finally {
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          link: originalLink,
          rename: originalRename,
          copyFile: originalCopyFile,
        }));
      }
    }
  });

  test("rejects preview and application after a component changes Git roots", async () => {
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
      await expect(applySecurityPolicy(draft)).rejects.toThrow(
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
    expect(
      await applySecurityPolicy(draft, { pythonPath: "missing-python" }),
    ).toEqual({
      status: "unchanged",
      targetPath: draft.targetPath,
      recoveryPath: null,
    });
    await writeFile(draft.targetPath, "# Concurrent policy\n");
    await expect(securityPolicyDiff(draft, PYTHON)).rejects.toThrow(
      "changed after",
    );
    await expect(applySecurityPolicy(draft)).rejects.toThrow("changed after");
  });

  test("rejects new out-of-scope aliases when applying an unchanged draft", async () => {
    for (const [directory, message] of [
      ["sibling", "outside the selected component"],
      [".github", "separate vulnerability-reporting policy"],
    ] as const) {
      const f = await fixture();
      const component = join(f.repository, "component");
      const target = join(component, "SECURITY.md");
      await mkdir(component);
      await writeFile(target, POLICY);
      const draft = await f.generate({ path: "component" });
      const alias = join(f.repository, directory, "SECURITY.md");
      await mkdir(dirname(alias));
      await symlink(target, alias, "file");

      await expect(
        applySecurityPolicy(draft, { pythonPath: "missing-python" }),
      ).rejects.toThrow(message);
      expect(await readFile(target, "utf8")).toBe(POLICY);
      expect((await lstat(alias)).isSymbolicLink()).toBe(true);
    }
  });

  test("rechecks policy changes made while preparing a diff", async () => {
    for (const changed of ["target", "inherited", "applied"]) {
      const f = await fixture();
      await mkdir(join(f.repository, "component"));
      const rootPolicy = join(f.repository, "SECURITY.md");
      await writeFile(rootPolicy, "# Original root policy\n");
      const draft = await f.generate({ path: "component" });
      const preview = securityPolicyDiff(draft, async () => {
        await writeFile(
          changed === "inherited" ? rootPolicy : draft.targetPath,
          changed === "applied" ? draft.content : "# Concurrent policy\n",
        );
        return PYTHON;
      });
      if (changed === "applied") expect(await preview).toBe("");
      else await expect(preview).rejects.toThrow("changed after");
    }
  });

  test("invalidates saved component drafts when inherited policies change", async () => {
    for (const change of ["edit", "add", "remove"] as const) {
      const f = await fixture();
      const component = join(f.repository, "services", "api");
      const rootPolicy = join(f.repository, "SECURITY.md");
      await mkdir(component, { recursive: true });
      await writeFile(rootPolicy, "# Root policy\n");
      if (change === "edit")
        await writeFile(join(component, "SECURITY.md"), POLICY);
      const generated = await f.generate({ path: "services/api" });
      const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir, {
        path: "services/api",
      });
      expect(draft.inheritedPolicySha256).toBe(generated.inheritedPolicySha256);
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
      await expect(
        applySecurityPolicy(draft, { pythonPath: "missing-python" }),
      ).rejects.toThrow("inherited SECURITY.md changed");
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        draft.previousContent,
      );
    }
  });

  test("applies a component policy without changing a safe inherited link", async () => {
    const f = await fixture();
    const ownerPolicy = join(f.repository, "owner-policy.md");
    const inherited = join(f.repository, "SECURITY.md");
    await mkdir(join(f.repository, "component"));
    await writeFile(ownerPolicy, "# Owner policy\n");
    await symlink(ownerPolicy, inherited, "file");
    const draft = await f.generate({ path: "component" });
    const hash = (text: string) =>
      createHash("sha256").update(text).digest("hex");
    const links = {
      links: [["SECURITY.md", await readlink(inherited)]],
      destination: "owner-policy.md",
    };
    expect(draft.inheritedPolicySha256).toBe(
      hash(
        JSON.stringify([
          ["SECURITY.md", `link:${hash(JSON.stringify(links))}`],
          ["SECURITY.md", hash("# Owner policy\n")],
        ]),
      ),
    );
    await applySecurityPolicy(draft);
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    expect(await readFile(inherited, "utf8")).toBe("# Owner policy\n");
    expect((await lstat(inherited)).isSymbolicLink()).toBe(true);
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
    const linkedPolicy = join(f.repository, "owner-policy.md");
    await mkdir(join(f.repository, "component"));
    await writeFile(linkedPolicy, "# Owner policy\n");
    await symlink(linkedPolicy, join(f.repository, "SECURITY.md"), "file");
    const draft = await f.generate({ path: "component" });
    expect(await securityPolicyDiff(draft, PYTHON)).toContain(
      "b/component/SECURITY.md",
    );
    await writeFile(linkedPolicy, "# Changed owner policy\n");
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
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

  test("rejects policy aliases in a sibling component", async () => {
    for (const [existing, chained] of [
      [false, false],
      [true, false],
      [false, true],
      [true, true],
    ]) {
      const f = await fixture();
      const component = join(f.repository, "component");
      const target = join(component, "SECURITY.md");
      const alias = join(f.repository, "component-other", "SECURITY.md");
      await mkdir(component);
      await mkdir(dirname(alias));
      if (existing) await writeFile(target, "# Original policy\n");
      const destination = chained
        ? join(f.repository, "policy-link.md")
        : target;
      if (chained) await symlink(target, destination, "file");
      await symlink(destination, alias, "file");
      const draft = await f.generate({ path: "component" });
      await expect(applySecurityPolicy(draft)).rejects.toThrow(
        "outside the selected component",
      );
      expect((await lstat(alias)).isSymbolicLink()).toBe(true);
      expect(await readSecurityPolicy(target)).toBe(
        existing ? "# Original policy\n" : null,
      );
    }
  });

  test("allows aliases within the selected policy scope", async () => {
    for (const scope of [".", "component"]) {
      const f = await fixture();
      const component = join(f.repository, scope);
      const descendant = join(component, "child", "SECURITY.md");
      const target = join(component, "SECURITY.md");
      await mkdir(dirname(descendant), { recursive: true });
      await symlink(target, descendant, "file");
      const draft = await f.generate({ path: scope });
      await applySecurityPolicy(draft);
      expect(await readFile(descendant, "utf8")).toBe(POLICY);
      expect((await lstat(descendant)).isSymbolicLink()).toBe(true);
    }
  });

  test("keeps descendant checkout reporting policies out of scope", async () => {
    for (const kind of ["nested", "submodule"] as const) {
      for (const linkedDirectory of [false, true]) {
        const f = await fixture();
        policyGit(f.repository, "init", "--quiet");
        let child: string;
        if (kind === "submodule") {
          child = await addPolicySubmodule(
            f.repository,
            join(f.root, "submodule-source"),
            "child",
          );
        } else {
          child = join(f.repository, "child");
          await mkdir(child);
          policyGit(child, "init", "--quiet");
        }
        const reporting = linkedDirectory
          ? join(f.repository, "reporting")
          : join(child, ".github");
        await mkdir(reporting);
        const target = join(f.repository, "SECURITY.md");
        const draft = await f.generate();
        await symlink(target, join(reporting, "SECURITY.md"), "file");
        if (linkedDirectory)
          await symlink(
            reporting,
            join(child, ".github"),
            process.platform === "win32" ? "junction" : "dir",
          );
        await expect(applySecurityPolicy(draft)).rejects.toThrow(
          "separate vulnerability-reporting policy",
        );
        expect(await readSecurityPolicy(target)).toBe(null);
      }
    }
  });

  test("leaves unrelated aliases in descendant checkouts alone", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    const child = join(f.repository, "child");
    await mkdir(child);
    policyGit(child, "init", "--quiet");
    const separate = join(f.repository, "child-policy.md");
    await writeFile(separate, "# Child policy\n");
    await symlink(separate, join(child, "SECURITY.md"), "file");
    await applySecurityPolicy(await f.generate());
    expect(await readFile(separate, "utf8")).toBe("# Child policy\n");
  });

  test("preserves separate reporting policies when applying a root draft", async () => {
    const f = await fixture();
    for (const directory of [".github", "docs"]) {
      await mkdir(join(f.repository, directory));
      await writeFile(
        join(f.repository, directory, "SECURITY.md"),
        "# Reporting a vulnerability\n",
      );
    }
    const draft = await f.generate();
    await applySecurityPolicy(draft);
    for (const directory of [".github", "docs"])
      expect(
        await readFile(join(f.repository, directory, "SECURITY.md"), "utf8"),
      ).toBe("# Reporting a vulnerability\n");
  });

  test("treats non-directory reporting-policy paths as absent", async () => {
    for (const entry of [".github", "docs"]) {
      const f = await fixture();
      const path = join(f.repository, entry);
      await writeFile(path, "A regular source file.\n");
      const draft = await f.generate();
      expect(await securityPolicyDiff(draft, PYTHON)).toContain(
        "b/SECURITY.md",
      );
      await applySecurityPolicy(draft);
      expect(await readFile(path, "utf8")).toBe("A regular source file.\n");
    }
  });

  test("validates descendant policy links before applying a draft", async () => {
    for (const scope of [".", "component"]) {
      for (const existing of [false, true]) {
        const f = await fixture();
        const component = join(f.repository, scope);
        const alias = join(component, "child", "SECURITY.md");
        const outside = join(f.root, "outside-policy.md");
        await mkdir(dirname(alias), { recursive: true });
        if (existing) await writeFile(outside, "# Outside policy\n");
        const draft = await f.generate({ path: scope });
        await symlink(outside, alias, "file");
        expect(await securityPolicyDiff(draft, PYTHON)).toContain(
          "SECURITY.md",
        );
        await expect(
          applySecurityPolicy(draft, { pythonPath: "missing-python" }),
        ).rejects.toThrow("outside the repository");
        expect(await readSecurityPolicy(draft.targetPath)).toBe(null);
      }
    }
  });

  test("rejects root drafts that would change a linked reporting policy", async () => {
    for (const directory of [".github", "docs"]) {
      for (const [existing, chained] of [
        [false, false],
        [true, false],
        [false, true],
        [true, true],
      ]) {
        const f = await fixture();
        const target = join(f.repository, "SECURITY.md");
        const reporting = join(f.repository, directory, "SECURITY.md");
        await mkdir(dirname(reporting));
        if (existing) await writeFile(target, "# Original policy\n");
        const draft = await f.generate();
        const destination = chained
          ? join(f.repository, "policy-link.md")
          : target;
        if (chained) await symlink(target, destination, "file");
        await symlink(destination, reporting, "file");
        expect(await securityPolicyDiff(draft, PYTHON)).toContain(
          "b/SECURITY.md",
        );
        await expect(
          applySecurityPolicy(draft, { pythonPath: "missing-python" }),
        ).rejects.toThrow("separate vulnerability-reporting policy");
        expect(await readSecurityPolicy(target)).toBe(
          existing ? "# Original policy\n" : null,
        );
      }
    }
  });

  test("rejects reporting-policy aliases through directory links", async () => {
    for (const directory of [".github", "docs"]) {
      const f = await fixture();
      const draft = await f.generate();
      await symlink(
        f.repository,
        join(f.repository, directory),
        process.platform === "win32" ? "junction" : "dir",
      );
      await expect(applySecurityPolicy(draft)).rejects.toThrow(
        "separate vulnerability-reporting policy",
      );
      expect(await readSecurityPolicy(draft.targetPath)).toBe(null);
    }
  });

  test("stops policy-link walks before inspecting another target", async () => {
    const name = "stops policy-link walks before inspecting another target";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const originalLstat = fsPromises.lstat;
    const originalReadlink = fsPromises.readlink;
    const originalRealpath = fsPromises.realpath;
    const inspected: string[] = [];
    let outside = "";
    const record = (path: unknown) => {
      const value = String(path);
      if (value === outside || value.startsWith(`${outside}${sep}`))
        inspected.push(value);
    };
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      lstat: (...args: Parameters<typeof originalLstat>) => {
        record(args[0]);
        return originalLstat(...args);
      },
      readlink: (...args: Parameters<typeof originalReadlink>) => {
        record(args[0]);
        return originalReadlink(...args);
      },
      realpath: (...args: Parameters<typeof originalRealpath>) => {
        record(args[0]);
        return originalRealpath(...args);
      },
    }));
    try {
      for (const viaDirectory of [false, true]) {
        for (const existing of [false, true]) {
          const f = await fixture();
          outside = join(f.root, "outside");
          const target = join(f.repository, "component", "SECURITY.md");
          const alias = join(f.repository, "sibling", "SECURITY.md");
          await mkdir(dirname(target));
          await mkdir(dirname(alias));
          await mkdir(outside);
          if (existing) await writeFile(target, "# Original policy\n");
          const externalLink = join(outside, "policy-link.md");
          await symlink(target, externalLink, "file");
          let destination = externalLink;
          if (viaDirectory) {
            const directoryLink = join(f.repository, "outside-link");
            await symlink(
              outside,
              directoryLink,
              process.platform === "win32" ? "junction" : "dir",
            );
            destination = join(directoryLink, "policy-link.md");
          }
          await symlink(destination, alias, "file");
          const draft = await f.generate({ path: "component" });
          inspected.length = 0;
          await expect(applySecurityPolicy(draft)).rejects.toThrow(
            "outside the repository",
          );
          expect(inspected).toEqual([]);
        }
      }
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        lstat: originalLstat,
        readlink: originalReadlink,
        realpath: originalRealpath,
      }));
    }
  });

  test("ignores unrelated broken policies, Git metadata, and directory links", async () => {
    const f = await fixture();
    execFileSync("git", ["init", "--quiet", f.repository]);
    const target = join(f.repository, "component", "SECURITY.md");
    const cycle = join(f.repository, "unrelated", "SECURITY.md");
    const intermediate = join(f.repository, "unrelated", "cycle.md");
    const outside = join(f.root, "linked-directory");
    await mkdir(dirname(target));
    await mkdir(dirname(cycle));
    await mkdir(outside);
    await symlink(
      join(f.repository, "missing", "owner-policy.md"),
      join(f.repository, "SECURITY.md"),
      "file",
    );
    await symlink(intermediate, cycle, "file");
    await symlink(cycle, intermediate, "file");
    await symlink(target, join(f.repository, ".git", "SECURITY.md"), "file");
    await symlink(target, join(outside, "SECURITY.md"), "file");
    await symlink(
      outside,
      join(f.repository, "linked-directory"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const draft = await f.generate({ path: "component" });
    await applySecurityPolicy(draft);
    expect(await readFile(target, "utf8")).toBe(POLICY);
    expect((await lstat(cycle)).isSymbolicLink()).toBe(true);
  });

  test("ignores case-equivalent Git metadata without hiding ordinary directories", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    const target = join(f.repository, "component", "SECURITY.md");
    await mkdir(dirname(target));
    await rename(
      join(f.repository, ".git"),
      join(f.repository, "git-metadata"),
    );
    await rename(
      join(f.repository, "git-metadata"),
      join(f.repository, ".GIT"),
    );
    await symlink(target, join(f.repository, ".GIT", "SECURITY.md"), "file");
    const gitRecognizesDirectory = await lstat(join(f.repository, ".git")).then(
      () => true,
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return false;
        throw error;
      },
    );
    const draft = await f.generate({ path: "component" });
    if (gitRecognizesDirectory) {
      await applySecurityPolicy(draft);
      expect(await readFile(target, "utf8")).toBe(POLICY);
    } else {
      await expect(applySecurityPolicy(draft)).rejects.toThrow(
        /outside the selected component|Git metadata/u,
      );
      expect(await readSecurityPolicy(target)).toBe(null);
    }
  });

  test("rejects case aliases to a missing component policy on every platform", async () => {
    for (const name of ["security.md", "\u017fECURITY.md"]) {
      const f = await fixture();
      await mkdir(join(f.repository, "component"));
      await mkdir(join(f.repository, "sibling"));
      await symlink(
        join(f.repository, "component", name),
        join(f.repository, "sibling", "SECURITY.md"),
        "file",
      );
      const draft = await f.generate({ path: "component" });
      await expect(
        applySecurityPolicy(draft, { pythonPath: "missing-python" }),
      ).rejects.toThrow("outside the selected component");
      expect(await readSecurityPolicy(draft.targetPath)).toBe(null);
    }
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
    await applySecurityPolicy(draft);
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
  });

  test("invalidates component drafts when inherited links change", async () => {
    for (const change of ["add", "remove", "retarget", "dangle"] as const) {
      const f = await fixture();
      const component = join(f.repository, "component");
      const target = join(component, "SECURITY.md");
      const inherited = join(f.repository, "SECURITY.md");
      const ownerPolicy = join(f.repository, "owner-policy.md");
      const intermediate = join(f.repository, "policy-link.md");
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
      await expect(
        applySecurityPolicy(draft, { pythonPath: "missing-python" }),
      ).rejects.toThrow("inherited SECURITY.md changed");
      expect(await readFile(target, "utf8")).toBe("# Original policy\n");
    }
  });

  test("rejects saved drafts when an outside scope starts linking to the target", async () => {
    for (const policyDirectory of [".", "sibling"]) {
      for (const existing of [false, true]) {
        const f = await fixture();
        await mkdir(join(f.repository, "component"));
        const target = join(f.repository, "component", "SECURITY.md");
        const alias = join(f.repository, policyDirectory, "SECURITY.md");
        await mkdir(dirname(alias), { recursive: true });
        if (existing) await writeFile(target, "# Original policy\n");
        await f.generate({ path: "component" });
        await symlink(target, alias, "file");
        const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir, {
          path: "component",
        });
        await expect(
          applySecurityPolicy(draft, { pythonPath: "missing-python" }),
        ).rejects.toThrow("outside the selected component");
        expect(await readSecurityPolicy(target)).toBe(
          existing ? "# Original policy\n" : null,
        );
      }
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

  test("checks policy aliases before and after a policy write", async () => {
    for (const policyDirectory of [".", "sibling"]) {
      for (const timing of ["before", "after"] as const) {
        const f = await fixture();
        await mkdir(join(f.repository, "component"));
        await mkdir(join(f.repository, policyDirectory), { recursive: true });
        const pluginPath = await policyPlugin(
          f.root,
          [
            "import pathlib, sys",
            "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
            "target = root / 'component' / 'SECURITY.md'",
            `if ${timing === "before" ? "not " : ""}target.exists():`,
            `    (root / ${JSON.stringify(policyDirectory)} / 'SECURITY.md').symlink_to(target)`,
            "print('resolver accepted the current policy chain')",
          ].join("\n"),
        );
        const draft = await f.generate({ path: "component", pluginPath });
        await expect(applySecurityPolicy(draft)).rejects.toThrow(
          timing === "before"
            ? "outside the selected component"
            : "was written",
        );
        expect(await readSecurityPolicy(draft.targetPath)).toBe(
          timing === "before" ? null : POLICY,
        );
        if (timing === "after")
          await expect(applySecurityPolicy(draft)).rejects.toBeInstanceOf(
            SecurityPolicyVerificationError,
          );
      }
    }
  });

  test("checks inherited policies around application and verification", async () => {
    for (const timing of ["before", "after"] as const) {
      const f = await fixture();
      await mkdir(join(f.repository, "component"));
      await writeFile(join(f.repository, "SECURITY.md"), "# Root policy\n");
      const pluginPath = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          "target = root / 'component' / 'SECURITY.md'",
          `if ${timing === "before" ? "not " : ""}target.exists():`,
          "    (root / 'SECURITY.md').write_text('# New root policy\\n')",
          "print('resolver accepted the current policy chain')",
        ].join("\n"),
      );
      const draft = await f.generate({ path: "component", pluginPath });
      const error = await applySecurityPolicy(draft).catch(
        (value: unknown) => value,
      );
      if (timing === "before")
        expect(String(error)).toContain("inherited SECURITY.md changed");
      else expect(error).toBeInstanceOf(SecurityPolicyVerificationError);
      expect(await readSecurityPolicy(draft.targetPath)).toBe(
        timing === "before" ? null : POLICY,
      );
    }
  });

  test("honors cancellation before applying a draft", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const signal = AbortSignal.abort(new Error("canceled"));
    await expect(
      applySecurityPolicy(draft, { pythonPath: PYTHON, signal }),
    ).rejects.toThrow("canceled");
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("does not overwrite a policy changed after generation", async () => {
    const f = await fixture();
    const draft = await f.generate();
    await writeFile(draft.targetPath, "# Someone else's new policy\n");
    await expect(applySecurityPolicy(draft)).rejects.toThrow("changed after");
    expect(await readFile(draft.targetPath, "utf8")).toBe(
      "# Someone else's new policy\n",
    );
  });

  test("binds saved drafts to the explicitly selected repository and component", async () => {
    const f = await fixture();
    await mkdir(join(f.repository, "component"));
    await f.generate({ path: "component" });
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow("different repository or component");
    const draft = await loadSecurityPolicyDraft(f.repository, f.outputDir, {
      path: "component",
    });
    expect(draft.scope).toBe("component");
    const other = await fixture();
    await expect(
      loadSecurityPolicyDraft(other.repository, f.outputDir),
    ).rejects.toThrow("different repository or component");
  });

  test("rejects linked policy files and replaced component directories", async () => {
    const f = await fixture();
    const component = join(f.repository, "component");
    await mkdir(component);
    const draft = await f.generate({ path: "component" });
    const external = join(f.root, "external");
    await mkdir(external);
    const externalPolicy = join(external, "SECURITY.md");
    await writeFile(externalPolicy, "# External policy\n");
    await symlink(externalPolicy, draft.targetPath);
    await expect(applySecurityPolicy(draft)).rejects.toThrow("regular file");
    await rm(draft.targetPath);
    await rename(component, join(f.repository, "old-component"));
    await symlink(
      external,
      component,
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(applySecurityPolicy(draft)).rejects.toThrow(
      "outside the repository",
    );
    expect(await readFile(externalPolicy, "utf8")).toBe("# External policy\n");
    expect((await lstat(component)).isSymbolicLink()).toBe(true);
  });

  test("rejects a modified original-content checkpoint", async () => {
    const f = await fixture();
    await f.generate();
    await writeFile(
      join(f.outputDir, "previous-SECURITY.md"),
      "# Forged baseline\n",
    );
    await expect(
      loadSecurityPolicyDraft(f.repository, f.outputDir),
    ).rejects.toThrow("checkpoint has changed");
  });
});
