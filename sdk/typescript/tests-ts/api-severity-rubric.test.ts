import { hash } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import { bundledSeverityRubric } from "../src/severity-rubric.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import { codexFactory, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("a scan accepts policy checkout rubrics and rejects links to unrelated files", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const policy = join(root, "policy");
  const policyCheckout = join(root, "policy-checkout");
  const home = join(root, "home");
  await Promise.all([mkdir(repository), mkdir(policy), mkdir(home)]);
  await mkdir(join(policyCheckout, ".git"), { recursive: true });
  const linkType = process.platform === "win32" ? "junction" : "dir";
  const checkoutLink = join(repository, "documents");
  const alias = join(root, "selected-policy");
  await writeFile(join(policy, "rubric.md"), "External policy.");
  await symlink(policy, checkoutLink, linkType);
  await symlink(checkoutLink, alias, linkType);
  const policyLink = join(policyCheckout, "current");
  await symlink(policy, policyLink, linkType);
  const versions = join(policyCheckout, "versions");
  const stable = join(policyCheckout, "stable");
  await mkdir(versions);
  await writeFile(join(versions, "rubric.md"), "Approved synthetic policy.");
  await symlink(versions, stable, linkType);
  const prompts: string[] = [];
  await using client = TestClient.withDependencies({
    environment: {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
    prepareRuntime: async () => preparedRuntime(home),
    prepareOutputDir: async () => mkdtemp(join(root, "scan-")),
    resolvePluginPython: async () => "python3",
    runWorkbench: async (_options, args, input) => mockWorkbench(args, input),
    createCodex: codexFactory(async (prompt: string) => {
      prompts.push(prompt);
      throw new Error("Synthetic turn received the policy");
    }),
  });
  await expect(
    client.run(repository, { rubricPath: join(alias, "rubric.md") }),
  ).rejects.toThrow("Input files must not follow repository directory links");
  await expect(
    client.run(repository, { rubricPath: join(policyLink, "rubric.md") }),
  ).rejects.toThrow("Synthetic turn received the policy");
  await expect(
    client.run(repository, { rubricPath: join(stable, "rubric.md") }),
  ).rejects.toThrow("Synthetic turn received the policy");
  expect(prompts).toHaveLength(2);
  expect(prompts[0]).toContain("External policy.");
  expect(prompts[1]).toContain("Approved synthetic policy.");
});

for (const mode of ["standard", "deep"] as const) {
  test.each(["bundled", "remote", "custom file"] as const)(
    `${mode} workflow keeps its %s rubric across an interrupted scan and retry`,
    async (source) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const home = join(root, "codex-home");
      await Promise.all([mkdir(repository), mkdir(home)]);
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC:
          source === "bundled" ? undefined : "1",
      };
      const python = Bun.which("python3") ?? Bun.which("python");
      if (!python) throw new Error("Python is required for this test.");
      const markdown = `Use this synthetic ${source} policy.`;
      const rubricPath = join(root, "policy.md");
      if (source === "custom file") await writeFile(rubricPath, markdown);
      const expected =
        source === "bundled"
          ? bundledSeverityRubric
          : {
              markdown,
              revision: source === "custom file" ? 1 : 7,
              sha256: hash("sha256", markdown),
            };
      const config = {
        name: "codex_security_default_severity_rubric",
        value: { markdown, revision: 7 },
      };
      using request = spyOn(globalThis, "fetch").mockResolvedValue(
        Response.json(config),
      );
      const prompts: string[] = [];
      const workflowId = "rubric-retry";
      const registrations: unknown[] = [];
      for (const attempt of [1, 2]) {
        await using client = TestClient.withDependencies({
          environment,
          prepareRuntime: async () => preparedRuntime(home),
          prepareOutputDir: async () => mkdtemp(join(root, "scan-")),
          resolvePluginPython: async () => python,
          runWorkbench: async (options, args, input) => {
            if (args[0] === "register-cli-scan")
              registrations.push(JSON.parse(input!).recipe.severityRubric);
            if (
              [
                "finding-workflow",
                "register-cli-scan",
                "get-scan",
                "get-scan-feedback",
              ].includes(args[0]!)
            )
              return runWorkbench(options, args, input);
            return mockWorkbench(args, input);
          },
          createCodex: codexFactory(async (prompt: string) => {
            prompts.push(prompt);
            throw new Error("Synthetic transport disconnected");
          }),
        });
        await expect(
          client.run(repository, {
            workflowId,
            mode,
            ...(source === "custom file" ? { rubricPath } : {}),
          }),
        ).rejects.toThrow("Synthetic transport disconnected");
        expect(registrations).toHaveLength(attempt);
        expect(registrations.at(-1)).toEqual(expected);
        expect(prompts).toHaveLength(attempt);
        expect(prompts.at(-1)).toContain(
          JSON.stringify({ severityRubric: expected }),
        );
        expect(request).toHaveBeenCalledTimes(source === "remote" ? 1 : 0);
        if (attempt === 1) {
          if (source === "custom file") await rm(rubricPath);
          request.mockResolvedValue(
            Response.json({
              ...config,
              value: { markdown: "A newer policy for new scans.", revision: 8 },
            }),
          );
          environment.CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC = "1";
        }
      }
    },
    60_000,
  );
}
