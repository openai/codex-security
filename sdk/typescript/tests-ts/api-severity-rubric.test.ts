import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import { CodexSecurity } from "../src/api.js";
import * as rubricSource from "../src/severity-rubric.js";
import { bundledSeverityRubric } from "../src/severity-rubric.js";
import { mockWorkbench } from "./support/api-client.js";
import { codexFactory, scanRuntimeDependencies } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
afterEach(() => mock.restore());

function testClient(
  dependencies: Partial<
    NonNullable<ConstructorParameters<typeof CodexSecurity>[1]>
  >,
) {
  return new CodexSecurity(
    {},
    {
      environment: {},
      createCodex: () => {
        throw new Error("Unexpected model invocation");
      },
      probeCodexSandbox: async () => {},
      prepareScanArtifactRestorer: async () => ({ restore: async () => {} }),
      ...dependencies,
    },
    { surface: "sdk" },
  );
}

test.each(["standard", "deep"] as const)(
  "%s scans isolate default-off and opted-in policies across concurrent clients",
  async (mode) => {
    const config = { markdown: "# Remote scan policy", revision: 9 };
    const remotePolicy = {
      ...config,
      sha256: createHash("sha256").update(config.markdown).digest("hex"),
    };
    const key = createHash("sha256")
      .update("codex_security_default_severity_rubric")
      .digest("base64");
    const request = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        hash_used: "sha256",
        dynamic_configs: { [key]: { value: config } },
      }),
    );
    const policies = await Promise.all(
      [undefined, "0", "1"].map(async (value) => {
        const root = await temporaryDirectory();
        const repository = join(root, "repository");
        const home = join(root, "home");
        const scan = join(root, "scan");
        await Promise.all([repository, home, scan].map((path) => mkdir(path)));
        const runtime = scanRuntimeDependencies(home, scan);
        let savedPolicy: unknown;
        await using client = testClient({
          ...runtime,
          environment: {
            CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC: value,
          },
          canRunDirectDeepScan: () => false,
          runWorkbench: async (_options, args, input) => {
            if (args[0] === "register-cli-scan")
              savedPolicy = JSON.parse(input!).recipe.severityRubric;
            return mockWorkbench(args, input);
          },
          createCodex: codexFactory(async () => {
            throw new Error("Captured scan policy");
          }),
        });
        await expect(client.run(repository, { mode })).rejects.toThrow(
          "Captured scan policy",
        );
        return savedPolicy;
      }),
    );
    expect(policies).toEqual([
      bundledSeverityRubric,
      bundledSeverityRubric,
      remotePolicy,
    ]);
    expect(request).toHaveBeenCalledTimes(1);
  },
);

test.each(["standard", "deep"] as const)(
  "%s scans retain one resolved policy in the model and saved recipe",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    const scan = join(root, "scan");
    await Promise.all([repository, home, scan].map((path) => mkdir(path)));
    const policy = { ...bundledSeverityRubric, revision: 7 };
    const resolve = spyOn(
      rubricSource,
      "getDefaultSeverityRubric",
    ).mockResolvedValue({ ...policy });
    let registration: any;
    let prompt: string | undefined;
    await using client = testClient({
      ...scanRuntimeDependencies(home, scan),
      canRunDirectDeepScan: () => false,
      runWorkbench: async (_options, args, input) => {
        if (args[0] === "register-cli-scan") registration = JSON.parse(input!);
        return mockWorkbench(args, input);
      },
      createCodex: codexFactory(async (value: string) => {
        prompt = value;
        policy.revision = 8;
        throw new Error("Captured scan policy");
      }),
    });
    await expect(
      client.run(repository, { mode, scanPrompt: "Review authorization." }),
    ).rejects.toThrow("Captured scan policy");
    expect(resolve).toHaveBeenCalledTimes(1);
    const saved = { ...bundledSeverityRubric, revision: 7 };
    expect(registration.recipe.severityRubric).toEqual(saved);
    expect(registration.recipe.requiresScanPrompt).toBe(true);
    expect(registration.userContext).toBe("Review authorization.");
    expect(prompt).toContain(JSON.stringify({ severityRubric: saved }));
  },
);

test("explicit scan policy is captured before asynchronous preparation and bypasses defaults", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const home = join(root, "home");
  const scan = join(root, "scan");
  await Promise.all([repository, home, scan].map((path) => mkdir(path)));
  const policy = { ...bundledSeverityRubric, revision: 12 };
  const resolve = spyOn(
    rubricSource,
    "getDefaultSeverityRubric",
  ).mockRejectedValue(new Error("Explicit policy must win"));
  let registration: any;
  const runtime = scanRuntimeDependencies(home, scan);
  await using client = testClient({
    ...runtime,
    prepareRuntime: async () => {
      policy.markdown = "Changed by caller";
      return runtime.prepareRuntime();
    },
    runWorkbench: async (_options, args, input) => {
      if (args[0] === "register-cli-scan") registration = JSON.parse(input!);
      return mockWorkbench(args, input);
    },
    createCodex: codexFactory(async () => {
      throw new Error("Captured scan policy");
    }),
  });
  await expect(
    client.run(repository, { severityRubric: policy }),
  ).rejects.toThrow("Captured scan policy");
  expect(resolve).not.toHaveBeenCalled();
  expect(registration.recipe.severityRubric).toEqual({
    ...bundledSeverityRubric,
    revision: 12,
  });
});
