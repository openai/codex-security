import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import Ajv from "ajv";
import {
  readProjectConfig,
  resolveScanSettings,
} from "../src/project-config.js";
import {
  ProjectConfigInputSchema,
  projectConfigJsonSchema,
  type ProjectConfigInput,
} from "../src/project-config-schema.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "../src/deep-scan-defaults.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
async function temporaryDirectory() {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "project-config-")),
  );
  directories.push(directory);
  return directory;
}

const cases: [string, unknown, boolean][] = [
  ["minimal file", {}, true],
  [
    "standard path scope",
    { scan: { mode: "standard", scope: { paths: ["src"] } } },
    true,
  ],
  [
    "zero subagents",
    {
      scan: {
        mode: "deep",
        deep: { workers: 4, subagentsPerWorker: 0, maxTimeHours: 96 },
      },
    },
    true,
  ],
  [
    "working tree with an absent base",
    { scan: { scope: { workingTree: {} } } },
    true,
  ],
  [
    "diff with an absent head",
    { scan: { scope: { diff: { base: "HEAD" } } } },
    true,
  ],
  ["empty context list", { scan: { knowledgeBase: [] } }, true],
  [
    "editor metadata",
    { $schema: "../schemas/project-config.schema.json" },
    true,
  ],
  [
    "native JSON passthrough",
    {
      codex: { synthetic_setting: { enabled: false, names: [], value: null } },
    },
    true,
  ],
  [
    "model availability is a later check",
    { codex: { model: "synthetic-model" } },
    true,
  ],
  [
    "mode and scope may be overridden later",
    { scan: { mode: "deep", scope: { diff: { base: "HEAD" } } } },
    true,
  ],
  [
    "custom validation may be overridden later",
    { scan: { mode: "deep", validationFile: "validate.md" } },
    true,
  ],
  ["unknown wrapper key", { concurrency: 4 }, false],
  ["unknown scan key", { scan: { workres: 4 } }, false],
  [
    "repository selection is not file configuration",
    { repository: "." },
    false,
  ],
  ["null is not a reset", { policy: null }, false],
  ["empty scope", { scan: { scope: {} } }, false],
  [
    "multiple scope variants",
    { scan: { scope: { paths: ["src"], diff: { base: "HEAD" } } } },
    false,
  ],
  ["empty path list", { scan: { scope: { paths: [] } } }, false],
  ["missing diff base", { scan: { scope: { diff: {} } } }, false],
  ["zero workers", { scan: { deep: { workers: 0 } } }, false],
  ["fractional workers", { scan: { deep: { workers: 1.5 } } }, false],
  ["no string coercion", { scan: { deep: { workers: "4" } } }, false],
  ["negative subagents", { scan: { deep: { subagentsPerWorker: -1 } } }, false],
  [
    "hours above the existing maximum",
    { scan: { deep: { maxTimeHours: 97 } } },
    false,
  ],
  ["nonpositive cost", { limits: { maxCostUsdPerScan: 0 } }, false],
  ["incorrect native model type", { codex: { model: 42 } }, false],
];

describe("project configuration input contract", () => {
  const validate = new Ajv({ strict: true, allErrors: true }).compile(
    projectConfigJsonSchema(),
  );

  test.each(cases)(
    "Zod and JSON Schema agree: %s",
    (_name, input, accepted) => {
      const original = structuredClone(input);
      const parsed = ProjectConfigInputSchema.safeParse(input);
      expect(parsed.success).toBe(accepted);
      expect(validate(input)).toBe(accepted);
      expect(input).toEqual(original);
      if (parsed.success) expect<unknown>(parsed.data).toEqual(original);
    },
  );

  test("the packaged schema and shared deep defaults are current", async () => {
    expect(
      JSON.parse(
        await readFile(
          new URL("../schemas/project-config.schema.json", import.meta.url),
          "utf8",
        ),
      ),
    ).toEqual(projectConfigJsonSchema());
    expect(
      JSON.parse(
        await readFile(
          new URL(
            "../../../plugins/codex-security/scripts/deep_scan_defaults.json",
            import.meta.url,
          ),
          "utf8",
        ),
      ),
    ).toEqual(DEFAULT_DEEP_SCAN_SETTINGS);
  });

  test("YAML and JSON load the same literal data without adding defaults", async () => {
    const root = await temporaryDirectory();
    const yaml = join(root, "scan.yaml");
    const json = join(root, "scan.json");
    const input = {
      scan: { deep: { subagentsPerWorker: 0 } },
      codex: { synthetic_setting: "${LITERAL_VALUE}" },
    } satisfies ProjectConfigInput;
    await writeFile(
      yaml,
      "scan:\n  deep:\n    subagentsPerWorker: 0\ncodex:\n  synthetic_setting: ${LITERAL_VALUE}\n",
    );
    await writeFile(json, JSON.stringify(input));
    expect((await readProjectConfig(yaml)).input).toEqual(input);
    expect((await readProjectConfig(json)).input).toEqual(input);
  });

  test.each([
    ["invalid.yaml", "scan: [\n"],
    ["duplicate.yaml", "scan: {}\nscan: {}\n"],
    ["stream.yaml", "scan: {}\n---\nscan: {}\n"],
    ["invalid.json", '{"scan":'],
    ["invalid.ts", "export default {};"],
    ["unknown.yaml", "scan:\n  workres: 2\n"],
  ])("rejects an invalid selected file: %s", async (name, contents) => {
    const root = await temporaryDirectory();
    const path = join(root, name);
    await writeFile(path, contents);
    await expect(readProjectConfig(path)).rejects.toThrow();
  });

  test("reports a missing selected file", async () => {
    await expect(
      readProjectConfig("missing.yaml", await temporaryDirectory()),
    ).rejects.toThrow("Cannot read project configuration");
  });
});

describe("project configuration resolution", () => {
  test("resolves paths according to their layer and replaces lists", async () => {
    const root = await temporaryDirectory();
    const project = {
      path: join(root, "settings", "scan.yaml"),
      directory: join(root, "settings"),
      input: {
        scan: {
          scope: { paths: ["src"] },
          knowledgeBase: ["context.md"],
          instructionsFile: "scan.md",
          validationFile: "validate.md",
        },
        output: { directory: "../artifacts" },
      } satisfies ProjectConfigInput,
    };
    const { options: settings, projectConfig: provenance } =
      resolveScanSettings(
        project,
        {
          knowledgeBasePaths: ["cli-context.md"],
          validationPromptFile: "cli-validate.md",
        },
        join(root, "invocation"),
      );
    expect(settings).toMatchObject({
      target: ["src"],
      knowledgeBasePaths: [join(root, "invocation", "cli-context.md")],
      scanPromptFile: join(root, "settings", "scan.md"),
      validationPromptFile: join(root, "invocation", "cli-validate.md"),
      outputDir: join(root, "artifacts"),
    });
    expect(provenance?.sources).toMatchObject({
      "scan.knowledgeBase": "cli",
      "scan.instructionsFile": "project",
      "scan.validationFile": "cli",
      "output.directory": "project",
    });
    expect(project.input.scan.knowledgeBase).toEqual(["context.md"]);
  });

  test("retains valid false and zero native values and native profile structure", async () => {
    const root = await temporaryDirectory();
    const project = {
      path: join(root, "scan.yaml"),
      directory: root,
      input: {
        scan: { mode: "deep", deep: { subagentsPerWorker: 3, workers: 8 } },
        codex: {
          profile: "review",
          profiles: {
            review: { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
          },
          synthetic_setting: { enabled: true, count: 2, names: ["first"] },
        },
      } satisfies ProjectConfigInput,
    };
    const {
      config,
      options: settings,
      projectConfig: provenance,
    } = resolveScanSettings(
      project,
      {
        subagents: 0,
        codexOverrides: {
          model: "gpt-5.6-sol",
          synthetic_setting: { enabled: false, count: 0, names: [] },
        },
      },
      root,
    );
    expect(settings).toMatchObject({
      subagents: 0,
      workers: 8,
    });
    expect(config).toEqual({
      codexOverrides: {
        model: "gpt-5.6-sol",
        profile: "review",
        profiles: project.input.codex.profiles,
        synthetic_setting: { enabled: false, count: 0, names: [] },
      },
    });
    expect(provenance?.sources).toMatchObject({
      "scan.deep.subagentsPerWorker": "cli",
      "scan.deep.workers": "project",
      "codex.model": "cli",
      "codex.profiles.review.model": "project",
    });
  });

  test("ignores valid inactive deep defaults but rejects explicit deep CLI options in standard mode", async () => {
    const root = await temporaryDirectory();
    const project = {
      path: join(root, "scan.yaml"),
      directory: root,
      input: {
        scan: { mode: "deep", deep: { workers: 8 } },
      } satisfies ProjectConfigInput,
    };
    expect(
      resolveScanSettings(project, { mode: "standard" }, root).options.workers,
    ).toBeUndefined();
    expect(() =>
      resolveScanSettings(project, { mode: "standard", workers: 2 }, root),
    ).toThrow("require --mode deep");
  });

  test("keeps existing unsafe native-key protections before merging", async () => {
    const root = await temporaryDirectory();
    for (const [filename, contents] of [
      ["scan.json", '{"codex":{"__proto__":{"syntheticPollution":true}}}'],
      ["scan.yaml", "codex:\n  __proto__:\n    syntheticPollution: true\n"],
    ] as const) {
      await writeFile(join(root, filename), contents);
      const project = await readProjectConfig(filename, root);
      expect(() => resolveScanSettings(project, {}, root)).toThrow(
        "Invalid Codex override key: __proto__.",
      );
    }
    expect(
      ({} as Record<string, unknown>)["syntheticPollution"],
    ).toBeUndefined();
  });

  test.each([
    '{"__proto__":{"synthetic":true}}',
    '{"scan":{"__proto__":{"synthetic":true}}}',
  ])(
    "rejects reserved unknown wrapper keys without dropping them: %s",
    async (contents) => {
      const root = await temporaryDirectory();
      const path = join(root, "scan.json");
      await writeFile(path, contents);
      await expect(readProjectConfig(path)).rejects.toThrow(
        "Unknown key __proto__.",
      );
    },
  );
});
