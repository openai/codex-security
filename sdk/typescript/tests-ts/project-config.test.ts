import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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
import { mergedCodexConfig, type JsonValue } from "../src/config.js";
import { ConfigurationError } from "../src/errors.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } =
  createApiTestFixtures("project-config-");
afterEach(cleanup);

const cases: [string, unknown, boolean][] = [
  ["minimal file", {}, true],
  ["owner artifact enabled", { scan: { owner_suggestions: true } }, true],
  ["owner artifact disabled", { scan: { owner_suggestions: false } }, true],
  [
    "owner artifact requires a boolean",
    { scan: { owner_suggestions: "true" } },
    false,
  ],
  [
    "fractional investigation minutes",
    { scan: { max_time_minutes: 0.5 } },
    true,
  ],
  ["unset Standard cap", { scan: { max_time_minutes: 6000 } }, true],
  [
    "nonpositive investigation minutes",
    { scan: { max_time_minutes: 0 } },
    false,
  ],
  ["minute strings", { scan: { max_time_minutes: "15" } }, false],
  [
    "Cyber selection",
    { scan: { cyber_access_program: "daybreak_blue" } },
    true,
  ],
  [
    "unknown Cyber selection",
    { scan: { cyber_access_program: "unknown" } },
    false,
  ],
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
        deep: { workers: 4, subagents_per_worker: 0, max_time_hours: 96 },
      },
    },
    true,
  ],
  [
    "working tree with an absent base",
    { scan: { scope: { working_tree: {} } } },
    true,
  ],
  [
    "diff with an absent head",
    { scan: { scope: { diff: { base: "HEAD" } } } },
    true,
  ],
  ["empty context list", { scan: { knowledge_base: [] } }, true],
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
    { scan: { mode: "deep", validation_file: "validate.md" } },
    true,
  ],
  ["unknown wrapper key", { concurrency: 4 }, false],
  ["unknown scan key", { scan: { workres: 4 } }, false],
  [
    "camelCase names are not project-file keys",
    {
      scan: {
        knowledgeBase: [],
        deep: { stopAfterNoNew: 4 },
        scope: { workingTree: {} },
      },
      limits: { maxCostUsdPerScan: 5 },
      policy: { failOnSeverity: "high" },
    },
    false,
  ],
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
  [
    "negative subagents",
    { scan: { deep: { subagents_per_worker: -1 } } },
    false,
  ],
  [
    "hours above the existing maximum",
    { scan: { deep: { max_time_hours: 97 } } },
    false,
  ],
  ["nonpositive cost", { limits: { max_cost_usd_per_scan: 0 } }, false],
  ["incorrect native model type", { codex: { model: 42 } }, false],
];

test("minute and deprecated hour settings follow source precedence", () => {
  const directory = process.cwd();
  for (const [scan, overrides, expected, sourceKey, source] of [
    [
      { mode: "standard", max_time_minutes: 15 },
      {},
      { maxTimeMinutes: 15 },
      "scan.max_time_minutes",
      "project",
    ],
    [
      { mode: "deep", max_time_minutes: 30, deep: { max_time_hours: 2 } },
      { maxTimeMinutes: 15 },
      { maxTimeMinutes: 15, maxTimeHours: undefined },
      "scan.max_time_minutes",
      "cli",
    ],
    [
      { mode: "deep", max_time_minutes: 15, deep: { max_time_hours: 1 } },
      { maxTimeHours: 2 },
      { maxTimeMinutes: undefined, maxTimeHours: 2 },
      "scan.deep.max_time_hours",
      "cli",
    ],
    [
      { mode: "deep", max_time_minutes: 90, deep: { max_time_hours: 1.5 } },
      {},
      { maxTimeMinutes: 90, maxTimeHours: 1.5 },
      "scan.max_time_minutes",
      "project",
    ],
    [
      { mode: "standard", max_time_minutes: 15, deep: { max_time_hours: 2 } },
      {},
      { maxTimeMinutes: 15, maxTimeHours: undefined },
      "scan.max_time_minutes",
      "project",
    ],
    [
      { mode: "standard", max_time_minutes: 6000 },
      { mode: "deep", maxTimeMinutes: 15 },
      { maxTimeMinutes: 15 },
      "scan.max_time_minutes",
      "cli",
    ],
  ] as const) {
    const resolved = resolveScanSettings(
      { input: { scan }, directory },
      overrides,
      directory,
    );
    expect({
      maxTimeMinutes: resolved.options.maxTimeMinutes,
      maxTimeHours: resolved.options.maxTimeHours,
    }).toMatchObject(expected);
    expect(resolved.sources[sourceKey]).toBe(source);
  }
});

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
      scan: { deep: { subagents_per_worker: 0 } },
      codex: { synthetic_setting: "${LITERAL_VALUE}" },
    } satisfies ProjectConfigInput;
    await writeFile(
      yaml,
      "scan:\n  deep:\n    subagents_per_worker: 0\ncodex:\n  synthetic_setting: ${LITERAL_VALUE}\n",
    );
    await writeFile(json, JSON.stringify(input));
    expect((await readProjectConfig(yaml)).input).toEqual(input);
    expect((await readProjectConfig(json)).input).toEqual(input);
  });

  test("loads a JSON project file with a UTF-8 byte order mark", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "scan.json");
    const input = {
      scan: { mode: "deep", deep: { subagents_per_worker: 0 } },
      codex: { synthetic_setting: "preserve\uFEFFthis" },
    } satisfies ProjectConfigInput;
    await writeFile(path, `\uFEFF${JSON.stringify(input)}`);

    expect(await readProjectConfig(path)).toEqual({
      path,
      directory: root,
      input,
    });
  });

  test.each([
    [150, 1],
    [500, 20],
  ])(
    "loads %i YAML profiles reusing a %i-field table",
    async (count, fields) => {
      const root = await temporaryDirectory();
      const path = join(root, "profiles.yaml");
      const profile = {
        model: "synthetic-model",
        ...Object.fromEntries(
          Array.from({ length: fields - 1 }, (_, index) => [
            `setting_${index}`,
            index,
          ]),
        ),
      };
      const names = Array.from(
        { length: count },
        (_, index) => `profile_${index}`,
      );
      await writeFile(
        path,
        [
          "codex:",
          "  profiles:",
          `    shared: &shared ${JSON.stringify(profile)}`,
          ...names.map((name) => `    ${name}: *shared`),
        ].join("\n"),
      );
      const project = await readProjectConfig(path);
      expect(
        resolveScanSettings(project, {}, root).config.codexOverrides[
          "profiles"
        ],
      ).toEqual({
        shared: profile,
        ...Object.fromEntries(names.map((name) => [name, profile])),
      });
    },
  );

  test("rejects excessive nested YAML alias expansion before resolving settings", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "nested-aliases.yaml");
    await writeFile(
      path,
      [
        "codex:",
        "  shared_0: &shared_0 [value, value, value, value, value]",
        ...Array.from(
          { length: 6 },
          (_, index) =>
            `  shared_${index + 1}: &shared_${index + 1} [${Array(10).fill(`*shared_${index}`).join(", ")}]`,
        ),
      ].join("\n"),
    );
    await expect(readProjectConfig(path)).rejects.toThrow(
      "Cannot parse project configuration",
    );
  });

  test.each([
    ["duplicate.yaml", "scan: {}\nscan: {}\n"],
    ["stream.yaml", "scan: {}\n---\nscan: {}\n"],
    ["invalid.ts", "export default {};"],
    ["unknown.yaml", "scan:\n  workres: 2\n"],
  ])("rejects an invalid selected file: %s", async (name, contents) => {
    const root = await temporaryDirectory();
    const path = join(root, name);
    await writeFile(path, contents);
    await expect(readProjectConfig(path)).rejects.toThrow();
  });

  test.each([
    ["scan.yaml", "scan: [\n"],
    ["scan.json", '{"scan":'],
  ])(
    "includes the parser message when %s cannot be parsed",
    async (name, contents) => {
      const path = join(await temporaryDirectory(), name);
      await writeFile(path, contents);
      const error = await readProjectConfig(path).catch(
        (cause: unknown) => cause,
      );
      assert(error instanceof ConfigurationError);
      assert(error.cause instanceof Error);
      expect(error.message).toBe(
        `Cannot parse project configuration at ${path}: ${error.cause.message}`,
      );
    },
  );

  test.each([
    ["missing.yaml", "ENOENT"],
    ["directory.yaml", "EISDIR"],
  ])("includes the system error for %s", async (name, code) => {
    const path = join(await temporaryDirectory(), name);
    if (code === "EISDIR") await mkdir(path);
    await expect(readProjectConfig(path)).rejects.toMatchObject({
      message: expect.stringContaining(`${path}: ${code}`),
      cause: expect.objectContaining({ code }),
    });
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
          knowledge_base: ["context.md"],
          instructions_file: "scan.md",
          validation_file: "validate.md",
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
      "scan.knowledge_base": "cli",
      "scan.instructions_file": "project",
      "scan.validation_file": "cli",
      "output.directory": "project",
    });
    expect(project.input.scan.knowledge_base).toEqual(["context.md"]);
  });

  test("keeps native key spelling and false/zero values when merging overrides", async () => {
    const root = await temporaryDirectory();
    const project = {
      path: join(root, "scan.yaml"),
      directory: root,
      input: {
        scan: { mode: "deep", deep: { subagents_per_worker: 3, workers: 8 } },
        codex: {
          profile: "reviewCase",
          profiles: {
            reviewCase: {
              model: "gpt-5.6-terra",
              model_reasoning_effort: "high",
            },
          },
          synthetic_setting: { enabled: true, itemCount: 2, names: ["first"] },
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
          synthetic_setting: { enabled: false, itemCount: 0, names: [] },
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
        profile: "reviewCase",
        profiles: project.input.codex.profiles,
        synthetic_setting: { enabled: false, itemCount: 0, names: [] },
      },
    });
    expect(provenance?.sources).toMatchObject({
      "scan.deep.subagents_per_worker": "cli",
      "scan.deep.workers": "project",
      "codex.model": "cli",
      "codex.profiles.reviewCase.model": "project",
      "codex.synthetic_setting.itemCount": "cli",
    });
  });

  test.each<{ value: JsonValue; source: "default" | "project" }>([
    { value: null, source: "default" },
    { value: false, source: "default" },
    { value: [], source: "default" },
    { value: {}, source: "default" },
    { value: { enabled: true }, source: "project" },
  ])(
    "tracks restored native defaults after replacing $value with a CLI table",
    async ({ value, source }) => {
      const root = await temporaryDirectory();
      const input = { codex: { features: { multi_agent_v2: value } } };
      const original = structuredClone(input);
      const resolved = resolveScanSettings(
        { input, directory: root },
        {
          codexOverrides: {
            features: {
              multi_agent_v2: { max_concurrent_threads_per_session: 2 },
            },
          },
        },
        root,
      );
      expect(
        (await mergedCodexConfig(resolved.config))["features"],
      ).toMatchObject({
        multi_agent_v2: {
          enabled: true,
          max_concurrent_threads_per_session: 2,
        },
      });
      expect(resolved.sources).toMatchObject({
        "codex.features.multi_agent_v2.enabled": source,
        "codex.features.multi_agent_v2.max_concurrent_threads_per_session":
          "cli",
      });
      expect(
        Object.hasOwn(resolved.sources, "codex.features.multi_agent_v2"),
      ).toBe(false);
      expect(Object.isFrozen(resolved.sources)).toBe(true);
      expect(input).toEqual(original);
    },
  );

  test("preserves literal native keys and profile sources across empty-table and list replacements", async () => {
    const root = await temporaryDirectory();
    const { config, sources } = resolveScanSettings(
      {
        directory: root,
        input: {
          codex: {
            "setting.with.dot": { keep: true, retained: null, replace: [] },
            setting: { with: { dot: { keep: true } } },
            "literal.branch": { leaf: true },
            synthetic: { old: true },
            profile: "review",
            profiles: { review: { model: "gpt-5.6-terra" } },
          },
        },
      },
      {
        codexOverrides: {
          "setting.with.dot": { keep: false, replace: {} },
          literal: { branch: false },
          synthetic: [],
        },
      },
      root,
    );
    expect(config.codexOverrides["setting.with.dot"]).toEqual({
      keep: false,
      retained: null,
      replace: {},
    });
    expect(config.codexOverrides["synthetic"]).toEqual([]);
    expect(config.codexOverrides["literal.branch"]).toEqual({ leaf: true });
    expect(config.codexOverrides["literal"]).toEqual({ branch: false });
    expect(sources).toMatchObject({
      "codex.setting.with.dot.keep": "cli",
      "codex.setting.with.dot.retained": "project",
      "codex.literal.branch.leaf": "project",
      "codex.literal.branch": "cli",
      "codex.synthetic": "cli",
      "codex.profile": "project",
      "codex.profiles.review.model": "project",
    });
    expect(Object.hasOwn(sources, "codex.setting.with.dot.replace")).toBe(
      false,
    );
    expect(Object.hasOwn(sources, "codex.synthetic.old")).toBe(false);
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
    ).toThrow("require deep mode");
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
