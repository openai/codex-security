import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";
import { captureOriginalReasoningSummary } from "../src/reasoning-summary.js";
import type { JsonObject } from "../src/config.js";
import { createProviderProfile } from "../src/provider-profile.js";

test.each([
  { model_reasoning_summary: "none" },
  { model_reasoning_summary: "concise" },
  { model_reasoning_summary: null },
  { model_reasoning_summary: "" },
  {
    profile: "selected",
    profiles: { selected: { model_reasoning_summary: "auto" } },
  },
] as JsonObject[])(
  "preserves explicit summary without a native lookup: %j",
  async (config) => {
    expect(
      await captureOriginalReasoningSummary({
        config,
        command: { command: "unused-native-executable" },
        cwd: tmpdir(),
        environment: {},
        signal: new AbortController().signal,
      }),
    ).toBeUndefined();
  },
);

test.each(["unknown-model", "unsupported-command", "missing-metadata"])(
  "keeps an unavailable original model default unknown: %s",
  async (scenario) => {
    const root = await mkdtemp(join(tmpdir(), "summary-selection-"));
    try {
      const cwd = join(root, "original output");
      const script = join(root, "native.mjs");
      const receipt = join(root, "receipt.json");
      await mkdir(cwd);
      await writeFile(
        script,
        [
          'import { writeFileSync } from "node:fs";',
          `writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({cwd:process.cwd(),args:process.argv,home:process.env.CODEX_HOME}));`,
          `console.log(JSON.stringify({models:[{slug:${JSON.stringify(scenario === "unknown-model" ? "another-model" : "selected-model")}${scenario === "missing-metadata" ? "" : ',default_reasoning_summary:"none"'}}]}));`,
          `process.exit(${scenario === "unsupported-command" ? 1 : 0});`,
        ].join("\n"),
      );
      const command = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const value = await captureOriginalReasoningSummary({
        config: { model: "selected-model", model_reasoning_effort: "high" },
        command: { command },
        cwd,
        environment: {
          CODEX_HOME: root,
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
        },
        signal: new AbortController().signal,
      });
      expect(value).toBeUndefined();
      const recorded = JSON.parse(await readFile(receipt, "utf8"));
      expect(await realpath(recorded.cwd)).toBe(await realpath(cwd));
      expect(recorded.home).toBe(root);
      expect(recorded.args).toContain('model="selected-model"');
      expect(recorded.args).toContain('model_reasoning_effort="high"');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each(["literal", "selected", "default"])(
  "original model lookup keeps %s provider credentials in its native profile",
  async (scenario) => {
    const root = await mkdtemp(join(tmpdir(), "summary-provider-"));
    let profile: Awaited<ReturnType<typeof createProviderProfile>> | undefined;
    try {
      const script = join(root, "native.mjs");
      const receipt = join(root, "arguments.json");
      const provider = "synthetic.gateway";
      const definition = {
        name: "Synthetic gateway",
        http_headers: { Authorization: "synthetic-summary-header" },
      };
      const config: JsonObject = {
        model: "selected-model",
        model_reasoning_effort: "high",
        ...(scenario === "default"
          ? {}
          : scenario === "selected"
            ? {
                profile: "selected",
                profiles: {
                  selected: {
                    model_provider: provider,
                    model_providers: { [provider]: definition },
                  },
                },
              }
            : {
                model_provider: provider,
                model_providers: { [provider]: definition },
              }),
      };
      if (scenario !== "default")
        profile = await createProviderProfile(root, config);
      await writeFile(
        script,
        [
          'import { writeFileSync, readFileSync } from "node:fs";',
          'import { join } from "node:path";',
          `writeFileSync(${JSON.stringify(receipt)}, JSON.stringify(process.argv));`,
          'const i = process.argv.indexOf("--profile");',
          "const selected = i === -1 ? undefined : process.argv[i + 1];",
          ...(scenario === "default"
            ? []
            : [
                'if (!selected || !readFileSync(join(process.env.CODEX_HOME, selected + ".config.toml"), "utf8").includes("synthetic-summary-header")) process.exit(13);',
              ]),
          'console.log(JSON.stringify({models:[{slug:"selected-model",default_reasoning_summary:"none"}]}));',
          "process.exit(0);",
        ].join("\n"),
      );
      const command = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const value = await captureOriginalReasoningSummary({
        config,
        command: { command },
        cwd: root,
        environment: {
          CODEX_HOME: root,
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
        },
        signal: new AbortController().signal,
        ...(profile === undefined ? {} : { nativeProfile: profile.name }),
      });
      const args: string[] = JSON.parse(await readFile(receipt, "utf8"));
      expect(args.some((arg) => arg.includes("synthetic-summary-header"))).toBe(
        false,
      );
      expect(value).toBe("none");
      expect(args).toContain('model="selected-model"');
      if (profile !== undefined)
        expect(args[args.indexOf("--profile") + 1]).toBe(profile.name);
    } finally {
      await profile?.cleanup();
      await rm(root, { recursive: true, force: true });
    }
  },
);
