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
import { createProviderProfile } from "../src/provider-profile.js";
import type { JsonObject } from "../src/config.js";

test.each([
  { model_reasoning_summary: "none" },
  { model_reasoning_summary: "concise" },
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

test.each([undefined, null])(
  "loads an omitted or null summary through the private provider profile: %j",
  async (summary) => {
    const root = await mkdtemp(join(tmpdir(), "summary-private-provider-"));
    let profile: Awaited<ReturnType<typeof createProviderProfile>> | undefined;
    try {
      const config: JsonObject = {
        model: "selected-model",
        model_reasoning_effort: "high",
        ...(summary === undefined ? {} : { model_reasoning_summary: summary }),
        model_provider: "synthetic-provider",
        model_providers: {
          "synthetic-provider": {
            name: "Synthetic Provider",
            base_url: "https://synthetic.invalid/v1",
            wire_api: "responses",
            http_headers: { Authorization: "Bearer synthetic-provider-header" },
          },
        },
      };
      profile = await createProviderProfile(root, config);
      const marker = join(root, "invocation.json");
      const script = join(root, "native.mjs");
      await writeFile(
        script,
        [
          'import { readFileSync, writeFileSync } from "node:fs";',
          `writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ args: process.argv.slice(2), profile: readFileSync(${JSON.stringify(profile.path)}, "utf8") }));`,
          'console.log(JSON.stringify({models:[{slug:"selected-model",default_reasoning_summary:"none"}]}));',
          "process.exit(0);",
        ].join("\n"),
      );
      const executable = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const value = await captureOriginalReasoningSummary({
        config,
        nativeProfile: profile,
        command: { command: executable, args: [script] },
        cwd: root,
        environment: {
          CODEX_HOME: root,
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
        },
        signal: new AbortController().signal,
      });
      expect(value).toBe("none");
      const recorded = JSON.parse(await readFile(marker, "utf8"));
      expect(recorded.args.slice(0, 2)).toEqual(["--profile", profile.name]);
      expect(recorded.args.join(" ")).not.toContain(
        "synthetic-provider-header",
      );
      expect(recorded.args.join(" ")).not.toContain("model_providers");
      expect(recorded.profile).toContain("synthetic-provider-header");
      expect(recorded.args).toContain('model_provider="synthetic-provider"');
    } finally {
      await profile?.cleanup();
      await rm(root, { recursive: true, force: true });
    }
  },
);
