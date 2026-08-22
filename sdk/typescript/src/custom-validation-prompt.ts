import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { JsonObject } from "./config.js";
import { IncompleteScanError } from "./errors.js";
import { PLUGIN_NAME } from "./runtime.js";

// Review this adapter when the bundled workflows change. Never silently run
// the ordinary validation sequence with a custom-validation request.
const SOURCES = {
  "references/core-scan.md":
    "806efc9432b3352e86c495466b00a700d77e338b6db297a67f3d78d1f7ec359e",
  "skills/security-scan/SKILL.md":
    "ef4d18fdf85667877f80f68be557214d5edca629c97075c85d7ccdefcc76fb8f",
  "skills/security-diff-scan/SKILL.md":
    "5c2bcdf8c862da4e7fb2c01b0fed8f0de61b65a479c6ae6897d7f12f11f9f87a",
} as const;

const DISABLED_TOOLS = [
  "start_codex_security_standard_scan",
  "start_codex_security_prompt_only_scan",
  "start_codex_security_deep_scan",
  "complete_codex_security_scan",
  "record_codex_security_candidate_validations",
  "record_candidate_attack_paths",
];

const HANDOFF =
  "Preserve every surviving source-backed candidate as a provisional finding, including its identity, source locations, evidence, counterevidence, and preliminary assessments. Assemble unsealed scan-manifest.json, findings.json, and coverage.json using <plugin_dir>/examples/completed-scan/ and <plugin_dir>/schemas/ as shape references. Set scan.scope.validationMode to custom_pending and put each finding's matching coverage surface IDs in extensions.customValidationSurfaceIds. Every reported coverage surface must have a candidate. Do not claim that custom validation has occurred. Verify the three files exist, then return control to the SDK without invoking validation or attack-path skills, running application code, sealing files, generating a report, or calling a scan completion tool or helper.";

async function source(pluginRoot: string, name: keyof typeof SOURCES) {
  const text = (await readFile(join(pluginRoot, name), "utf8")).replaceAll(
    "\r\n",
    "\n",
  );
  if (createHash("sha256").update(text).digest("hex") !== SOURCES[name]) {
    throw new IncompleteScanError(
      `Custom validation is incompatible with the installed plugin workflow (${name}). Update the SDK and plugin together. Default validation was not started.`,
    );
  }
  return text;
}

function step(text: string, number: number): string {
  return text.match(new RegExp(`^${number}\\. (.+)$`, "m"))![1]!;
}

export async function customDiscoveryPrompt(
  pluginRoot: string,
  skillName: string,
): Promise<string> {
  let workflow: string;
  if (skillName === "security-scan") {
    const [skill, core] = await Promise.all([
      source(pluginRoot, "skills/security-scan/SKILL.md"),
      source(pluginRoot, "references/core-scan.md"),
    ]);
    const discovery = core
      .replace(
        /^7\. .+$/m,
        "7. Retain the combined source-backed candidates and their existing evidence. The SDK will run independent final validation in a separate turn.",
      )
      .replace(
        /^Keep discovery, validation, and attack-path reasoning.+$/m,
        "Keep source-evidence and counterevidence checks within discovery. Do not run an independent final validation pass or invoke separate phase skills.",
      );
    workflow = [
      skill.slice(
        skill.indexOf("## Host And Setup"),
        skill.indexOf("## Workflow"),
      ),
      "## Discovery workflow",
      `1. ${step(skill, 1)}`,
      "2. Perform the embedded core discovery workflow below. Do not reload the ordinary core-scan.md or top-level security-scan skill.",
      `3. ${step(skill, 3).split("For an SDK-owned or prompt-only headless scan, ")[1]}`,
      `4. ${HANDOFF}`,
      "## Embedded core discovery workflow",
      discovery,
    ].join("\n\n");
  } else if (skillName === "security-diff-scan") {
    const skill = await source(
      pluginRoot,
      "skills/security-diff-scan/SKILL.md",
    );
    workflow = [
      skill.slice(skill.indexOf("## Setup"), skill.indexOf("\n4. ")),
      `4. ${HANDOFF} Use diff for coverage.mode and coverage.inventoryStrategy.`,
    ].join("\n\n");
  } else {
    throw new IncompleteScanError(
      "Custom validation is not supported for this scan workflow.",
    );
  }
  return [
    "Follow this SDK-owned discovery workflow, derived from the installed plugin. It replaces the ordinary top-level scan skill for this turn. The SDK owns the separate custom validation pass and all completion. <plugin_dir> is CODEX_SECURITY_PLUGIN_ROOT; other bare reference filenames are relative to its references directory.",
    workflow.replaceAll("../../references/", "<plugin_dir>/references/"),
  ].join("\n\n");
}

export async function customValidationConfig(
  config: JsonObject,
  pluginRoot: string,
): Promise<JsonObject> {
  const manifest = JSON.parse(
    await readFile(join(pluginRoot, ".mcp.json"), "utf8"),
  );
  const server = manifest.mcpServers[PLUGIN_NAME];
  const servers = (config["mcp_servers"] ?? {}) as JsonObject;
  const configured = (servers[PLUGIN_NAME] ?? {}) as JsonObject;
  // The pinned Codex applies this per-invocation server entry ahead of the
  // installed plugin. Plugin-specific command-line policy overrides do not.
  return {
    ...config,
    mcp_servers: {
      ...servers,
      [PLUGIN_NAME]: {
        ...server,
        ...configured,
        cwd: resolve(
          pluginRoot,
          (configured["cwd"] as string | undefined) ?? server.cwd ?? ".",
        ),
        disabled_tools: [
          ...new Set([
            ...(server.disabled_tools ?? []),
            ...((configured["disabled_tools"] ?? []) as string[]),
            ...DISABLED_TOOLS,
          ]),
        ],
      },
    },
  };
}
