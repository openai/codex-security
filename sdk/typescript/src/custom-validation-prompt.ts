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
    "5197aefbcb75f418ddcac104a7a81378c40bf8d83006094f78a54ff63947cc08",
  "skills/security-diff-scan/SKILL.md":
    "09232fd5d96cfed2a5bdccd176c09b7e9ca53ebd7ac136d283bec884fde94b0d",
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
  "Preserve every surviving source-backed candidate as a provisional finding, including its identity, source locations, evidence, counterevidence, and preliminary assessments. Assemble unsealed scan-manifest.json and findings.json using <plugin_dir>/examples/completed-scan/ and <plugin_dir>/schemas/ as shape references. Put candidate dispositions and pending work in scan.reviewState. Set scan.scope.validationMode to custom_pending and put each finding's matching review-state surface IDs in extensions.customValidationSurfaceIds. Every reported review-state surface must have a candidate. When source discovery finishes and a bound semantic draft tool is available, submit an accepted final source-discovery draft with complete: true, preserving the provisional findings, reviewState, threat model, and custom_pending validation mode. This marks source discovery finished; it does not claim custom validation has occurred or seal the scan. Keep complete: false when requested source review remains unfinished. Verify both files exist, then return control to the SDK without invoking validation or attack-path skills, running application code, sealing files, generating a report, or calling a scan completion tool or helper.";

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

export async function customDiscoveryPrompt(
  pluginRoot: string,
  skillName: string,
): Promise<string> {
  let workflow: string;
  if (skillName === "security-scan") {
    await source(pluginRoot, "references/core-scan.md");
    workflow = [
      "Use <plugin_dir>/references/core-scan.md for source discovery. This caller supplies the validation handoff: the SDK runs independent final validation in a separate turn. Check source evidence and counterevidence now, but do not run the default validation pass.",
      "Keep any supplied investigation time allowance unchanged. Only for an explicit time request with no existing allowance, render <plugin_dir>/references/investigation-time-budget.md once before source review.",
      HANDOFF,
    ].join("\n\n");
  } else if (skillName === "security-diff-scan") {
    const skill = await source(
      pluginRoot,
      "skills/security-diff-scan/SKILL.md",
    );
    workflow = [
      skill.slice(skill.indexOf("## Setup"), skill.indexOf("\n4. ")),
      `4. ${HANDOFF} Use diff for scan.mode.`,
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
