import { chmod, copyFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { installFixtureSpawn } from "../../../../../sdk/typescript/scripts/fixtures/package-deep-spawn.mjs";
import path from "node:path";
import { fakeCodexSource } from "./fake-codex-source.ts";
import type { createTemporaryDirectories } from "./temporary-directories.ts";
import { privateWindowsOutputRoot } from "./windows-output-fixture.ts";

export const trustedParentSandbox = Object.freeze({
  filesystemDenies: [],
});
export const trustedParentSandboxWithDenials = Object.freeze({
  filesystemDenies: [
    "/repo/.env",
    "/repo/**/.secret",
    "/repo/**/*.pem",
    "/repo/temp[1]",
    "/repo/secret[1]",
    "/repo/.env",
  ],
  literalFilesystemDenies: ["/repo/temp[1]", "/repo/secret[1]"],
  globScanMaxDepth: 3,
});
export const deniedWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: {
    ":root": "read",
    "/repo/.env": "deny",
    "/repo/**/.secret": "deny",
    "/repo/**/*.pem": "deny",
    "/repo/temp[1]": { ".": "deny" },
    "/repo/secret[1]": { ".": "deny" },
    "/": { "repo/temp[1]": "deny", "repo/secret[1]": "deny" },
    glob_scan_max_depth: 3,
  },
  network: { enabled: false },
};

export const emptyWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: { ":root": "read" },
  network: { enabled: false },
};

export async function createFakeCodexFixture(
  temporaryDirectories: ReturnType<typeof createTemporaryDirectories>,
  // null resolves the invocation's profile; explicit values exercise mismatches.
  preflightProfile:
    typeof emptyWorkerPermissionProfile | null = emptyWorkerPermissionProfile,
  preflightAllowed = true,
  accountResult: {
    account: { type: string } | null;
    requiresOpenaiAuth: boolean;
  } = { account: { type: "apiKey" }, requiresOpenaiAuth: true },
  privateWindowsRoot = false,
) {
  let root = await temporaryDirectories.create("codex-security-sdk-executor-");
  if (privateWindowsRoot) root = await privateWindowsOutputRoot(root);
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(
    scriptPath,
    fakeCodexSource(
      preflightProfile,
      preflightAllowed,
      accountResult,
      preflightMarkerPath,
    ),
  );
  await chmod(scriptPath, 0o755);
  process.env.FAKE_CODEX_MARKER = markerPath;
  return { root, markerPath, preflightMarkerPath, executablePath: scriptPath };
}

export function syntheticPermissionAppServer(parentPath?: string) {
  return `function servePermissionProfiles() {
  const { parse } = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
  const config = {};
  const argv = process.argv.slice(2);
  function merge(target, value) {
    for (const [key, child] of Object.entries(value)) {
      if (child && typeof child === "object" && !Array.isArray(child)) {
        target[key] = merge(target[key] ?? {}, child);
      } else target[key] = child;
    }
    return target;
  }
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] === "--config" || argv[index] === "-c") merge(config, parse(argv[++index]));
  }
  const scenario = process.env.NATIVE_PROFILE_SCENARIO
    ? fs.readFileSync(process.env.NATIVE_PROFILE_SCENARIO, "utf8").trim() : "valid";
  const selected = config.default_permissions;
  const profile = config.permissions?.[selected] ?? { filesystem: {}, network: {} };
  profile.description = "Synthetic profile description";
  profile.network.fixtureNull = null;
  if (scenario === "substituted-default") config.default_permissions = ":read-only";
  if (scenario === "substituted-profile") {
    for (const [key, value] of Object.entries(profile.filesystem)) {
      if (value === "deny") delete profile.filesystem[key];
    }
  }
  const capture = (value) => {
    if (process.env.NATIVE_PROFILE_CAPTURE) fs.appendFileSync(process.env.NATIVE_PROFILE_CAPTURE, JSON.stringify(value) + "\\n");
  };
  capture({ kind: "preflight", executable: process.argv[1], argv, modelProvider: config.model_provider, provider: config.model_providers?.[config.model_provider], cwd: process.cwd(), marker: process.env.NATIVE_PROFILE_MARKER,
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY,
    gitEnvironment: Object.fromEntries(["PATH", "CODEX_SECURITY_GIT", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL"].map(name => [name, process.env[name]])) });
  require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {
    const request = JSON.parse(line);
    capture({ kind: "request", method: request.method, params: request.params });
    if (request.id === undefined) return;
    let result;
    if (request.method === "initialize") result = {};
    else if (request.method === "config/read") result = { config };
    else if (request.method === "thread/read") result = { thread: { id: request.params.threadId, path: ${JSON.stringify(parentPath ?? null)} } };
    else if (request.method === "permissionProfile/list") result = request.params?.cursor === "selected-page"
      ? { data: [{ id: selected, allowed: scenario !== "disallowed" }], nextCursor: null }
      : { data: [{ id: "other-profile", allowed: true }], nextCursor: "selected-page" };
    else throw new Error("Unexpected app-server request " + request.method);
    console.log(JSON.stringify({ id: request.id, result }));
  });
}`;
}

export async function writeNativeWorkerExecutable(
  executable: string,
  capture: string,
  script = executable,
) {
  await writeFile(
    script,
    `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) servePermissionProfiles();
else {
  const { parse } = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
  const argv = process.argv.slice(2);
  const path = require("node:path");
  const effective = parse(fs.readFileSync(path.join(process.env.CODEX_HOME, "config.toml"), "utf8"));
  const merge = (target, value) => { for (const [key, child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {}, child) : child; return target; };
  const profile = argv.includes("--profile") ? parse(fs.readFileSync(path.join(process.env.CODEX_HOME, argv[argv.indexOf("--profile") + 1] + ".config.toml"), "utf8")) : {};
  merge(effective, profile);
  for (let i = 0; i < argv.length; i++) if (["--config", "-c"].includes(argv[i])) merge(effective, parse(argv[++i]));
  const provider = effective.model_providers?.[effective.model_provider];
  fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ argv, path: process.env.PATH, codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY, home: process.env.CODEX_HOME, state: process.env.CODEX_SECURITY_STATE_DIR, executable: process.argv[1], binary: process.execPath, knowledge: process.env.CODEX_SECURITY_KNOWLEDGE_BASE,
    knowledgeDocuments: process.env.CODEX_SECURITY_KNOWLEDGE_BASE && Object.fromEntries(fs.readdirSync(process.env.CODEX_SECURITY_KNOWLEDGE_BASE).map(name => [name, fs.readFileSync(path.join(process.env.CODEX_SECURITY_KNOWLEDGE_BASE, name), "utf8")])),
    model: effective.model,
    reasoningEffort: effective.model_reasoning_effort,
    modelProvider: effective.model_provider,
    safetyIdentifier: process.env.CODEX_SAFETY_IDENTIFIER,
    provider,
    profileProvider: profile.model_providers?.[effective.model_provider],
    providerToken: provider && (provider.experimental_bearer_token ?? process.env[provider.env_key]),
    providerHeaders: provider && {...provider.http_headers, ...Object.fromEntries(Object.entries(provider.env_http_headers ?? {}).map(([header, key]) => [header, process.env[key]]))},
    literalCredentialInEnvironment: ["synthetic-provider-token", "synthetic-provider-header"].some(value => Object.values(process.env).includes(value)),
  }));
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-merged-worker" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
    { mode: 0o700 },
  );
  if (script !== executable) {
    await copyFile(process.execPath, executable);
    return installFixtureSpawn(executable, script);
  }
}
