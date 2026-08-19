import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const PACKAGE_VERSIONS = packageVersions(
  new URL("../package.json", import.meta.url),
);

export const VERSION = PACKAGE_VERSIONS.package;
export const CODEX_SDK_VERSION = PACKAGE_VERSIONS.sdk;
export const CODEX_EXECUTABLE_VERSION = PACKAGE_VERSIONS.executable;
export const BUNDLED_PLUGIN_VERSION = "0.1.22" as const;

const PACKAGE_NAME = "@openai/codex-security";
const VERSION_PATTERN =
  /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/u;

export interface UpdateNotice {
  readonly currentVersion: string;
  readonly latestVersion: string;
  readonly command: string;
}

export function updateNoticeEnabled(environment: NodeJS.ProcessEnv): boolean {
  return (
    environment["CODEX_SECURITY_NO_UPDATE_NOTICE"] === undefined &&
    environment["NO_UPDATE_NOTIFIER"] === undefined &&
    environment["CI"] === undefined
  );
}

export function updateCommand(
  environment: NodeJS.ProcessEnv = process.env,
  entrypoint: string = fileURLToPath(import.meta.url),
): string {
  const path = entrypoint.replaceAll("\\", "/").toLowerCase();
  const agent = (environment["npm_config_user_agent"] ?? "").toLowerCase();

  if (
    environment["npm_command"] === "exec" ||
    environment["npm_lifecycle_event"] === "npx" ||
    path.includes("/_npx/")
  ) {
    return `npx ${PACKAGE_NAME}@latest`;
  }
  if (path.includes("/.install/node_modules/")) {
    return "download and extract the latest Codex Security release";
  }

  const global =
    environment["npm_config_global"] === "true" ||
    path.includes("/lib/node_modules/") ||
    path.includes("/appdata/roaming/npm/node_modules/") ||
    path.includes("/pnpm/global/") ||
    path.includes("/.bun/install/global/") ||
    path.includes("/.yarn/global/") ||
    path.includes("/yarn/global/");

  if (agent.startsWith("pnpm/") || path.includes("/.pnpm/")) {
    return `pnpm add${global ? " -g" : ""} ${PACKAGE_NAME}@latest`;
  }
  if (
    agent.startsWith("yarn/") ||
    path.includes("/.yarn/") ||
    path.includes("/yarn/global/")
  ) {
    return `yarn${global ? " global" : ""} add ${PACKAGE_NAME}@latest`;
  }
  if (agent.startsWith("bun/") || path.includes("/.bun/")) {
    return `bun add${global ? " -g" : ""} ${PACKAGE_NAME}@latest`;
  }
  return agent.startsWith("npm/") || path.includes("/node_modules/")
    ? `npm install${global ? " -g" : ""} ${PACKAGE_NAME}@latest`
    : `npx ${PACKAGE_NAME}@latest`;
}

export async function checkForUpdate({
  environment = process.env,
  entrypoint,
  currentVersion = VERSION,
  fetch: fetchLatest = fetch,
  signal,
}: {
  environment?: NodeJS.ProcessEnv;
  entrypoint?: string;
  currentVersion?: string;
  fetch?: (
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ) => ReturnType<typeof fetch>;
  signal?: AbortSignal;
} = {}): Promise<UpdateNotice | undefined> {
  if (!updateNoticeEnabled(environment)) return undefined;

  try {
    const registry =
      environment["CODEX_SECURITY_NPM_REGISTRY"] ??
      environment["npm_config_registry"] ??
      environment["NPM_CONFIG_REGISTRY"] ??
      "https://registry.npmjs.org/";
    const timeout = AbortSignal.timeout(3_000);
    const response = await fetchLatest(
      new URL(
        `${encodeURIComponent(PACKAGE_NAME)}/latest`,
        registry.endsWith("/") ? registry : `${registry}/`,
      ),
      {
        signal:
          signal === undefined ? timeout : AbortSignal.any([signal, timeout]),
      },
    );
    if (!response.ok) return undefined;

    const manifest: unknown = await response.json();
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      !("version" in manifest) ||
      typeof manifest.version !== "string" ||
      !isNewerVersion(manifest.version, currentVersion)
    ) {
      return undefined;
    }

    return {
      currentVersion,
      latestVersion: manifest.version,
      command: updateCommand(environment, entrypoint),
    };
  } catch {
    return undefined;
  }
}

export function formatUpdateNotice(notice: UpdateNotice): string {
  const lines = [
    `Codex Security update available: ${notice.currentVersion} → ${notice.latestVersion}`,
    `Run: ${notice.command}`,
  ];
  const width = Math.max(...lines.map((line) => line.length));
  return [
    "",
    `╭${"─".repeat(width + 2)}╮`,
    ...lines.map((line) => `│ ${line.padEnd(width)} │`),
    `╰${"─".repeat(width + 2)}╯`,
    "",
  ].join("\n");
}

function isNewerVersion(latest: string, current: string): boolean {
  const candidate = VERSION_PATTERN.exec(latest);
  const installed = VERSION_PATTERN.exec(current);
  if (candidate === null || installed === null) return false;

  for (let index = 1; index <= 3; index += 1) {
    const difference = Number(candidate[index]) - Number(installed[index]);
    if (difference !== 0) return difference > 0;
  }

  if (candidate[4] === installed[4]) return false;
  if (candidate[4] === undefined) return true;
  if (installed[4] === undefined) return false;
  return (
    new Intl.Collator("en", { numeric: true }).compare(
      candidate[4],
      installed[4],
    ) > 0
  );
}

function packageVersions(url: URL): {
  package: string;
  sdk: string;
  executable: string;
} {
  try {
    const manifest: unknown = JSON.parse(readFileSync(url, "utf8"));
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      !("version" in manifest) ||
      typeof manifest.version !== "string" ||
      manifest.version.length === 0
    ) {
      throw new Error("version must be a non-empty string");
    }
    const dependencies =
      "dependencies" in manifest ? manifest.dependencies : undefined;
    if (typeof dependencies !== "object" || dependencies === null) {
      throw new Error("dependencies must be an object");
    }
    const sdk =
      "@openai/codex-sdk" in dependencies
        ? dependencies["@openai/codex-sdk"]
        : undefined;
    const executable =
      "@openai/codex" in dependencies
        ? dependencies["@openai/codex"]
        : undefined;
    if (
      typeof sdk !== "string" ||
      sdk.length === 0 ||
      typeof executable !== "string" ||
      executable.length === 0
    ) {
      throw new Error("Codex dependencies must have non-empty versions");
    }
    return { package: manifest.version, sdk, executable };
  } catch (error) {
    throw new Error("Unable to read Codex Security package versions.", {
      cause: error,
    });
  }
}
