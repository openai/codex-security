import { isNonEmptyString } from "./value.js";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, resolve, win32 } from "node:path";
import { isWithin } from "./trusted-executable.js";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import semverGt from "semver/functions/gt.js";

const PACKAGE_VERSIONS = packageVersions(
  new URL("../package.json", import.meta.url),
);

export const VERSION = PACKAGE_VERSIONS.package;
export const CODEX_SDK_VERSION = PACKAGE_VERSIONS.sdk;
export const CODEX_EXECUTABLE_VERSION = PACKAGE_VERSIONS.executable;
export const BUNDLED_PLUGIN_VERSION = "0.1.95" as const;

const PACKAGE_NAME = "@openai/codex-security";

export interface UpdateNotice {
  readonly currentVersion: string;
  readonly latestVersion: string;
  readonly command: string;
}

export function updateNoticeEnabled(environment: NodeJS.ProcessEnv): boolean {
  return (
    environment["CODEX_SECURITY_NO_UPDATE_NOTICE"] === undefined &&
    environment["NO_UPDATE_NOTIFIER"] === undefined &&
    environment["npm_config_update_notifier"] !== "false" &&
    environment["CI"] === undefined
  );
}

/** @internal Whether the current CLI invocation runs through npm exec or npx. */
export function invokedWithNpx(
  environment: NodeJS.ProcessEnv,
  path = new URL(import.meta.url).pathname,
): boolean {
  return (
    environment["npm_command"] === "exec" ||
    environment["npm_lifecycle_event"] === "npx" ||
    path.includes("/_npx/")
  );
}

function resolveUpdate(
  environment: NodeJS.ProcessEnv = process.env,
  entrypoint: string = fileURLToPath(import.meta.url),
  nodeExecutable: string | undefined = process.platform === "win32"
    ? realpathSync(process.execPath)
    : undefined,
) {
  const windowsPath =
    !entrypoint.startsWith("/") && win32.isAbsolute(entrypoint);
  const path =
    process.platform === "linux" && !windowsPath
      ? entrypoint
      : entrypoint.replaceAll("\\", "/").toLowerCase();

  if (invokedWithNpx(environment, path)) {
    return { command: `npx ${PACKAGE_NAME}@latest` } as const;
  }
  if (path.includes("/.install/node_modules/")) {
    return {
      command: "download and extract the latest Codex Security release",
    } as const;
  }

  const nodeModulesDirectory =
    nodeExecutable === undefined
      ? undefined
      : win32
          .join(win32.dirname(nodeExecutable), "node_modules")
          .replaceAll("\\", "/")
          .toLowerCase();
  const modules = path.indexOf("/node_modules/");
  const directory =
    modules < 0 ? dirname(entrypoint) : entrypoint.slice(0, modules + 1);
  const installRoot = modules < 0 ? path : path.slice(0, modules + 1);
  let manifest: Record<string, unknown> | undefined;
  if (modules >= 0) {
    try {
      manifest = JSON.parse(
        readFileSync(join(directory, "package.json"), "utf8"),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  const fields = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ].filter((key) => Object.hasOwn(manifest?.[key] ?? {}, PACKAGE_NAME));
  const global =
    (installRoot.endsWith("/lib/") && manifest === undefined) ||
    installRoot.endsWith("/appdata/roaming/npm/") ||
    (nodeModulesDirectory !== undefined &&
      path.startsWith(`${nodeModulesDirectory}/`)) ||
    installRoot.includes("/pnpm/global/") ||
    installRoot.includes("/.bun/install/global/") ||
    installRoot.includes("/.yarn/global/") ||
    installRoot.includes("/yarn/global/") ||
    installRoot.includes("/yarn/data/global/");
  if (!global && modules < 0)
    return { command: `npx ${PACKAGE_NAME}@latest` } as const;
  // Plain node_modules layouts do not distinguish npm, Yarn and Bun.
  const packageManager = manifest?.["packageManager"];
  const lockfiles = [
    ["pnpm-lock.yaml", "pnpm"],
    ["yarn.lock", "yarn"],
    ["bun.lock", "bun"],
    ["bun.lockb", "bun"],
    ["package-lock.json", "npm"],
  ] as const;
  const agent =
    (typeof packageManager === "string"
      ? packageManager.split("@")[0]
      : undefined) ??
    (global
      ? undefined
      : lockfiles.find(([lock]) => existsSync(join(directory, lock)))?.[1]) ??
    (environment["npm_config_user_agent"] ?? "").toLowerCase().split("/")[0];

  let manager = "npm";
  let args = global ? ["install", "-g"] : ["install"];
  if (
    path.includes("/.pnpm/") ||
    path.includes("/pnpm/global/") ||
    (!global && agent === "pnpm")
  ) {
    manager = "pnpm";
    args = global ? ["add", "-g"] : ["add"];
    if (
      !global &&
      fields.length === 1 &&
      existsSync(join(directory, "pnpm-workspace.yaml"))
    )
      args.push("--workspace-root");
  } else if (
    path.includes("/.yarn/") ||
    path.includes("/yarn/global/") ||
    path.includes("/yarn/data/global/") ||
    (!global && agent === "yarn")
  ) {
    manager = "yarn";
    args = global ? ["global", "add"] : ["add"];
  } else if (path.includes("/.bun/") || (!global && agent === "bun")) {
    manager = "bun";
    args = global ? ["add", "-g"] : ["add"];
  }
  if (!global && fields.length === 1) {
    switch (fields[0]) {
      case "devDependencies":
        args.push("-D");
        break;
      case "optionalDependencies":
        args.push(manager === "bun" ? "--optional" : "-O");
        break;
      case "peerDependencies":
        args.push(manager === "npm" ? "--save-peer" : "--peer");
        break;
    }
  }
  args.push(`${PACKAGE_NAME}@latest`);
  return {
    command: [manager, ...args].join(" "),
    manager,
    global,
    directory,
    direct: fields.length === 1,
  } as const;
}

export function updateCommand(
  environment?: NodeJS.ProcessEnv,
  entrypoint?: string,
  nodeExecutable?: string,
): string {
  return resolveUpdate(environment, entrypoint, nodeExecutable).command;
}

/** Update a known npm global installation, or explain how to update it manually. */
export async function installUpdate(
  environment: NodeJS.ProcessEnv,
  entrypoint = fileURLToPath(import.meta.url),
  nodeExecutable = process.execPath,
): Promise<void> {
  const windows = process.platform === "win32";
  const update = resolveUpdate(
    environment,
    entrypoint,
    windows ? nodeExecutable : undefined,
  );
  if (!update.manager)
    throw new Error(`To use the latest version, ${update.command}.`);
  if (!update.global) {
    const project = update.direct
      ? JSON.stringify(resolve(update.directory))
      : `the project that declares ${PACKAGE_NAME}`;
    throw new Error(`Run ${update.command} from ${project}.`);
  }

  // Only Node's own npm can run without consulting PATH, shims or project
  // package-manager plugins. Point other global installations to their owner.
  const prefix =
    !windows && update.manager === "npm"
      ? dirname(update.directory)
      : resolve(update.directory);
  const manual = `Use the installation at ${JSON.stringify(prefix)} to run ${update.command}.`;
  if (update.manager !== "npm") throw new Error(manual);
  const node = realpathSync(nodeExecutable);
  const nodeBin = dirname(node);
  const nodePrefix = windows ? nodeBin : dirname(nodeBin);
  if (
    resolve(prefix) !== nodePrefix &&
    !(
      windows &&
      resolve(prefix) === join(userInfo().homedir, "AppData", "Roaming", "npm")
    )
  )
    throw new Error(manual);
  const npm = join(
    windows ? nodePrefix : join(nodePrefix, "lib"),
    "node_modules",
    "npm",
    "bin",
    "npm-cli.js",
  );
  // A checkout may supply a Node distribution or a linked npm script. Scope
  // this check to the invoking project; nvm itself can be a separate checkout.
  if (!existsSync(npm) || realpathSync(npm) !== npm) throw new Error(manual);
  const cwd = realpathSync(process.cwd());
  const { gitMarkerRoot } = await import("./targets.js");
  const checkout = await gitMarkerRoot(cwd, undefined, "nearest");
  const project =
    checkout ??
    (cwd === userInfo().homedir || cwd === dirname(cwd) ? null : cwd);
  if (project && (isWithin(project, nodeBin) || isWithin(project, npm)))
    throw new Error(manual);

  process.stderr.write(
    `Running ${update.command} for ${JSON.stringify(prefix)}\n`,
  );
  await runGlobalNpm(node, npm, prefix);
}

async function runGlobalNpm(
  node: string,
  npm: string,
  prefix: string,
): Promise<void> {
  const scratch = realpathSync(
    await mkdtemp(join(tmpdir(), "codex-security-update-")),
  );
  try {
    // A fresh home and cache avoid user credentials and registry overrides.
    // Global npm ignores project configuration; explicitly disable lifecycle
    // scripts and pin both the default registry and the @openai scope.
    const env: NodeJS.ProcessEnv = {
      HOME: scratch,
      USERPROFILE: scratch,
      PATH: dirname(node),
      npm_config_cache: join(scratch, "cache"),
      npm_config_userconfig: join(scratch, "user.npmrc"),
      npm_config_globalconfig: join(scratch, "global.npmrc"),
      ...(process.platform === "win32" && {
        SystemRoot: process.env["SystemRoot"],
      }),
    };
    const args = [
      npm,
      "install",
      "-g",
      `${PACKAGE_NAME}@latest`,
      "--prefix",
      prefix,
      "--ignore-scripts",
      "--registry=https://registry.npmjs.org/",
      "--@openai:registry=https://registry.npmjs.org/",
    ];
    await new Promise<void>((fulfilled, reject) => {
      const child = spawn(node, args, {
        cwd: scratch,
        env,
        stdio: ["ignore", process.stderr, process.stderr],
      });
      child.once("error", reject);
      child.once("close", (code, signal) => {
        if (code === 0) fulfilled();
        else reject(new Error(`npm install exited with ${signal ?? code}.`));
      });
    });
  } finally {
    await rm(scratch, { force: true, recursive: true });
  }
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
      !semverGt(manifest.version, currentVersion)
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

function packageVersions(url: URL) {
  try {
    const manifest: unknown = JSON.parse(readFileSync(url, "utf8"));
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      !("version" in manifest) ||
      !isNonEmptyString(manifest.version)
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
    if (!isNonEmptyString(sdk) || !isNonEmptyString(executable)) {
      throw new Error("Codex dependencies must have non-empty versions");
    }
    return { package: manifest.version, sdk, executable };
  } catch (error) {
    throw new Error("Unable to read Codex Security package versions.", {
      cause: error,
    });
  }
}
