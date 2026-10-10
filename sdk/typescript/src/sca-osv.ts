import { execFile as execFileCallback, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  dirname,
  join,
  posix,
  relative,
  sep,
  win32,
} from "node:path";
import { finished } from "node:stream/promises";
import { promisify } from "node:util";
import { parse as parseYaml } from "yaml";
import { parse as parseToml } from "smol-toml";
import semverValid from "semver/functions/valid.js";
import { errorMessage } from "./errors.js";
import {
  additionalScaFormat,
  inspectAdditionalScaInput,
  type ScaUnresolvedReference,
} from "./sca-inputs.js";
import { executablePathForSpawn } from "./runtime.js";
import type {
  ScaComponent,
  ScaCoverage,
  ScaFile,
  ScaInput,
  ScaMatch,
  ScaScanner,
} from "./sca-types.js";
import {
  enclosingGitWorktreeRoot,
  gitMarkerRoot,
  isolatedGitEnvironment,
  normalizeRepository,
  relativePathIsOutside,
  validatedGitEnvironment,
} from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const lockNames = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
]);

export interface OsvScanResult {
  scanner: ScaScanner;
  coverage: ScaCoverage;
  components: ScaComponent[];
  matches: ScaMatch[];
  diagnostics: string[];
  status: "completed" | "partial" | "failed";
}
export interface OsvProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}
export interface OsvProcessOptions {
  cwd: string;
  environment: Record<string, string | undefined>;
  signal?: AbortSignal;
  stdoutPath?: string;
  stderrPath?: string;
}
export type OsvProcessRunner = (
  executable: string,
  argv: string[],
  options: OsvProcessOptions,
) => Promise<OsvProcessResult>;
export interface OsvDependencies {
  executable?: string;
  runProcess?: OsvProcessRunner;
  now?: () => string;
}

function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
function stableId(prefix: string, values: unknown[]): string {
  return `${prefix}-${digest(JSON.stringify(values)).slice(0, 24)}`;
}
function slash(path: string): string {
  return path.split(sep).join("/");
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}
function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

type DependencyLocalReference = ScaUnresolvedReference;

const supportedEcosystems = new Set([
  "npm",
  "PyPI",
  "Go",
  "crates.io",
  "Maven",
  "RubyGems",
  "Packagist",
  "NuGet",
]);
function resolvedPackage(
  ecosystem: string | null,
  version: string | null,
): boolean {
  return (
    ecosystem !== null &&
    supportedEcosystems.has(ecosystem) &&
    version !== null &&
    version !== "" &&
    (ecosystem !== "npm" || semverValid(version) !== null)
  );
}
function packageName(ecosystem: string | null, name: string): string {
  if (ecosystem === "PyPI") return name.toLowerCase().replace(/[-_.]+/gu, "-");
  if (ecosystem === "NuGet") return name.toLowerCase();
  return name;
}
function sameReferenceName(
  reference: DependencyLocalReference,
  component: ScaComponent,
): boolean {
  return (
    packageName(reference.ecosystem, component.name) ===
    packageName(reference.ecosystem, reference.name)
  );
}
function referenceVersionMatches(
  reference: DependencyLocalReference,
  version: string | null,
): boolean {
  return (
    version === reference.version ||
    (reference.ecosystem === "npm" &&
      reference.version !== null &&
      version !== null &&
      reference.version.startsWith(`${version}(`))
  );
}

function alternateNpmTarball(value: string): boolean {
  return (
    /^https?:\/\//u.test(value) &&
    !/^https?:\/\/registry\.npmjs\.org(?:\/|$)/u.test(value)
  );
}

/** OSV omits pnpm links and loses non-Git tarball provenance. */
function pnpmLocalReferences(
  parsed: Record<string, unknown>,
  sourcePath: string,
): DependencyLocalReference[] {
  const references = new Map<string, DependencyLocalReference>();
  // The pinned extractor emits packages-entry identities, not importer aliases or
  // file references. Explicit name/version fields override the v9 package key.
  const packages = parsed["packages"];
  if (record(packages))
    for (const [key, entry] of Object.entries(packages)) {
      if (!record(entry)) continue;
      const packageKey = key.replace(/^'+|'+$/gu, "");
      const separator = packageKey.indexOf(
        "@",
        packageKey.startsWith("@") ? 1 : 0,
      );
      const directReference = /^(?:file:|https?:\/\/)/u.test(packageKey);
      const keyName =
        directReference || separator === -1
          ? ""
          : packageKey.slice(0, separator);
      const keyVersion = directReference
        ? packageKey
        : separator === -1
          ? ""
          : packageKey.slice(separator + 1);
      const tarball = record(entry["resolution"])
        ? entry["resolution"]["tarball"]
        : null;
      // Public registry tarballs retain registry identity; explicit direct URL
      // keys and alternate tarball origins remain unresolved.
      const resolution = /^(?:file:|link:|https?:\/\/)/u.test(keyVersion)
        ? keyVersion
        : typeof tarball === "string" &&
            (/^(?:file|link):/u.test(tarball) || alternateNpmTarball(tarball))
          ? tarball
          : null;
      if (resolution === null) continue;
      const name =
        typeof entry["name"] === "string" && entry["name"] !== ""
          ? entry["name"]
          : keyName;
      const version =
        typeof entry["version"] === "string" && entry["version"] !== ""
          ? entry["version"]
          : packageKey.startsWith("file:")
            ? ""
            : keyVersion;
      if (!name || !version) continue;
      references.set(JSON.stringify([name, version, resolution]), {
        sourcePath,
        ecosystem: "npm",
        name,
        version,
        resolution,
      });
    }
  const packageReferences = [...references.values()];
  for (const section of [parsed["importers"], parsed["snapshots"]]) {
    if (!record(section)) continue;
    for (const project of Object.values(section)) {
      if (!record(project)) continue;
      for (const group of [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
      ]) {
        const dependencies = project[group];
        if (!record(dependencies)) continue;
        for (const [name, dependency] of Object.entries(dependencies)) {
          const version = record(dependency)
            ? dependency["version"]
            : dependency;
          if (
            typeof version !== "string" ||
            !/^(?:file:|link:|https?:\/\/)/u.test(version)
          )
            continue;
          if (
            packageReferences.some(
              (reference) =>
                reference.resolution === version ||
                version.startsWith(`${reference.resolution}(`),
            )
          )
            continue;
          references.set(JSON.stringify([name, version, version]), {
            sourcePath,
            ecosystem: "npm",
            name,
            version,
            resolution: version,
          });
        }
      }
    }
  }
  return [...references.values()];
}

/** A semver in an npm lockfile does not establish registry provenance. */
function npmLocalReferences(
  parsed: Record<string, unknown>,
  sourcePath: string,
): DependencyLocalReference[] {
  const packages = parsed["packages"];
  if (!record(packages)) return [];
  // A matching dependency specifier records an explicit direct URL origin even
  // when its tarball is hosted by the public registry.
  const directUrls = new Set<string>();
  for (const dependency of Object.values(packages)) {
    if (!record(dependency)) continue;
    for (const group of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
    ]) {
      const specifiers = dependency[group];
      if (!record(specifiers)) continue;
      for (const specifier of Object.values(specifiers))
        if (typeof specifier === "string" && /^https?:\/\//u.test(specifier))
          directUrls.add(specifier);
    }
  }
  const references = new Map<string, DependencyLocalReference>();
  for (const [path, dependency] of Object.entries(packages)) {
    if (!path || !record(dependency)) continue;
    const resolved = dependency["resolved"];
    if (
      dependency["link"] !== true &&
      (typeof resolved !== "string" ||
        (!/^(?:file|link|git\+file):/u.test(resolved) &&
          !directUrls.has(resolved) &&
          !alternateNpmTarball(resolved)))
    )
      continue;
    const name =
      typeof dependency["name"] === "string"
        ? dependency["name"]
        : path.split("node_modules/").at(-1)!;
    const version =
      typeof dependency["version"] === "string" ? dependency["version"] : null;
    const resolution =
      typeof resolved === "string" ? resolved : "workspace link";
    references.set(JSON.stringify([name, version, resolution]), {
      sourcePath,
      ecosystem: "npm",
      name,
      version,
      resolution,
    });
  }
  return [...references.values()];
}

function uncountedLocalReferences(
  references: DependencyLocalReference[],
  components: ScaComponent[],
  stderr = "",
): number {
  return references.filter(
    (reference) =>
      !excludedLocalReference(reference, components, stderr) &&
      !components.some(
        (component) =>
          component.sourcePath === reference.sourcePath &&
          sameReferenceName(reference, component) &&
          !resolvedPackage(component.ecosystem, component.version) &&
          referenceVersionMatches(reference, component.version),
      ),
  ).length;
}

/** Scanner receipts reflect config matching, groups, regexes, and expiry. */
function packageFilteringReceipts(stderr: string): string[] {
  return stderr
    .split(/\r?\n/u)
    .filter(
      (line) =>
        line.startsWith("Package ") &&
        line.includes(" has been filtered out because:"),
    );
}

function excludedLocalReference(
  reference: DependencyLocalReference,
  components: ScaComponent[],
  stderr: string,
): boolean {
  const referenceVersion = reference.version;
  if (
    reference.omittedCategory !== undefined ||
    referenceVersion === null ||
    components.some(
      (component) =>
        component.sourcePath === reference.sourcePath &&
        sameReferenceName(reference, component) &&
        referenceVersionMatches(reference, component.version),
    )
  )
    return false;
  const prefix = `Package ${reference.ecosystem}/${packageName(reference.ecosystem, reference.name)}/`;
  return packageFilteringReceipts(stderr).some((line) => {
    // NuGet package IDs are case-insensitive; OSV receipts retain the lockfile spelling.
    const matchesPrefix =
      reference.ecosystem === "NuGet"
        ? line.slice(0, prefix.length).toLowerCase() === prefix.toLowerCase()
        : line.startsWith(prefix);
    if (!matchesPrefix) return false;
    const end = line.indexOf(" has been filtered out because:", prefix.length);
    if (end === -1) return false;
    const version = line.slice(prefix.length, end);
    return version !== "" && referenceVersionMatches(reference, version);
  });
}

function caseInsensitiveField(
  value: Record<string, unknown>,
  name: string,
): unknown {
  return Object.entries(value).find(([key]) => key.toLowerCase() === name)?.[1];
}

function inputProvenance(
  coverage: Pick<ScaCoverage, "inputs" | "configFiles" | "limitations">,
): string {
  return JSON.stringify({
    inputs: coverage.inputs.map(({ path, sha256, format, status }) => ({
      path,
      sha256,
      format,
      status,
    })),
    configFiles: coverage.configFiles,
    limitations: coverage.limitations,
  });
}

/** Use the same tracked/untracked, non-ignored scope as other repository operations. */
async function repositoryFiles(
  repository: string,
  environment: Record<string, string | undefined>,
  signal?: AbortSignal,
): Promise<{
  files: string[];
  submodules: string[];
  nestedRepositories: string[];
  skipWorktree: string[];
}> {
  const worktree = await enclosingGitWorktreeRoot(repository, signal, {
    requireIfPresent: true,
  });
  if (worktree !== null) {
    validatedGitEnvironment(environment);
    const git = await resolveTrustedExecutable(
      "git",
      isolatedGitEnvironment(false, environment),
      (await gitMarkerRoot(repository, signal, "outermost")) ?? repository,
    );
    if (git === null)
      throw new Error(
        "Git is required to enumerate dependency inputs in this repository.",
      );
    const listing = (args: string[]) =>
      execFile(
        git.executable,
        [
          "-c",
          "core.fsmonitor=false",
          "-C",
          worktree,
          "ls-files",
          ...args,
          "-z",
          "--",
          ".",
        ],
        { env: git.environment, signal, maxBuffer: Infinity },
      );
    const [listed, staged] = await Promise.all([
      listing([
        "-t",
        "--cached",
        "--others",
        "--exclude-standard",
        "--deduplicate",
      ]),
      listing(["--stage"]),
    ]);
    const scope = relative(worktree, repository);
    const depth = scope === "" ? 0 : scope.split(sep).length;
    const metadata =
      depth === 0 ? null : await stat(repository, { bigint: true });
    const prefixes = new Map<string, boolean>();
    const inScope = async (path: string): Promise<string | null> => {
      const parts = path.split("/");
      if (parts.length <= depth || parts.slice(depth).includes("node_modules"))
        return null;
      if (depth === 0) return path;
      const prefix = parts.slice(0, depth).join("/");
      if (!prefixes.has(prefix)) {
        const candidate = await stat(join(worktree, prefix), {
          bigint: true,
        }).catch((error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
          throw error;
        });
        // Index spelling can differ after a case-only rename. Filesystem identity
        // also keeps distinct case-sensitive directories from sharing inventory.
        prefixes.set(
          prefix,
          candidate !== null &&
            candidate.dev === metadata!.dev &&
            candidate.ino === metadata!.ino,
        );
      }
      return prefixes.get(prefix) ? parts.slice(depth).join("/") : null;
    };
    const selected = async (paths: string[]) => {
      const result: string[] = [];
      for (const path of paths) {
        signal?.throwIfAborted();
        const scoped = await inScope(path);
        if (scoped !== null) result.push(scoped);
      }
      return unique(result);
    };
    const listedEntries = listed.stdout.split("\0").filter(Boolean);
    const listedPaths = listedEntries.map((entry) => entry.slice(2));
    return {
      files: await selected(listedPaths.filter((path) => !path.endsWith("/"))),
      skipWorktree: await selected(
        listedEntries
          .filter((entry) => entry.startsWith("S "))
          .map((entry) => entry.slice(2)),
      ),
      // Git lists an untracked nested checkout as a directory, not its contents.
      nestedRepositories: await selected(
        listedPaths
          .filter((path) => path.endsWith("/"))
          .map((path) => path.slice(0, -1)),
      ),
      submodules: await selected(
        staged.stdout
          .split("\0")
          .filter((entry) => entry.startsWith("160000 "))
          .map((entry) => entry.slice(entry.indexOf("\t") + 1)),
      ),
    };
  }
  const files: string[] = [];
  const pending = [repository];
  while (pending.length) {
    signal?.throwIfAborted();
    const directory = pending.pop()!;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else files.push(relative(repository, path));
    }
  }
  return { files, submodules: [], nestedRepositories: [], skipWorktree: [] };
}

type ScaInputDiscovery = Pick<
  ScaCoverage,
  "inputs" | "configFiles" | "limitations"
> & {
  localReferences: DependencyLocalReference[];
  diagnostics: string[];
};

class ScaInputDiscoveryError extends Error {
  constructor(
    error: unknown,
    readonly discovery: ScaInputDiscovery,
  ) {
    super(errorMessage(error), { cause: error });
  }
}

/** Select effective lockfiles before invoking OSV, which itself gives shrinkwrap precedence. */
export async function discoverScaInputs(
  repositoryPath: string,
  environment: Record<string, string | undefined> = process.env,
  signal?: AbortSignal,
): Promise<ScaInputDiscovery> {
  const repository = await normalizeRepository(repositoryPath, signal);
  const { files, submodules, nestedRepositories, skipWorktree } =
    await repositoryFiles(repository, environment, signal);
  const candidates = files
    .filter(
      (path) =>
        lockNames.has(basename(path)) || additionalScaFormat(path) !== null,
    )
    .map(slash)
    .sort();
  const inputs: ScaInput[] = [];
  const configFiles: ScaFile[] = [];
  const localReferences: DependencyLocalReference[] = [];
  const diagnostics = [
    ...submodules.map(
      (path) =>
        `Git submodule ${path} is not inspected by dependency inventory; coverage is incomplete.`,
    ),
    ...nestedRepositories.map(
      (path) =>
        `Untracked nested Git repository ${path} is not inspected by dependency inventory; coverage is incomplete.`,
    ),
  ];
  const limitations: string[] = [
    "Inventory covers observed package tuples in supported dependency files, not every installed instance, runtime, or a complete dependency graph.",
    ...diagnostics,
  ];
  for (const candidate of candidates) {
    signal?.throwIfAborted();
    const path = join(repository, candidate);
    const additional = additionalScaFormat(path);
    const input: ScaInput = {
      path: slash(candidate),
      sha256: "",
      format:
        additional ?? (basename(path) === "pnpm-lock.yaml" ? "pnpm" : "npm"),
      status: "scanned",
      reason: null,
    };
    inputs.push(input);
    try {
      const metadata = await lstat(path).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
          throw error;
        },
      );
      if (metadata === null) {
        if (skipWorktree.includes(candidate)) {
          input.status = "unsupported";
          input.reason =
            "Tracked lockfile is unavailable in this sparse checkout; coverage is incomplete.";
          continue;
        }
        // The Git index can still list a file deleted from the working tree.
        inputs.pop();
        continue;
      }
      if (
        !metadata.isFile() ||
        relativePathIsOutside(relative(repository, await realpath(path)))
      ) {
        input.status = "unsupported";
        input.reason =
          "Lockfile is not a regular file within the selected repository.";
        continue;
      }
      const content = await readFile(path);
      input.sha256 = digest(content);
      if (
        basename(path) === "package-lock.json" &&
        (await lstat(join(dirname(path), "npm-shrinkwrap.json")).then(
          () => true,
          (error: NodeJS.ErrnoException) => {
            if (error.code === "ENOENT") return false;
            throw error;
          },
        ))
      ) {
        input.status = "excluded";
        input.reason =
          "npm-shrinkwrap.json takes precedence in this directory.";
        // A gitignored shrinkwrap still changes npm and OSV interpretation.
        const shrinkwrap = slash(
          relative(repository, join(dirname(path), "npm-shrinkwrap.json")),
        );
        if (!candidates.includes(shrinkwrap)) {
          input.status = "unsupported";
          input.reason =
            "An npm-shrinkwrap.json outside the selected file scope takes precedence; the package-lock.json cannot be assessed as effective input.";
        }
        continue;
      }
      if (additional !== null) {
        const inspected = inspectAdditionalScaInput(
          content.toString("utf8"),
          additional,
          input.path,
        );
        input.status = inspected.status;
        input.reason = inspected.reason;
        localReferences.push(...inspected.references);
        diagnostics.push(...inspected.diagnostics);
        limitations.push(...inspected.limitations);
        if (inspected.references.length > 0)
          limitations.push(
            `${input.path} includes unresolved dependency origins: ${inspected.references.map((reference) => `${reference.ecosystem}/${reference.name}@${reference.version ?? "unresolved"} (${reference.resolution})`).join(", ")}.`,
          );
        continue;
      }
      const parsed: unknown =
        input.format === "npm"
          ? JSON.parse(content.toString("utf8"))
          : parseYaml(content.toString("utf8"));
      const version = record(parsed) ? parsed["lockfileVersion"] : undefined;
      if (
        input.format === "npm"
          ? version !== 2 && version !== 3
          : String(version) !== "9.0" && String(version) !== "9"
      ) {
        input.status = "unsupported";
        input.reason = `Unsupported ${input.format} lockfile version: ${String(version)}.`;
      } else if (record(parsed)) {
        const references =
          input.format === "pnpm"
            ? pnpmLocalReferences(parsed, input.path)
            : npmLocalReferences(parsed, input.path);
        localReferences.push(...references);
        if (references.length > 0)
          limitations.push(
            `${input.path} includes local or direct URL dependency references outside npm registry matching: ${references.map((reference) => `${reference.name}@${reference.resolution}`).join(", ")}.`,
          );
      }
    } catch (error) {
      signal?.throwIfAborted();
      input.status = "failed";
      input.reason = errorMessage(error);
    }
  }
  const directories = unique(
    inputs
      .filter((input) => input.status === "scanned")
      .map((input) => dirname(join(repository, input.path))),
  );
  try {
    for (const directory of directories) {
      const path = join(directory, "osv-scanner.toml");
      const metadata = await lstat(path).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return null;
          throw error;
        },
      );
      if (metadata === null) continue;
      if (
        !metadata.isFile() ||
        relativePathIsOutside(relative(repository, await realpath(path)))
      )
        throw new Error(
          `OSV configuration must be a regular file within the selected repository: ${path}`,
        );
      const content = await readFile(path);
      configFiles.push({
        path: slash(relative(repository, path)),
        sha256: digest(content),
      });
      let config: Record<string, unknown>;
      try {
        config = parseToml(content.toString("utf8"));
      } catch (error) {
        diagnostics.push(
          `Unable to parse OSV configuration ${slash(relative(repository, path))}: ${errorMessage(error)}`,
        );
        continue;
      }
      const overrides = caseInsensitiveField(config, "packageoverrides");
      if (
        caseInsensitiveField(config, "ignoredvulns") !== undefined ||
        overrides !== undefined
      )
        limitations.push(
          `OSV exclusions/overrides are configured in ${slash(relative(repository, path))}; results are evaluated after these settings. Exact suppressed counts are unavailable.`,
        );
    }
  } catch (error) {
    throw new ScaInputDiscoveryError(error, {
      inputs,
      configFiles,
      limitations,
      localReferences,
      diagnostics,
    });
  }

  return {
    inputs,
    configFiles,
    limitations,
    localReferences,
    diagnostics,
  };
}

/** Error diagnostics from the pinned scanner can accompany exit 0 and valid JSON. */
export function osvErrorDiagnostics(stderr: string): string[] {
  return stderr
    .split(/\r?\n/u)
    .filter((line) =>
      /Error during extraction:|could not load db for .+ ecosystem:|Ignored invalid config file at |Skipping .+: short commit hash .+ cannot be queried;/u.test(
        line,
      ),
    );
}

function sourceRelativePath(repository: string, source: string): string {
  const windows = win32.isAbsolute(repository) && !posix.isAbsolute(repository);
  const paths = windows ? win32 : posix;
  const normalized = paths.relative(
    repository,
    paths.isAbsolute(source) ? source : paths.resolve(repository, source),
  );
  return windows ? normalized.replaceAll("\\", "/") : normalized;
}

/** Normalize scanner facts only. Every advisory is retained; aliases join groups transitively. */
export function normalizeOsvOutput(
  raw: unknown,
  options: { repositoryPath: string; inputs: readonly ScaInput[] },
): {
  components: ScaComponent[];
  matches: ScaMatch[];
  diagnostics: string[];
  unresolvedPackages: number;
} {
  const components: ScaComponent[] = [];
  const matches: ScaMatch[] = [];
  const diagnostics: string[] = [];
  let unresolvedPackages = 0;
  if (!record(raw) || !Array.isArray(raw["results"]))
    throw new Error("OSV output must contain a results array.");
  const selected = new Set(
    options.inputs
      .filter((input) => input.status === "scanned")
      .map((input) => input.path),
  );
  for (const source of raw["results"]) {
    if (
      !record(source) ||
      !record(source["source"]) ||
      typeof source["source"]["path"] !== "string" ||
      !Array.isArray(source["packages"])
    ) {
      diagnostics.push(
        "OSV result has missing source or packages fields; inspect retained raw output.",
      );
      continue;
    }
    const sourcePath = sourceRelativePath(
      options.repositoryPath,
      source["source"]["path"],
    );
    if (!selected.has(sourcePath)) {
      diagnostics.push(
        `OSV returned a source outside the selected inputs: ${sourcePath}.`,
      );
      continue;
    }
    for (const item of source["packages"]) {
      if (!record(item) || !record(item["package"])) {
        unresolvedPackages++;
        diagnostics.push(`OSV package identity is missing in ${sourcePath}.`);
        continue;
      }
      const pkg = item["package"];
      const name = typeof pkg["name"] === "string" ? pkg["name"] : "";
      const version =
        typeof pkg["version"] === "string" && pkg["version"] !== ""
          ? pkg["version"]
          : null;
      const ecosystem =
        typeof pkg["ecosystem"] === "string" && pkg["ecosystem"] !== ""
          ? pkg["ecosystem"]
          : null;
      if (
        name === "" ||
        version === null ||
        !resolvedPackage(ecosystem, version)
      )
        unresolvedPackages++;
      if (ecosystem !== null && !supportedEcosystems.has(ecosystem))
        diagnostics.push(
          `Package ${name} in ${sourcePath} uses unsupported ecosystem ${ecosystem}. Raw scanner evidence is retained.`,
        );
      const id = stableId("component", [
        sourcePath,
        ecosystem,
        name,
        version,
        pkg["commit"] ?? null,
      ]);
      let component = components.find((candidate) => candidate.id === id);
      if (component === undefined) {
        component = {
          id,
          name,
          version,
          ecosystem,
          sourcePath,
          dependencyGroups: strings(item["dependency_groups"]),
        };
        components.push(component);
      } else
        component.dependencyGroups = unique([
          ...component.dependencyGroups,
          ...strings(item["dependency_groups"]),
        ]);
      if (
        item["vulnerabilities"] !== undefined &&
        !Array.isArray(item["vulnerabilities"])
      ) {
        diagnostics.push(
          `OSV vulnerabilities must be an array for ${sourcePath}:${name}.`,
        );
        continue;
      }
      const vulnerabilities = Array.isArray(item["vulnerabilities"])
        ? item["vulnerabilities"]
        : [];
      const validAdvisories = vulnerabilities.filter(
        (advisory): advisory is Record<string, unknown> =>
          record(advisory) &&
          typeof advisory["id"] === "string" &&
          advisory["id"] !== "",
      );
      if (validAdvisories.length !== vulnerabilities.length)
        diagnostics.push(
          `OSV advisory ID is missing for ${sourcePath}:${name}; inspect retained raw output.`,
        );
      const groups = Array.isArray(item["groups"])
        ? item["groups"].filter(record)
        : [];
      const buckets: {
        advisories: Record<string, unknown>[];
        ids: Set<string>;
        severity: string | null;
      }[] = [];
      for (const advisory of validAdvisories) {
        const advisoryId = advisory["id"] as string;
        const matchingGroups = groups.filter((group) =>
          strings(group["ids"]).includes(advisoryId),
        );
        const ids = new Set([
          advisoryId,
          ...strings(advisory["aliases"]),
          ...matchingGroups.flatMap((group) => [
            ...strings(group["ids"]),
            ...strings(group["aliases"]),
          ]),
        ]);
        const joined = buckets.filter((bucket) =>
          [...bucket.ids].some((value) => ids.has(value)),
        );
        for (const bucket of joined)
          for (const value of bucket.ids) ids.add(value);
        const severity =
          matchingGroups
            .map((group) => group["max_severity"])
            .find(
              (value): value is string =>
                typeof value === "string" && value !== "",
            ) ??
          joined.find((bucket) => bucket.severity !== null)?.severity ??
          null;
        for (const bucket of joined) buckets.splice(buckets.indexOf(bucket), 1);
        buckets.push({
          advisories: [
            ...joined.flatMap((bucket) => bucket.advisories),
            advisory,
          ],
          ids,
          severity,
        });
      }
      for (const bucket of buckets) {
        const advisoryIds = unique(
          bucket.advisories.map((advisory) => advisory["id"] as string),
        );
        const aliases = unique([...bucket.ids]);
        const fixedVersions: string[] = [];
        for (const advisory of bucket.advisories) {
          if (!Array.isArray(advisory["affected"])) continue;
          for (const affected of advisory["affected"]) {
            if (
              !record(affected) ||
              !record(affected["package"]) ||
              typeof affected["package"]["name"] !== "string" ||
              packageName(ecosystem, affected["package"]["name"]) !==
                packageName(ecosystem, name) ||
              affected["package"]["ecosystem"] !== ecosystem ||
              !Array.isArray(affected["ranges"])
            )
              continue;
            for (const range of affected["ranges"])
              if (
                record(range) &&
                (range["type"] === "SEMVER" || range["type"] === "ECOSYSTEM") &&
                Array.isArray(range["events"])
              )
                for (const event of range["events"])
                  if (record(event) && typeof event["fixed"] === "string")
                    fixedVersions.push(event["fixed"]);
          }
        }
        const match: ScaMatch = {
          id: stableId("match", [id, aliases]),
          componentId: id,
          advisoryIds,
          aliases,
          sourceAdvisories: bucket.advisories,
          severity: bucket.severity,
          fixedVersions: unique(fixedVersions),
          advisoryModifiedAt: unique(
            bucket.advisories
              .map((advisory) => advisory["modified"])
              .filter((value): value is string => typeof value === "string"),
          ),
        };
        const existing = matches.find((candidate) => candidate.id === match.id);
        if (existing === undefined) matches.push(match);
        else existing.sourceAdvisories.push(...match.sourceAdvisories);
      }
    }
  }
  return { components, matches, diagnostics, unresolvedPackages };
}

/** Keep stream files even if the child is interrupted. No shell or process-global mutation. */
export const runOsvProcess: OsvProcessRunner = async (
  executable,
  argv,
  options,
) => {
  options.signal?.throwIfAborted();
  const stdoutFile =
    options.stdoutPath === undefined
      ? null
      : createWriteStream(options.stdoutPath);
  const stderrFile =
    options.stderrPath === undefined
      ? null
      : createWriteStream(options.stderrPath);
  const files = [stdoutFile, stderrFile].filter((file) => file !== null);
  let processError: Error | undefined;
  for (const file of files)
    file.on("error", (error) => {
      processError = error;
    });
  const child = spawn(executablePathForSpawn(executable), argv, {
    cwd: options.cwd,
    env: options.environment,
    signal: options.signal,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
    stdoutFile?.write(chunk);
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
    stderrFile?.write(chunk);
  });
  const exitCode = await new Promise<number | null>((finish) => {
    child.once("error", (error) => {
      processError = error;
    });
    child.once("close", finish);
  });
  for (const file of files) file.end();
  await Promise.all(files.map((file) => finished(file)));
  if (processError !== undefined) throw processError;
  return { stdout, stderr, exitCode };
};

export async function runOsvScan(
  options: {
    repositoryPath: string;
    outputDir: string;
    environment?: Record<string, string | undefined>;
    signal?: AbortSignal;
  },
  dependencies: OsvDependencies = {},
): Promise<OsvScanResult> {
  const now = dependencies.now ?? (() => new Date().toISOString());
  const scanner: ScaScanner = {
    name: "osv-scanner",
    version: null,
    argv: [],
    invocations: [],
    startedAt: now(),
    completedAt: "",
    exitCode: null,
    rawOutputPath: join(options.outputDir, "osv-output.json"),
    stderrPath: join(options.outputDir, "osv-stderr.log"),
    advisoryMode: "online",
    advisorySnapshotId: null,
  };
  const result: OsvScanResult = {
    scanner,
    coverage: {
      status: "failed",
      inputs: [],
      configFiles: [],
      limitations: [],
      unresolvedPackages: 0,
    },
    components: [],
    matches: [],
    diagnostics: [],
    status: "failed",
  };
  await mkdir(options.outputDir, { recursive: true });
  await Promise.all([
    writeFile(scanner.rawOutputPath, ""),
    writeFile(scanner.stderrPath, ""),
  ]);
  const environment = { ...(options.environment ?? process.env) };
  let localReferences: DependencyLocalReference[] = [];
  let repository = options.repositoryPath;
  let selected: ScaInput[] = [];
  let pending: {
    input: ScaInput;
    invocation: NonNullable<ScaScanner["invocations"]>[number];
  } | null = null;
  const reconciledSources = new Set<string>();
  const rawSources: unknown[] = [];
  const stderrOutputs: string[] = [];
  const emptyOutputPaths = new Set<string>();
  let unresolvedPackages = 0;
  const consumeOutput = (raw: unknown, stderr: string, input: ScaInput) => {
    const normalized = normalizeOsvOutput(raw, {
      repositoryPath: repository,
      inputs: [input],
    });
    result.components.push(...normalized.components);
    result.matches.push(...normalized.matches);
    result.diagnostics.push(...normalized.diagnostics);
    unresolvedPackages +=
      normalized.unresolvedPackages +
      uncountedLocalReferences(
        localReferences.filter(
          (reference) => reference.sourcePath === input.path,
        ),
        normalized.components,
        stderr,
      );
    reconciledSources.add(input.path);
    result.coverage.unresolvedPackages =
      unresolvedPackages +
      localReferences.filter(
        (reference) => !reconciledSources.has(reference.sourcePath),
      ).length;
    const sources =
      record(raw) && Array.isArray(raw["results"]) ? raw["results"] : [];
    rawSources.push(...sources);
    return new Set(
      sources.flatMap((entry) =>
        record(entry) &&
        record(entry["source"]) &&
        typeof entry["source"]["path"] === "string"
          ? [sourceRelativePath(repository, entry["source"]["path"])]
          : [],
      ),
    );
  };
  const persistAggregate = async () => {
    if (selected.length <= 1) return;
    await Promise.all([
      writeFile(
        scanner.rawOutputPath,
        JSON.stringify({ results: rawSources }, null, 2) + "\n",
      ),
      writeFile(scanner.stderrPath, stderrOutputs.join("\n")),
    ]);
  };
  try {
    options.signal?.throwIfAborted();
    repository = await normalizeRepository(
      options.repositoryPath,
      options.signal,
    );
    const {
      localReferences: discoveredLocalReferences,
      diagnostics,
      ...discovered
    } = await discoverScaInputs(repository, environment, options.signal);
    localReferences = discoveredLocalReferences;
    const capturedProvenance = inputProvenance(discovered);
    Object.assign(result.coverage, discovered);
    result.coverage.unresolvedPackages = localReferences.length;
    result.diagnostics.push(...diagnostics);
    selected = result.coverage.inputs.filter(
      (input) => input.status === "scanned",
    );
    if (selected.length === 0) {
      result.diagnostics.push(
        "No supported effective dependency lockfiles were available.",
      );
      return result;
    }
    const executable = await resolveTrustedExecutable(
      dependencies.executable ?? "osv-scanner",
      environment,
      (await gitMarkerRoot(repository, options.signal, "outermost")) ??
        repository,
    );
    if (executable === null)
      throw new Error(
        "OSV-Scanner is not installed on the trusted PATH. Install OSV-Scanner v2.6.0 or a compatible version.",
      );
    const run = dependencies.runProcess ?? runOsvProcess;
    const processOptions = {
      cwd: repository,
      environment: executable.environment,
      signal: options.signal,
    };
    const version = await run(
      executable.executable,
      ["--version"],
      processOptions,
    );
    if (version.exitCode !== 0)
      throw new Error(
        `OSV version check failed with exit code ${version.exitCode}: ${version.stderr}`,
      );
    scanner.version = version.stdout.trim() || null;
    for (const [index, input] of selected.entries()) {
      options.signal?.throwIfAborted();
      // Positional files remain literal; OSV's --lockfile StringSliceFlag splits commas.
      // One file per process also avoids aggregate Windows command-line limits and
      // attributes OSV package-exclusion receipts to exactly one source.
      const invocation = {
        argv: [
          "scan",
          "source",
          "--format=json",
          "--all-packages",
          "--no-call-analysis=all",
          "--no-resolve",
          "--",
          join(repository, input.path),
        ],
        exitCode: null as number | null,
        rawOutputPath:
          selected.length === 1
            ? scanner.rawOutputPath
            : join(options.outputDir, `osv-invocation-${index + 1}.json`),
        stderrPath:
          selected.length === 1
            ? scanner.stderrPath
            : join(options.outputDir, `osv-invocation-${index + 1}.stderr.log`),
      };
      await Promise.all([
        writeFile(invocation.rawOutputPath, ""),
        writeFile(invocation.stderrPath, ""),
      ]);
      scanner.invocations!.push(invocation);
      if (index === 0) scanner.argv = invocation.argv;
      pending = { input, invocation };
      const output = await run(executable.executable, invocation.argv, {
        ...processOptions,
        stdoutPath: invocation.rawOutputPath,
        stderrPath: invocation.stderrPath,
      });
      invocation.exitCode = output.exitCode;
      const emptyInputReceipt = `Scanned ${join(repository, input.path)
        .replaceAll("\r", "%0D")
        .replaceAll("\n", "%0A")} file and found 0 package`;
      const emptyInput =
        output.exitCode === 128 && output.stderr.includes(emptyInputReceipt);
      if (emptyInput) {
        emptyOutputPaths.add(invocation.rawOutputPath);
        input.reason = "OSV extracted no packages from this lockfile.";
      }
      const effectiveCodes = scanner
        .invocations!.filter(
          (call) => !emptyOutputPaths.has(call.rawOutputPath),
        )
        .map((call) => call.exitCode);
      const errorCode = effectiveCodes.find((code) => code !== 0 && code !== 1);
      scanner.exitCode =
        errorCode !== undefined
          ? errorCode
          : effectiveCodes.length === 0
            ? 128
            : effectiveCodes.includes(1)
              ? 1
              : 0;
      await Promise.all([
        writeFile(invocation.rawOutputPath, output.stdout),
        writeFile(invocation.stderrPath, output.stderr),
      ]);
      stderrOutputs.push(output.stderr);
      const diagnosticStart = result.diagnostics.length;
      result.diagnostics.push(...osvErrorDiagnostics(output.stderr));
      const matchCount = result.matches.length;
      if (output.stdout.trim() !== "") {
        let sources: Set<string> | undefined;
        try {
          sources = consumeOutput(
            JSON.parse(output.stdout),
            output.stderr,
            input,
          );
        } catch (error) {
          options.signal?.throwIfAborted();
          result.diagnostics.push(`${input.path}: ${errorMessage(error)}`);
        }
        if (sources !== undefined && !sources.has(input.path)) {
          if (output.stderr.includes(emptyInputReceipt)) {
            input.reason = "OSV extracted no packages from this lockfile.";
          } else if (packageFilteringReceipts(output.stderr).length > 0) {
            input.reason =
              "OSV returned no package tuples after applying configured package exclusions; suppressed counts are unavailable.";
          } else {
            input.status = "failed";
            input.reason =
              "The selected lockfile is absent from OSV output without evidence of an empty or excluded inventory.";
            result.diagnostics.push(`${input.path}: ${input.reason}`);
          }
        }
      } else if (emptyInput) {
        consumeOutput({ results: [] }, output.stderr, input);
      } else if (output.exitCode !== 128)
        result.diagnostics.push("OSV returned no JSON output.");
      pending = null;
      if (output.exitCode === 128 && !emptyInput)
        result.diagnostics.push(
          `${input.path}: OSV found no packages in the selected effective input; this is not a clean-repository result.`,
        );
      else if (output.exitCode !== 0 && output.exitCode !== 1 && !emptyInput)
        result.diagnostics.push(
          `${input.path}: OSV exited with code ${output.exitCode}. See ${invocation.stderrPath}.`,
        );
      if (output.exitCode === 1 && result.matches.length === matchCount)
        result.diagnostics.push(
          `${input.path}: OSV reported findings but no advisory matches could be normalized.`,
        );
      if (result.diagnostics.length > diagnosticStart) {
        input.status = "failed";
        input.reason =
          "Scanner execution or matching was incomplete; inspect diagnostics and retained output.";
      }
    }
    try {
      const current = await discoverScaInputs(
        repository,
        environment,
        options.signal,
      );
      if (inputProvenance(current) !== capturedProvenance) {
        result.diagnostics.push(
          "Dependency inputs or OSV configuration changed while matching; recorded digests describe discovery. Rerun against stable inputs.",
        );
        for (const input of selected) {
          input.status = "failed";
          input.reason = "Dependency input provenance changed during matching.";
        }
      }
    } catch (error) {
      options.signal?.throwIfAborted();
      result.diagnostics.push(
        `Unable to verify dependency input provenance after matching: ${errorMessage(error)}`,
      );
    }
    if (scanner.exitCode === 128)
      result.diagnostics.push(
        "OSV found no packages in any selected effective input; this is not a clean-repository result.",
      );
    if (result.coverage.unresolvedPackages > 0)
      result.coverage.limitations.push(
        `${result.coverage.unresolvedPackages} package identities or dependency references lack an established package ecosystem and resolved version; their advisory coverage is incomplete.`,
      );
    const incomplete =
      result.diagnostics.length > 0 ||
      result.coverage.unresolvedPackages > 0 ||
      result.coverage.inputs.some(
        (input) => input.status === "unsupported" || input.status === "failed",
      );
    result.status = incomplete
      ? result.components.length > 0
        ? "partial"
        : "failed"
      : "completed";
    result.coverage.status =
      result.status === "completed" ? "complete" : result.status;
    await persistAggregate();
    return result;
  } catch (error) {
    if (error instanceof ScaInputDiscoveryError) {
      const { localReferences, diagnostics, ...coverage } = error.discovery;
      Object.assign(result.coverage, coverage);
      result.coverage.unresolvedPackages = localReferences.length;
      result.diagnostics.push(...diagnostics);
    }
    // A later process may fail or be cancelled after writing valid JSON. Preserve
    // those facts alongside every earlier invocation rather than overwriting them.
    if (pending !== null) {
      const retained = await readFile(pending.invocation.rawOutputPath, "utf8");
      const stderr = await readFile(pending.invocation.stderrPath, "utf8");
      if (!reconciledSources.has(pending.input.path) && retained.trim()) {
        try {
          consumeOutput(JSON.parse(retained), stderr, pending.input);
        } catch {
          // Truncated output remains available in this invocation's raw artifact.
        }
      }
      if (pending.invocation.exitCode === null) {
        scanner.exitCode = null;
        stderrOutputs.push(stderr);
      }
    }
    await persistAggregate();
    result.diagnostics.push(errorMessage(error));
    result.status = result.components.length > 0 ? "partial" : "failed";
    result.coverage.status = result.status;
    for (const input of result.coverage.inputs)
      if (
        input.status === "scanned" &&
        (!reconciledSources.has(input.path) || pending?.input === input)
      ) {
        input.status = "failed";
        input.reason = errorMessage(error);
      }
    if (options.signal?.aborted)
      throw Object.assign(new Error(errorMessage(error), { cause: error }), {
        osvResult: result,
      });
    return result;
  } finally {
    result.components.sort((a, b) => a.id.localeCompare(b.id));
    result.matches.sort((a, b) => a.id.localeCompare(b.id));
    scanner.completedAt = now();
  }
}
