import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, relative } from "node:path";
import { isRecord } from "./record.js";
import { parseNodeLockfiles, scaInputBasename } from "./sca-inputs.js";
import { relativePathIsOutside } from "./targets.js";
import type { ScaPackageContext, ScaResult } from "./sca-types.js";

interface Package {
  path: string;
  name: string;
  version: string;
  manifest: Record<string, unknown>;
}

const dependencyFields = [
  ["dependencies", "runtime"],
  ["optionalDependencies", "optional"],
  ["devDependencies", "dev"],
  ["peerDependencies", "runtime"],
] as const;

async function readLocalFile(path: string, repository: string) {
  const canonical = await realpath(path);
  if (relativePathIsOutside(relative(repository, canonical))) return null;
  if (!(await stat(canonical)).isFile()) return null;
  return readFile(canonical, "utf8");
}

async function readPackage(
  path: string,
  repository: string,
  project = false,
): Promise<Package | null> {
  try {
    const directory = await realpath(path);
    if (relativePathIsOutside(relative(repository, directory))) return null;
    const content = await readLocalFile(
      join(directory, "package.json"),
      repository,
    );
    if (content === null) return null;
    const manifest: unknown = JSON.parse(content);
    if (
      !isRecord(manifest) ||
      (!project && typeof manifest["name"] !== "string")
    )
      return null;
    return {
      path: directory,
      name:
        typeof manifest["name"] === "string"
          ? manifest["name"]
          : basename(path),
      version:
        typeof manifest["version"] === "string"
          ? manifest["version"]
          : "unknown",
      manifest,
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (
      ["ENOENT", "ENOTDIR", "EISDIR", "ELOOP", "EACCES", "EPERM"].includes(
        code ?? "",
      ) ||
      error instanceof SyntaxError
    )
      return null;
    throw error;
  }
}

async function resolvePackage(
  from: string,
  name: string,
  repository: string,
): Promise<Package | null> {
  let directory = from;
  while (!relativePathIsOutside(relative(repository, directory))) {
    const modules = join(directory, "node_modules");
    const candidate = join(modules, name);
    if (relativePathIsOutside(relative(modules, candidate))) return null;
    try {
      await lstat(candidate);
      // A nearer installed package shadows hoisted copies even when its
      // manifest cannot be inspected within this repository.
      return await readPackage(candidate, repository);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EACCES" || code === "EPERM" || code === "ELOOP")
        return null;
      if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
    }
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return null;
}

async function workspacePaths(
  file: string,
  repository: string,
): Promise<string[]> {
  try {
    const path = join(repository, file);
    const content = await readLocalFile(path, repository);
    if (content === null) return [];
    const pnpm = scaInputBasename(file) === "pnpm-lock.yaml";
    return parseNodeLockfiles(content, pnpm).flatMap((lock) => {
      if (!isRecord(lock)) return [];
      const projects = lock[pnpm ? "importers" : "packages"];
      if (!isRecord(projects)) return [];
      return Object.entries(projects)
        .filter(
          ([path, value]) =>
            isRecord(value) && !path.split(/[\\/]/u).includes("node_modules"),
        )
        .map(([member]) => join(dirname(path), member));
    });
  } catch {
    // Optional workspace metadata can be absent or unreadable independently of installed source.
    return [];
  }
}

/** Resolve installed npm evidence without importing code, installing, or using the network. */
export async function dependencyPackageContexts(
  result: ScaResult,
  signal?: AbortSignal,
): Promise<ScaPackageContext[]> {
  const repository = result.repository.path;
  const matched = new Set(result.matches.map((match) => match.componentId));
  const contexts = result.components
    .filter((component) => matched.has(component.id))
    .map((component) => {
      const context: ScaPackageContext = {
        componentId: component.id,
        manifestPath: null,
        projectName: null,
        private: null,
        installedPath: null,
        dependencyChain: [],
        dependencyGroups: [...component.dependencyGroups],
        limitations: [],
      };
      return { component, context };
    });
  function setProject(context: ScaPackageContext, project: Package): void {
    context.manifestPath = relative(
      repository,
      join(project.path, "package.json"),
    );
    context.projectName =
      typeof project.manifest["name"] === "string" ? project.name : null;
    context.private = project.manifest["private"] === true;
  }
  const byFile = Map.groupBy(
    contexts.filter(({ component }) => component.ecosystem === "npm"),
    ({ component }) => component.sourcePath,
  );
  for (const [file, selected] of byFile) {
    signal?.throwIfAborted();
    const projectDirectory = dirname(join(repository, file));
    const projects: Package[] = [];
    const projectPaths = new Set([
      projectDirectory,
      ...(await workspacePaths(file, repository)),
    ]);
    for (const path of projectPaths) {
      signal?.throwIfAborted();
      const candidate = await readPackage(path, repository, true);
      if (candidate !== null) projects.push(candidate);
    }
    if (projectPaths.size === 1 && projects[0])
      for (const { context } of selected) setProject(context, projects[0]);
    const queue: {
      pkg: Package;
      project: Package;
      chain: ScaPackageContext["dependencyChain"];
      group: string | null;
    }[] = projects.map((project) => ({
      pkg: project,
      project,
      chain: [],
      group: null,
    }));
    const visited = new Set<string>();
    const visitedProjects = new Set<string>();
    for (let index = 0; index < queue.length; index++) {
      signal?.throwIfAborted();
      const { pkg, project, chain, group } = queue[index]!;
      const seen = chain.length === 0 ? visitedProjects : visited;
      if (seen.has(pkg.path)) continue;
      seen.add(pkg.path);
      const current = [
        ...chain,
        {
          name: pkg.name,
          version: pkg.version,
          path: relative(repository, pkg.path) || ".",
        },
      ];
      for (const { component, context } of selected) {
        if (
          group !== null &&
          context.installedPath === null &&
          component.name === pkg.name &&
          component.version === pkg.version
        ) {
          context.installedPath = relative(repository, pkg.path);
          setProject(context, project);
          context.dependencyChain = current;
          context.dependencyGroups = [
            ...new Set([...context.dependencyGroups, group]),
          ];
        }
      }
      if (selected.every(({ context }) => context.installedPath !== null))
        break;
      for (const [field, fieldGroup] of dependencyFields) {
        if (group !== null && fieldGroup === "dev") continue;
        const dependencies = pkg.manifest[field];
        if (!isRecord(dependencies)) continue;
        for (const name of Object.keys(dependencies)) {
          const dependency = await resolvePackage(pkg.path, name, repository);
          if (dependency !== null && !visited.has(dependency.path))
            queue.push({
              pkg: dependency,
              project,
              chain: current,
              group: group ?? fieldGroup,
            });
        }
      }
    }
  }
  for (const { component, context } of contexts) {
    context.limitations.push(
      context.installedPath === null
        ? "No matching installed source was resolved automatically; use the dependency file and inspect available source before concluding it is unavailable."
        : "This is one observed local dependency chain, not a complete graph or evidence of deployment or attacker reachability.",
    );
    if (component.ecosystem !== "npm")
      context.limitations.push(
        "Automatic installed-source resolution currently supports npm and pnpm projects.",
      );
  }
  return contexts.map(({ context }) => context);
}
