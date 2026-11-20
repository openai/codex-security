import { posix } from "node:path";
import { satisfies, valid, validRange } from "semver";
import { isScalar, LineCounter, parseDocument } from "yaml";
import { isRecord } from "./record.js";

export interface DependencyManifest {
  path: string;
  project: string;
  name?: string;
  requested: string;
  declaration?: string;
  line: number;
  selection?: {
    kind: "npm-lock" | "requirements-pin";
    version: string;
    lockfile: string;
    packagePath: string;
    line: number;
  };
}

const sections = [
  "optionalDependencies",
  "dependencies",
  "peerDependencies",
  "devDependencies",
] as const;

function jsonSource(text: string) {
  const value: unknown = JSON.parse(text);
  if (!isRecord(value)) throw new Error("Expected a JSON object");
  const lines = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lines, schema: "json" });
  if (doc.errors.length) throw doc.errors[0];
  return {
    value,
    line(keys: string[]) {
      const node = doc.getIn(keys, true);
      if (!isScalar(node) || !node.range) return undefined;
      return lines.linePos(node.range[0]).line;
    },
  };
}

function* ancestors(directory: string) {
  for (;;) {
    yield directory;
    if (directory === ".") return;
    directory = posix.dirname(directory);
  }
}

/** Resolve npm's installed path in the nearest v2/v3 lock, relative to the requesting project. */
export async function readNpmManifests(
  paths: ReadonlySet<string>,
  candidates: string[],
  name: string,
  read: (path: string) => Promise<string>,
  gaps: string[],
): Promise<DependencyManifest[]> {
  const result: DependencyManifest[] = [];
  const cache = new Map<string, ReturnType<typeof jsonSource>>();
  async function json(path: string) {
    let source = cache.get(path);
    if (!source) {
      source = jsonSource(await read(path));
      cache.set(path, source);
    }
    return source;
  }
  for (const path of candidates) {
    const project = posix.dirname(path);
    let reading = path;
    try {
      const manifest = await json(path);
      const section = sections.find((key) => {
        const deps = manifest.value[key];
        return isRecord(deps) && Object.hasOwn(deps, name);
      });
      if (!section) continue;
      const requested = (manifest.value[section] as Record<string, unknown>)[
        name
      ];
      const line = manifest.line([section, name]);
      if (typeof requested !== "string" || !line) {
        gaps.push(`Unrecognized dependency declaration in ${path}.`);
        continue;
      }
      const item: DependencyManifest = {
        path,
        project,
        requested,
        declaration: section,
        line,
        ...(typeof manifest.value["name"] === "string" && {
          name: manifest.value["name"],
        }),
      };
      result.push(item);
      // A file, Git or alias specification can refer to a different package.
      const range = validRange(requested);
      if (!range && !/^[A-Za-z][A-Za-z0-9_-]*$/u.test(requested)) continue;
      for (const parent of ancestors(project)) {
        const lock = ["npm-shrinkwrap.json", "package-lock.json"]
          .map((base) => posix.join(parent, base))
          .find((candidate) => paths.has(candidate));
        if (!lock) {
          if (
            ["pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"].some(
              (base) => paths.has(posix.join(parent, base)),
            )
          )
            break;
          continue;
        }
        reading = lock;
        const source = await json(lock);
        const entries = source.value["packages"];
        const relative = posix.relative(parent, project);
        if (
          !isRecord(entries) ||
          (source.value["lockfileVersion"] !== 2 &&
            source.value["lockfileVersion"] !== 3)
        )
          break;
        const requester = entries[relative];
        // A root workspace lock must actually describe this manifest's request.
        if (
          !isRecord(requester) ||
          !sections.some((key) => {
            const declarations = requester[key];
            return isRecord(declarations) && declarations[name] === requested;
          })
        )
          break;
        for (const directory of ancestors(relative || ".")) {
          const installed = posix.join(directory, "node_modules", name);
          const entry = entries[installed];
          if (!isRecord(entry)) continue;
          const version = entry["version"];
          const versionLine = source.line(["packages", installed, "version"]);
          if (
            typeof version === "string" &&
            valid(version) &&
            (!range || satisfies(version, range)) &&
            versionLine &&
            !entry["link"] &&
            (!entry["name"] || entry["name"] === name)
          ) {
            item.selection = {
              kind: "npm-lock",
              version,
              lockfile: lock,
              packagePath: installed,
              line: versionLine,
            };
          }
          break;
        }
        break;
      }
    } catch (error) {
      if (
        !(error instanceof SyntaxError) &&
        !(
          error instanceof Error &&
          (error.name === "YAMLParseError" ||
            error.message === "Expected a JSON object")
        )
      )
        throw error;
      gaps.push(`Could not parse the manifest or lockfile at ${reading}.`);
    }
  }
  for (const manifest of result) {
    if (!manifest.selection)
      gaps.push(
        `The installed copy selected by ${manifest.path} was not established from a lockfile.`,
      );
  }
  return result;
}

export function pythonDistributionName(name: string) {
  return name.replace(/[-_.]+/gu, "-").toLowerCase();
}

/** A literal pip requirement is a configured selection. Environment markers and includes remain open. */
export async function readPythonRequirements(
  paths: string[],
  name: string,
  read: (path: string) => Promise<string>,
  gaps: string[],
): Promise<DependencyManifest[]> {
  const result: DependencyManifest[] = [];
  for (const path of paths.filter((p) =>
    /^requirements[^/]*\.(?:txt|lock|in)$/iu.test(posix.basename(p)),
  )) {
    const lines = (await read(path))
      .split(/\r?\n/u)
      .map((line) => line.replace(/(?:^|\s+)#.*$/u, "").trim());
    const matches = lines.flatMap((line, index) => {
      const match = /^([A-Za-z0-9][A-Za-z0-9_.-]*)(.*)$/u.exec(line);
      return match &&
        pythonDistributionName(match[1]!) === pythonDistributionName(name)
        ? [{ requested: match[2]!.trim(), line: index + 1 }]
        : [];
    });
    if (!matches.length) continue;
    const input = matches[0]!;
    const version =
      /^==\s*([0-9]+(?:[.!][0-9]+)*(?:(?:a|b|rc|\.post|\.dev)[0-9]+)*(?:\+[a-z0-9]+(?:[.-][a-z0-9]+)*)?)(?:\s+--hash=[A-Za-z0-9]+:[a-fA-F0-9]+)*$/iu.exec(
        input.requested,
      )?.[1];
    const unconditional =
      matches.length === 1 &&
      !lines.some((line) =>
        /^(?:-r|-c|--requirement|--constraint)(?:\s|=|[^-])/u.test(line),
      );
    const project = posix.dirname(path);
    const manifest: DependencyManifest = { ...input, path, project };
    if (version && unconditional) {
      manifest.selection = {
        kind: "requirements-pin",
        version,
        lockfile: path,
        packagePath: name,
        line: input.line,
      };
    } else
      gaps.push(
        `The active version from ${path} depends on unresolved requirements or installation conditions.`,
      );
    result.push(manifest);
  }
  return result;
}
