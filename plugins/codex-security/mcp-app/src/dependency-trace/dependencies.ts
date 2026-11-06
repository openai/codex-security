import { basename } from "node:path";
import { isRecord } from "../record.ts";
import type { TraceEntity, TraceEvidence } from "./types.ts";

const manifestNames = ["package.json", "Dockerfile", "Containerfile"];
export const dependencyManifestGlob = `{${manifestNames.join(",")}}`;
const dependencyMaps = [
  "dependencies",
  "optionalDependencies",
  "peerDependencies",
  "devDependencies",
];

export function isDependencyManifest(file: string): boolean {
  return manifestNames.includes(basename(file));
}

function dependsOn(
  from: TraceEntity,
  packageName: string,
  source: string,
  line: number,
): TraceEvidence {
  return {
    source,
    line,
    step: {
      from,
      relation: "depends_on",
      to: { kind: "package", name: packageName, scope: from.scope ?? source },
    },
  };
}

// JSON.parse has already verified the declaration. Locate its key without
// mistaking a similarly named script, nested key, or quoted text for it.
function declarationLine(contents: string, map: string, packageName: string) {
  const tokens = /"(?:[^"\\]|\\.)*"(?:\s*:)?|[{}[\]]/gu;
  let depth = 0;
  let inMap = false;
  let offset: number | undefined;
  for (const { 0: token, index } of contents.matchAll(tokens)) {
    if (token === "{" || token === "[") depth++;
    else if (token === "}" || token === "]") depth--;
    else if (depth <= 2 && token.endsWith(":")) {
      const key: string = JSON.parse(token.slice(0, -1));
      if (depth === 1) {
        inMap = key === map;
        // Like JSON.parse, take the last value for a duplicate key.
        if (inMap) offset = undefined;
      } else if (inMap && key === packageName) {
        offset = index;
      }
    }
  }
  return offset === undefined
    ? undefined
    : contents.slice(0, offset).split("\n").length;
}

function npmDeclaration(
  contents: string,
  file: string,
  packageName: string,
): TraceEvidence[] {
  let manifest: unknown;
  try {
    manifest = JSON.parse(contents);
  } catch {
    return [];
  }
  if (!isRecord(manifest)) return [];
  for (const name of dependencyMaps) {
    const map = manifest[name];
    if (!isRecord(map) || !Object.hasOwn(map, packageName)) continue;
    const request = map[packageName];
    // Aliases, paths, tarballs and URLs can name a different package.
    if (
      typeof request !== "string" ||
      /[:/\\]|^\.{1,2}$|\.(?:tgz|tar(?:\.gz)?)$/iu.test(request.trim())
    )
      continue;
    const line = declarationLine(contents, name, packageName);
    if (line !== undefined)
      return [dependsOn({ kind: "file", name: file }, packageName, file, line)];
  }
  return [];
}

// Only recognize a shell-form RUN with a literal package list. Options with
// operands, substitutions and shell control flow need a different analysis.
function installsPackage(command: string[], packageName: string) {
  const [manager, action, ...operands] = command;
  const apt = manager === "apt-get" && action === "install";
  const apk = manager === "apk" && action === "add";
  if (!apt && !apk) return false;
  if (operands[0] === (apt ? "-y" : "--no-cache")) operands.shift();
  return (
    operands.includes(packageName) &&
    operands.every((name) => /^[a-z0-9]+(?:[.+_-][a-z0-9]+)*$/u.test(name))
  );
}

function buildDeclarations(
  contents: string,
  file: string,
  packageName: string,
): TraceEvidence[] {
  const evidence: TraceEvidence[] = [];
  let stage: TraceEntity | undefined;
  for (const [index, raw] of contents.split("\n").entries()) {
    const line = raw.trim();
    // Alternate frontends, escape characters, continued instructions and
    // heredoc bodies can change which physical lines are instructions.
    if (/^#\s*syntax\s*=\s*docker\/dockerfile:1(?:\.\d+){0,2}$/iu.test(line))
      continue;
    if (/^#\s*(?:syntax|escape)\s*=/iu.test(line)) break;
    if (!line || line.startsWith("#")) continue;
    if (line.includes("<<") || line.endsWith("\\") || /^SHELL\b/iu.test(line))
      break;
    const [word, ...args] = line.split(/[ \t]+/u);
    const instruction = word.toUpperCase();
    if (instruction === "FROM") {
      const from =
        /^FROM[ \t]+[a-z0-9][a-z0-9._:/@-]*(?:[ \t]+AS[ \t]+([a-z][a-z0-9._-]*))?$/iu.exec(
          line,
        );
      stage = from
        ? {
            kind: "build",
            name: from[1] ? `stage ${from[1]}` : `stage at line ${index + 1}`,
            scope: `${file}#FROM line ${index + 1}`,
          }
        : undefined;
    } else if (instruction === "RUN") {
      if (stage && installsPackage(args, packageName)) {
        evidence.push(dependsOn(stage, packageName, file, index + 1));
        // Repeated installs in a stage declare the same dependency.
        stage = undefined;
      }
    } else if (
      !/^(?:ADD|ARG|CMD|COPY|ENTRYPOINT|ENV|EXPOSE|HEALTHCHECK|LABEL|MAINTAINER|ONBUILD|STOPSIGNAL|USER|VOLUME|WORKDIR)$/u.test(
        instruction,
      )
    ) {
      // For example, do not treat a recipe embedded in Markdown as a build.
      break;
    }
  }
  return evidence;
}

export function dependencyEvidence(
  contents: string,
  file: string,
  packageName: string,
): TraceEvidence[] {
  if (!isDependencyManifest(file)) return [];
  return basename(file) === "package.json"
    ? npmDeclaration(contents, file, packageName)
    : buildDeclarations(contents, file, packageName);
}
