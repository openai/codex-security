import { basename } from "node:path";
import { SaxesParser } from "saxes";
import { parse as parseToml } from "smol-toml";

import type { ScaInput } from "./sca-types.js";

export type AdditionalScaFormat = Exclude<ScaInput["format"], "npm" | "pnpm">;

export interface ScaUnresolvedReference {
  sourcePath: string;
  ecosystem: string;
  name: string;
  version: string | null;
  resolution: string;
  omittedCategory?: string;
}

export interface InputInspection {
  status: "scanned" | "unsupported";
  reason: string | null;
  references: ScaUnresolvedReference[];
  diagnostics: string[];
  limitations: string[];
}

const filenames = new Map<string, AdditionalScaFormat>([
  ["uv.lock", "uv"],
  ["poetry.lock", "poetry"],
  ["Pipfile.lock", "pipenv"],
  ["go.mod", "go"],
  ["Cargo.lock", "cargo"],
  ["pom.xml", "maven"],
  ["gradle.lockfile", "gradle"],
  ["buildscript-gradle.lockfile", "gradle"],
  ["Gemfile.lock", "bundler"],
  ["gems.locked", "bundler"],
  ["composer.lock", "composer"],
  ["packages.lock.json", "nuget"],
]);

export function additionalScaFormat(path: string): AdditionalScaFormat | null {
  const name = basename(path);
  const known = filenames.get(name);
  if (known) return known;
  if (name.endsWith(".txt") && name.includes("requirements"))
    return "requirements";
  if (name.endsWith(".pom")) return "maven";
  return null;
}

function inspection(): InputInspection {
  return {
    status: "scanned",
    reason: null,
    references: [],
    diagnostics: [],
    limitations: [],
  };
}

function unsupported(reason: string): InputInspection {
  return { ...inspection(), status: "unsupported", reason };
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

function addReference(
  result: InputInspection,
  sourcePath: string,
  ecosystem: string,
  name: string,
  version: string | null,
  resolution: string,
  omittedCategory?: string,
): void {
  const normalizedName =
    ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/gu, "-") : name;
  const previous = result.references.find(
    (reference) =>
      reference.sourcePath === sourcePath &&
      reference.ecosystem === ecosystem &&
      reference.name === normalizedName &&
      reference.version === version &&
      reference.omittedCategory === omittedCategory,
  );
  if (previous) return;
  result.references.push({
    sourcePath,
    ecosystem,
    name: normalizedName,
    version,
    resolution,
    ...(omittedCategory === undefined ? {} : { omittedCategory }),
  });
}

function packagesInToml(content: string): Record<string, unknown>[] {
  const parsed = parseToml(content);
  const packages = parsed["package"];
  if (!Array.isArray(packages) || !packages.every(record))
    throw new Error("Expected a package array in the lockfile.");
  return packages.map((pkg) => pkg as Record<string, unknown>);
}

function packageName(pkg: Record<string, unknown>): string {
  const name = text(pkg["name"]);
  if (name === null) throw new Error("A lockfile package has no name.");
  return name;
}

function isPublicPypiIndex(url: string | null): boolean {
  return (
    url !== null &&
    /^https?:\/\/pypi\.(?:org|python\.org)\/simple\/?$/u.test(url)
  );
}

function inspectPythonToml(
  content: string,
  format: "uv" | "poetry",
  sourcePath: string,
): InputInspection {
  const result = inspection();
  for (const pkg of packagesInToml(content)) {
    const name = packageName(pkg);
    const source = pkg["source"];
    if (!record(source)) continue;
    // SCALIBR omits uv's virtual root; it emits other local sources as PyPI.
    if (format === "uv" && source["virtual"] === ".") continue;
    let origin: string | null = null;
    if (format === "uv") {
      const registry = text(source["registry"]);
      if (registry !== null && !isPublicPypiIndex(registry))
        origin = `registry:${registry}`;
      for (const key of [
        "editable",
        "directory",
        "path",
        "url",
        "git",
        "virtual",
      ]) {
        const value = text(source[key]);
        if (value !== null) {
          origin = `${key}:${value}`;
          break;
        }
      }
    } else if (
      ["directory", "file", "url", "git"].includes(String(source["type"]))
    ) {
      origin = `${String(source["type"])}:${text(source["url"]) ?? ""}`;
    } else if (source["type"] === "legacy") {
      const registry = text(source["url"]);
      if (!isPublicPypiIndex(registry))
        origin = `registry:${registry ?? "unresolved"}`;
    }
    if (origin !== null)
      addReference(
        result,
        sourcePath,
        "PyPI",
        name,
        text(pkg["version"]),
        origin,
      );
  }
  return result;
}

function inspectPipenv(content: string, sourcePath: string): InputInspection {
  const parsed: unknown = JSON.parse(content);
  if (!record(parsed)) throw new Error("Expected a Pipfile.lock object.");
  const result = inspection();
  const metadata = parsed["_meta"];
  const sources =
    record(metadata) && Array.isArray(metadata["sources"])
      ? metadata["sources"].filter(record)
      : [];
  for (const [group, entries] of Object.entries(parsed)) {
    if (group === "_meta") continue;
    if (!record(entries))
      throw new Error("Expected a Pipfile.lock package group.");
    for (const [name, pkg] of Object.entries(entries)) {
      if (!record(pkg))
        throw new Error("Expected a Pipfile.lock package object.");
      const declaredVersion = text(pkg["version"]);
      const version = declaredVersion?.startsWith("==")
        ? text(declaredVersion.slice(2))
        : null;
      let origin = ["path", "file", "git", "hg", "svn", "bzr"]
        .map((key) =>
          text(pkg[key]) !== null ? `${key}:${String(pkg[key])}` : null,
        )
        .find((value) => value !== null);
      if (origin === undefined) {
        const index = text(pkg["index"]);
        const source =
          index === null
            ? sources[0]
            : sources.find((candidate) => candidate["name"] === index);
        const url = source === undefined ? null : text(source["url"]);
        if ((index !== null || source !== undefined) && !isPublicPypiIndex(url))
          origin = `index:${index ?? text(source?.["name"]) ?? "default"};url:${url ?? "unresolved"}`;
      }
      const omittedCategory =
        group !== "default" && group !== "develop" ? group : undefined;
      const groupResolution = `group:${group};version:${declaredVersion ?? "unresolved"}`;
      if (
        origin !== undefined ||
        version === null ||
        /[*,<>=~]/u.test(version) ||
        omittedCategory !== undefined
      )
        addReference(
          result,
          sourcePath,
          "PyPI",
          name,
          version,
          omittedCategory === undefined
            ? (origin ?? groupResolution)
            : `${groupResolution}${origin === undefined ? "" : `;${origin}`}`,
          omittedCategory,
        );
    }
  }
  return result;
}

function inspectCargo(content: string, sourcePath: string): InputInspection {
  const result = inspection();
  for (const pkg of packagesInToml(content)) {
    const name = packageName(pkg);
    const source = text(pkg["source"]);
    // The upstream extractor drops source identity, including alternate registries.
    if (source !== "registry+https://github.com/rust-lang/crates.io-index")
      addReference(
        result,
        sourcePath,
        "crates.io",
        name,
        text(pkg["version"]),
        source ?? "workspace-or-path",
      );
  }
  return result;
}

function inspectRequirements(
  content: string,
  sourcePath: string,
): InputInspection {
  const result = inspection();
  const lines = content
    .replace(/(^|\s)#.*$/gmu, "$1")
    .replace(/\\\r?\n/gu, " ")
    .split(/\r?\n/u);
  for (const line of lines) {
    const requirement =
      line
        .split(";", 1)[0]
        ?.replace(/\s+--hash=\S+/gu, "")
        .trim() ?? "";
    if (requirement === "") continue;
    // A requirements include is a filesystem read even with --no-resolve.
    // Ranges are also unsafe as resolved facts: upstream reports their boundary.
    if (
      requirement.includes("${") ||
      !/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?:\[[^\[\]]+\])?\s*(?:===|==)\s*[^\s*,<>=~;]+$/u.test(
        requirement,
      )
    )
      return unsupported(
        `${sourcePath} requires fully pinned requirements without file includes, local references, or version ranges.`,
      );
  }
  const limitation = `${sourcePath} supplies declared Python pins; transitive dependencies and environment markers are not resolved.`;
  result.limitations.push(limitation);
  result.diagnostics.push(limitation);
  return result;
}

function goVersionAtLeast117(value: string | null | undefined): boolean {
  const parsed = /^(\d+)\.(\d+)(?:\.\d+)?(?:(rc|beta)\d+)?$/u.exec(value ?? "");
  return (
    parsed !== null &&
    (Number(parsed[1]) > 1 ||
      (Number(parsed[1]) === 1 &&
        (Number(parsed[2]) > 17 ||
          (Number(parsed[2]) === 17 && parsed[3] === undefined))))
  );
}

function inspectGo(content: string, sourcePath: string): InputInspection {
  let goVersion: string | null = null;
  let toolchain: string | null = null;
  for (const line of content.split(/\r?\n/u)) {
    const directive = line.replace(/\/\/.*$/u, "").trim();
    const go = /^go\s+(\S+)$/u.exec(directive);
    const tool = /^toolchain\s+(\S+)$/u.exec(directive);
    if (go?.[1]) goVersion = go[1].replace(/^"|"$/gu, "");
    if (tool?.[1]) toolchain = tool[1].replace(/^"|"$/gu, "");
  }
  const effective =
    toolchain === null
      ? goVersion
      : (toolchain.startsWith("go") ? toolchain.slice(2) : toolchain).split(
          "-",
          1,
        )[0];
  if (!goVersionAtLeast117(effective))
    return unsupported(
      `${sourcePath} requires Go 1.17 or newer; older or unspecified versions do not provide the supported go.mod inventory and may read go.sum.`,
    );
  const result = inspection();
  // Toolchain precedence determines upstream's go.sum reads, but the original
  // go directive determines whether indirect requirements are comprehensive.
  if (!goVersionAtLeast117(goVersion)) {
    const limitation = `${sourcePath} does not declare Go 1.17 or newer; its declared requirements may omit transitive dependencies despite the selected toolchain.`;
    result.limitations.push(limitation);
    result.diagnostics.push(limitation);
  }
  if (/^\s*exclude\s/mu.test(content)) {
    const limitation = `${sourcePath} contains exclude directives that OSV does not apply to its declared module inventory.`;
    result.limitations.push(limitation);
    result.diagnostics.push(limitation);
  }
  // Applied local replaces have no version in upstream output, so the normalizer
  // already counts them as unresolved; unused replace directives change nothing.
  return result;
}

type MavenElement = {
  name: string;
  children: MavenElement[];
  text: string;
};

// saxes only parses the supplied string; it does not retrieve external entities.
function mavenElements(content: string): MavenElement | null {
  const roots: MavenElement[] = [];
  const stack: MavenElement[] = [];
  const parser = new SaxesParser({ xmlns: true });
  parser.on("opentag", (tag) => {
    const element: MavenElement = { name: tag.local, children: [], text: "" };
    const parent = stack[stack.length - 1];
    if (parent) parent.children.push(element);
    else roots.push(element);
    stack.push(element);
  });
  const appendText = (value: string) => {
    const current = stack[stack.length - 1];
    if (current) current.text += value;
  };
  parser.on("text", appendText);
  parser.on("cdata", appendText);
  parser.on("closetag", () => {
    stack.pop();
  });
  try {
    parser.write(content).close();
  } catch {
    return null;
  }
  const root = roots[0];
  return roots.length === 1 && root?.name === "project" ? root : null;
}

function inspectMaven(content: string, sourcePath: string): InputInspection {
  const project = mavenElements(content);
  if (!project) {
    return unsupported(
      "Maven XML uses unsupported syntax or is malformed; it was not passed to OSV.",
    );
  }
  // SCALIBR pomxml.go:128 passes project.Parent to MergeParents(AllowLocal:true)
  // even with --no-resolve. Unrelated plugin configuration is not a parent POM.
  if (project.children.some((node) => node.name === "parent"))
    return unsupported(
      "Maven parent POMs require additional inputs; this manifest was not passed to OSV.",
    );
  const nodes = [project];
  for (const node of nodes) {
    if (node.children.length > 0 && node.text.trim() !== "") {
      return unsupported("Maven XML contains unsupported mixed content.");
    }
    nodes.push(...node.children);
  }
  const dependencies = project.children.filter(
    (node) => node.name === "dependencies",
  );
  if (dependencies.length > 1)
    return unsupported("Maven has multiple dependency sections.");
  const direct = dependencies[0]?.children ?? [];
  if (direct.some((node) => node.name !== "dependency")) {
    return unsupported(
      "Maven dependency declarations use unsupported structure.",
    );
  }
  const result = inspection();
  if (
    nodes.some((node) => node.name === "dependency" && !direct.includes(node))
  )
    result.limitations.push(
      "Maven dependencies outside the direct dependency section are not fully inventoried by this scan.",
    );
  const names = new Set<string>();
  for (const dependency of direct) {
    const field = (name: string): string | null => {
      const found = dependency.children.filter((node) => node.name === name);
      const first = found[0];
      if (found.length !== 1 || !first || first.children.length > 0)
        return null;
      return first.text.trim() || null;
    };
    const group = field("groupId");
    const artifact = field("artifactId");
    const version = field("version");
    // pomxml.go:53 reduces ranges to their first endpoint. Do not present that
    // endpoint as a resolved installation version.
    if (
      !group ||
      !artifact ||
      !version ||
      [group, artifact, version].some((value) => value.includes("${")) ||
      /[\s:]/.test(group) ||
      /[\s:]/.test(artifact) ||
      /[\s\[\](),*]/.test(version) ||
      /^(?:LATEST|RELEASE)$/i.test(version)
    ) {
      return unsupported(
        "Maven direct dependencies must have explicit names and exact versions; unresolved declarations were not passed to OSV.",
      );
    }
    const name = `${group}:${artifact}`;
    if (names.has(name)) {
      return unsupported(
        "Maven repeats a dependency identity that OSV would collapse.",
      );
    }
    names.add(name);
    const systemPath = field("systemPath");
    if (systemPath || field("scope") === "system") {
      addReference(
        result,
        sourcePath,
        "Maven",
        name,
        version,
        systemPath ?? "system dependency",
      );
      result.limitations.push(
        "Maven system dependencies refer to local artifacts whose contents were not identified.",
      );
    }
  }
  const limitation =
    "Maven POMs describe direct dependency declarations; transitive dependencies and the resolved build graph were not inspected with --no-resolve.";
  result.limitations.push(limitation);
  result.diagnostics.push(limitation);
  return result;
}

function inspectGradle(content: string, _sourcePath: string): InputInspection {
  const result = inspection();
  for (const [index, raw] of content.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("empty=")) continue;
    // gradlelockfile.go:51-71 parses group:artifact:version=configurations;
    // :110-112 silently skips malformed rows.
    if (!/^[^\s:=]+:[^\s:=]+:[^\s:=]+=[^=]*$/.test(line)) {
      return unsupported(
        `Gradle lockfile line ${index + 1} cannot be inventoried; OSV would omit malformed rows.`,
      );
    }
  }
  return result;
}

function inspectBundler(content: string, sourcePath: string): InputInspection {
  // The pinned gemfilelock extractor omits scanner.Err() after its Scan loop,
  // so bufio.Scanner's 64 KiB token ceiling can silently truncate its inventory.
  if (
    content
      .split("\n")
      .some((line) => Buffer.byteLength(line, "utf8") >= 64 * 1024)
  )
    return unsupported(
      "Bundler lockfile exceeds OSV's 64 KiB line token size; its extractor would silently truncate the inventory.",
    );
  const result = inspection();
  const sourceNames = new Set(["GEM", "GIT", "PATH", "PLUGIN SOURCE"]);
  const knownNames = new Set([
    ...sourceNames,
    "PLATFORMS",
    "DEPENDENCIES",
    "RUBY VERSION",
    "BUNDLED WITH",
    "CHECKSUMS",
  ]);
  let section = "";
  let remotes: string[] = [];
  let revision = "";
  let specs: { name: string; version: string }[] = [];
  let sourceSeen = false;
  const finishSection = () => {
    if (!sourceNames.has(section)) return;
    // The pinned extractor drops GEM remotes and always emits RubyGems identities.
    if (
      section === "GEM" &&
      remotes.length > 0 &&
      remotes.every((remote) => /^https?:\/\/rubygems\.org\/?$/i.test(remote))
    )
      return;
    const resolution = `${section.toLowerCase()}:${remotes.join(",")}${revision ? `#${revision}` : ""}`;
    for (const spec of specs) {
      addReference(
        result,
        sourcePath,
        "RubyGems",
        spec.name,
        spec.version,
        resolution,
      );
    }
  };
  for (const [index, line] of content.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    if (!line.startsWith(" ")) {
      if (!knownNames.has(line))
        return unsupported(
          `Bundler lockfile section at line ${index + 1} is unsupported.`,
        );
      finishSection();
      section = line;
      remotes = [];
      revision = "";
      specs = [];
      if (sourceNames.has(section)) sourceSeen = true;
      continue;
    }
    if (!section)
      return unsupported(
        "Bundler lockfile contains entries before its first section.",
      );
    if (!sourceNames.has(section)) continue;
    if (line.startsWith("  remote: ")) remotes.push(line.slice(10));
    if (line.startsWith("  revision: ")) revision = line.slice(12);
    if (!/^ {4}[^ ]/.test(line)) continue;
    // Same spec/version extraction as gemfilelock.go:45 and :140-157, including
    // stripping the platform suffix after the first hyphen.
    const spec = /^(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$/.exec(line.slice(4));
    const name = spec?.[1];
    const version = spec?.[2];
    if (!name || !version) {
      return unsupported(
        `Bundler spec at line ${index + 1} is invalid; OSV would omit it.`,
      );
    }
    specs.push({ name, version });
  }
  finishSection();
  if (!sourceSeen)
    return unsupported(
      "Bundler lockfile has no recognized package source section.",
    );
  if (result.references.length > 0) {
    result.limitations.push(
      "Bundler custom registries and local, Git, or plugin sources are reported by OSV as RubyGems versions; their source contents were not matched.",
    );
  }
  return result;
}

function localDistribution(value: unknown): string | null {
  if (typeof value !== "string" || value === "") return null;
  if (value.startsWith("//")) return null;
  if (/^(?:file:|\.{1,2}[/\\]|[/\\]|[A-Za-z]:[/\\])/.test(value)) return value;
  // Bare relative archives are local too; URLs and scp-style Git remotes are not.
  return /^(?:[A-Za-z][A-Za-z0-9+.-]*:|[^/\\]+@[^/\\]+:)/.test(value)
    ? null
    : value;
}

function inspectComposer(content: string, sourcePath: string): InputInspection {
  const lock: unknown = JSON.parse(content);
  if (
    !record(lock) ||
    (!Array.isArray(lock["packages"]) && !Array.isArray(lock["packages-dev"]))
  ) {
    return unsupported("Composer lockfile has no package arrays.");
  }
  const result = inspection();
  for (const key of ["packages", "packages-dev"]) {
    const packages = lock[key];
    if (packages === undefined) continue;
    if (!Array.isArray(packages))
      return unsupported("Composer package inventory is malformed.");
    for (const value of packages) {
      if (
        !record(value) ||
        typeof value["name"] !== "string" ||
        !value["name"] ||
        typeof value["version"] !== "string" ||
        !value["version"]
      ) {
        return unsupported(
          "Composer package entries require a name and version.",
        );
      }
      // composerlock.go:43 retains only name/version/dist.reference. Source-only
      // Git packages lose their origin; archives may also include Git metadata.
      for (const originKey of ["dist", "source"]) {
        const origin = value[originKey];
        if (!record(origin)) continue;
        const local = localDistribution(origin["url"]);
        const sourceOnlyGit =
          originKey === "source" &&
          origin["type"] === "git" &&
          !record(value["dist"]);
        if (origin["type"] === "path" || local || sourceOnlyGit) {
          const resolution =
            typeof origin["url"] === "string" && origin["url"]
              ? origin["url"]
              : `${originKey}:${origin["type"]}`;
          addReference(
            result,
            sourcePath,
            "Packagist",
            value["name"],
            value["version"],
            resolution,
          );
        }
      }
      if (/^(?:dev-)|(?:\.x)?-dev$/i.test(value["version"])) {
        addReference(
          result,
          sourcePath,
          "Packagist",
          value["name"],
          value["version"],
          `development version:${value["version"]}`,
        );
      }
    }
  }
  if (result.references.length > 0) {
    result.limitations.push(
      "Composer local sources, source-only Git packages, or development branches do not establish the contents of a published package release.",
    );
  }
  return result;
}

function inspectNuget(content: string, sourcePath: string): InputInspection {
  const lock: unknown = JSON.parse(content);
  if (!record(lock) || !record(lock["dependencies"])) {
    return unsupported("NuGet lockfile has no dependency map.");
  }
  const result = inspection();
  for (const [framework, dependencies] of Object.entries(
    lock["dependencies"],
  )) {
    if (!record(dependencies))
      return unsupported(
        "NuGet target-framework dependency inventory is malformed.",
      );
    for (const [name, value] of Object.entries(dependencies)) {
      if (!name || !record(value))
        return unsupported("NuGet dependency entry is malformed.");
      const version =
        typeof value["resolved"] === "string" && value["resolved"]
          ? value["resolved"]
          : null;
      // packageslockjson.go:76 does not retain type; :145-153 emits every entry's
      // resolved value, including an empty value for project references.
      if (value["type"] === "Project" || !version) {
        addReference(
          result,
          sourcePath,
          "NuGet",
          name,
          version,
          `${value["type"] === "Project" ? "project" : "unresolved"}:${framework}`,
        );
      } else if (/[\s\[\](),*]/.test(version)) {
        return unsupported(
          "NuGet resolved entries must contain exact versions.",
        );
      }
    }
  }
  if (result.references.length > 0) {
    result.limitations.push(
      "NuGet project references or dependencies without resolved versions were not identified as installed package releases.",
    );
  }
  return result;
}

/** Inspect only facts the pinned extractor drops or interprets as unresolved. */
export function inspectAdditionalScaInput(
  content: string,
  format: AdditionalScaFormat,
  sourcePath: string,
): InputInspection {
  try {
    switch (format) {
      case "uv":
      case "poetry":
        return inspectPythonToml(content, format, sourcePath);
      case "pipenv":
        return inspectPipenv(content, sourcePath);
      case "cargo":
        return inspectCargo(content, sourcePath);
      case "requirements":
        return inspectRequirements(content, sourcePath);
      case "go":
        return inspectGo(content, sourcePath);
      case "maven":
        return inspectMaven(content, sourcePath);
      case "gradle":
        return inspectGradle(content, sourcePath);
      case "bundler":
        return inspectBundler(content, sourcePath);
      case "composer":
        return inspectComposer(content, sourcePath);
      case "nuget":
        return inspectNuget(content, sourcePath);
    }
  } catch (error) {
    return unsupported(
      `Could not inspect ${sourcePath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
