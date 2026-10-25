import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const documentation =
  /^(?:README\.md|CONTRIBUTING\.md|CODE_OF_CONDUCT\.md|docs\/.*\.md|github-action\/README\.md|docker\/README\.md)$/;
const ordinarySource =
  /^(?:sdk\/typescript\/(?:src|tests-ts)|plugins\/codex-security\/mcp-app\/(?:src|tests))\/.*\.ts$/;
const actionFiles =
  /^(?:action\.yml|github-action\/(?:README\.md|(?:runtime\/)?package(?:-lock)?\.json|dist\/(?:index|post)\.cjs|(?:src|scripts|tests)\/[^/]+\.(?:mjs|ts)))$/;
const evalFiles =
  /^evals\/(?:standard-time-budget\/(?:[^/]+\.mts|experiment\.json|README\.md)|triage-finding\/(?:package\.json|pnpm-lock\.yaml|README\.md|(?:assertions|scripts)\/[^/]+\.mts))$/;

function scopeFor(paths, event, baseChanged) {
  if (event !== "pull_request" || baseChanged || !paths.length) return "full";
  if (paths.every((path) => documentation.test(path))) return "docs";
  if (paths.every((path) => actionFiles.test(path))) return "action";
  if (paths.every((path) => evalFiles.test(path))) return "evals";
  if (
    paths.every((path) => ordinarySource.test(path) || documentation.test(path))
  )
    return "source";
  return "full";
}

export function selectChecks(paths, { event, baseChanged = false }) {
  const scope = scopeFor(paths, event, baseChanged);
  const full = scope === "full";
  const source = full || scope === "source";
  const action =
    full ||
    scope === "action" ||
    paths.some(
      (path) =>
        path === "github-action/README.md" ||
        path === "sdk/typescript/src/git-remote.ts",
    );
  const compatibility = ["22.13.0", "24.0.0", "24", "26.0.0", "26"]
    .filter((version) => full || version !== "26")
    .map((version) => ({ os: "ubuntu-latest", node: version }));
  compatibility.push({ os: "macos-latest", node: "22.13.0" });
  const pythonMatrix = [
    ...["3.10", "3.12", "3.14"]
      .filter((version) => full || version === "3.12")
      .map((version) => ({
        os: "ubuntu-latest",
        python: version,
        markers: "",
      })),
    {
      os: "macos-latest",
      python: "3.12",
      markers: "cross_platform or native_macos",
    },
    {
      os: "windows-latest",
      python: "3.12",
      markers: "cross_platform or native_windows",
    },
  ];
  return {
    "source-required": String(source),
    "package-required": String(source || scope === "action"),
    "action-ci": String(action),
    "eval-contracts": String(source || scope === "evals"),
    "workflow-quality": String(full),
    "container-validate": String(source),
    "compatibility-matrix": JSON.stringify({
      include:
        scope === "action"
          ? [{ os: "ubuntu-latest", node: "24" }]
          : compatibility,
    }),
    "python-matrix": JSON.stringify({ include: pythonMatrix }),
    "windows-node-matrix": JSON.stringify({
      node: full ? ["22.13.0", "24"] : ["22.13.0"],
    }),
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const event = process.env.EVENT_NAME;
  const baseChanged = process.env.BASE_CHANGED === "true";
  if (event === "pull_request" && baseChanged) {
    const { base, head } = JSON.parse(
      readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"),
    ).pull_request;
    const parents = execFileSync("git", ["show", "-s", "--format=%P", "HEAD"], {
      encoding: "utf8",
    }).trim();
    const expected = `${base.sha} ${head.sha}`;
    console.log(
      `Requested base ${base.ref}. Expected merge parents ${expected}. Checked out ${parents}.`,
    );
    if (parents !== expected) {
      throw new Error(
        "GitHub supplied a stale test merge. After the merge ref updates, reopen the pull request to start a fresh source run. Rerunning this attempt uses the same commit.",
      );
    }
  }
  const paths =
    event === "pull_request" && !baseChanged
      ? execFileSync(
          "git",
          ["diff", "--no-renames", "--name-only", "-z", "HEAD^1", "HEAD"],
          { encoding: "utf8" },
        )
          .split("\0")
          .filter(Boolean)
      : [];
  const selected = selectChecks(paths, { event, baseChanged });
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    Object.entries(selected)
      .map(([key, value]) => `${key}=${value}\n`)
      .join(""),
  );
}
