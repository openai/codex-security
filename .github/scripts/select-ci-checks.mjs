import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const documentation =
  /^(?:README\.md|CONTRIBUTING\.md|CODE_OF_CONDUCT\.md|docs\/.*\.md|github-action\/README\.md|docker\/README\.md)$/;
const ordinarySource =
  /^(?:sdk\/typescript\/(?:src|tests-ts)|plugins\/codex-security\/mcp-app\/(?:src|tests))\/.*\.ts$/;

export function selectChecks(paths, { event, baseChanged = false }) {
  // Only known documentation and TypeScript source paths can narrow qualification.
  const full =
    event !== "pull_request" ||
    baseChanged ||
    paths.length === 0 ||
    paths.some(
      (path) => !documentation.test(path) && !ordinarySource.test(path),
    );
  const source = full || !paths.every((path) => documentation.test(path));
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
    "workflow-quality": String(full),
    "container-validate": String(source),
    "compatibility-matrix": JSON.stringify({ include: compatibility }),
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
