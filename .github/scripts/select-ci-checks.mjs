import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const documentation =
  /^(?:README\.md|CONTRIBUTING\.md|RELEASING\.md|CODE_OF_CONDUCT\.md|docs\/.*\.md|sdk\/typescript\/(?:README\.md|docs\/.*\.md)|github-action\/README\.md|docker\/README\.md)$/;
const infrastructure =
  /^\.github\/(?:workflows\/|actions\/|scripts\/|actionlint\.yaml$|zizmor\.yml$)/;
const nodeInputs =
  /(?:^|\/)(?:package\.json|pnpm-lock\.yaml|package-lock\.json|bunfig\.toml|tsconfig[^/]*\.json)$|^plugins\/codex-security\/native\/|^sdk\/typescript\/scripts\/|^plugins\/codex-security\/mcp-app\/scripts\//;
const pythonInputs =
  /^plugins\/codex-security\/.*\.(?:py|toml)$|^plugins\/codex-security\/requirements[^/]*\.txt$|^plugins\/codex-security\/schemas\//;

export function selectChecks(paths, { event, baseChanged = false }) {
  // A retarget, empty diff, or non-PR execution receives complete qualification.
  const full = event !== "pull_request" || baseChanged || paths.length === 0;
  const source = full || !paths.every((path) => documentation.test(path));
  const workflow =
    full ||
    paths.some(
      (path) =>
        infrastructure.test(path) ||
        path === "docker/verify-container-compose.sh",
    );
  const node =
    full ||
    paths.some((path) => infrastructure.test(path) || nodeInputs.test(path));
  const python =
    full ||
    paths.some((path) => infrastructure.test(path) || pythonInputs.test(path));
  const container =
    full ||
    paths.some(
      (path) =>
        /^(?:\.dockerignore$|Dockerfile(?:\.dockerignore)?$|compose(?:\.[^/]+)?\.yaml$|docker\/|plugins\/codex-security\/|sdk\/typescript\/)/.test(
          path,
        ) || infrastructure.test(path),
    );
  const compatibility = ["22.13.0", "24.0.0", "24", "26.0.0", "26"]
    .filter((version) => node || version !== "26")
    .map((version) => ({ os: "ubuntu-latest", node: version }));
  compatibility.push({ os: "macos-latest", node: "22.13.0" });
  const pythonMatrix = [
    ...["3.10", "3.12", "3.14"]
      .filter((version) => python || version === "3.12")
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
    "workflow-quality": String(workflow),
    "container-validate": String(source && container),
    "compatibility-matrix": JSON.stringify({ include: compatibility }),
    "python-matrix": JSON.stringify({ include: pythonMatrix }),
    "windows-node-matrix": JSON.stringify({
      node: node ? ["22.13.0", "24"] : ["22.13.0"],
    }),
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const event = process.env.EVENT_NAME;
  const baseChanged = process.env.BASE_CHANGED === "true";
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
