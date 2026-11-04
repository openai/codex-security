import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scanTopics = ["standard-scan", "diff-scan", "deep-scan"];
export const skillRuntimeTopics = [
  ...scanTopics,
  "build-explorer",
  "copy-worklist",
  "diff-local-patch",
  "diff-revisions",
  "external-imports",
  "patch-risk-validation",
  "policy-list",
  "policy-resolve",
  "recover-scan-results",
  "scope-binding",
  "scope-inventory",
  "tracking-source",
];

/** Select instructions from the installed plugin. The command runs
 * on this executor. Only the calling client can identify its UI surface. */
export async function readSkillRuntimeInstructions(
  pluginRoot,
  topic,
  { platform = process.platform, clientSurface = "headless" } = {},
) {
  if (!skillRuntimeTopics.includes(topic)) {
    throw new Error(`Unknown skill runtime topic: ${topic}`);
  }
  if (clientSurface !== "desktop" && clientSurface !== "headless") {
    throw new Error(`Unknown skill client surface: ${clientSurface}`);
  }
  const readTemplate = (file) =>
    readFile(join(pluginRoot, "templates", "skill-runtime", file), "utf8");
  if (scanTopics.includes(topic)) {
    const startup =
      topic === "standard-scan"
        ? join(clientSurface, "standard-scan.md")
        : topic + ".md";
    const files = [startup];
    if (topic !== "deep-scan") files.push("native-scan.md");
    if (clientSurface === "desktop") files.push("desktop/review-comments.md");
    return (await Promise.all(files.map(readTemplate))).join("\n");
  }
  if (topic === "external-imports") {
    const enabled = process.env.CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS === "1";
    return readTemplate(
      join(enabled ? "enabled" : "disabled", "external-imports.md"),
    );
  }
  const shell = platform === "win32" ? "windows" : "posix";
  return readTemplate(join(shell, topic + ".md"));
}

// Direct skill use can run this reader on the command executor without MCP.
if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  const [topic, clientSurface] = process.argv.slice(2);
  const pluginRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  readSkillRuntimeInstructions(pluginRoot, topic, { clientSurface })
    .then((instructions) => process.stdout.write(instructions))
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
}
