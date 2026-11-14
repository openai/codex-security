import { readFile } from "node:fs/promises";
import { join } from "node:path";

const scanTopics = ["standard-scan", "diff-scan", "deep-scan"];
export const skillRuntimeTopics = [
  ...scanTopics,
  "build-explorer",
  "copy-worklist",
  "diff-local-patch",
  "diff-revisions",
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
  if (scanTopics.includes(topic)) {
    const startup =
      topic === "standard-scan" ? topic + "-" + clientSurface : topic;
    const sections = [startup];
    if (topic !== "deep-scan") sections.push("checkpoints");
    if (clientSurface === "desktop") sections.push("review-comments");
    return readSections(pluginRoot, "scans", sections);
  }
  const shell = platform === "win32" ? "windows" : "posix";
  return readSections(pluginRoot, shell, [topic]);
}

async function readSections(pluginRoot, name, headings) {
  const catalog = await readFile(
    join(pluginRoot, "templates", "skill-runtime", name + ".md"),
    "utf8",
  );
  const [intro, ...sections] = catalog.split(/^## /m);
  const selected = headings.map((heading) => {
    const section = sections.find(
      (entry) => entry.split(/\r?\n/, 1)[0] === heading,
    );
    if (!section)
      throw new Error(`Missing ${name}.md instruction section: ${heading}`);
    return section.slice(heading.length).trim();
  });
  return intro + selected.join("\n\n") + "\n";
}
