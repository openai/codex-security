import { readFile, writeFile } from "node:fs/promises";
import { format } from "prettier";

const plugin = new URL("../../../plugins/codex-security/", import.meta.url);
const deepDefaults = JSON.parse(
  await readFile(new URL("scripts/deep_scan_defaults.json", plugin), "utf8"),
);
const rubricPath = "references/default-severity-rubric.md";
const rubric = await readFile(new URL(rubricPath, plugin), "utf8");

for (const [filename, source] of [
  [
    "deep-scan-defaults.ts",
    `// Generated from the plugin deep_scan_defaults.json. Run pnpm build.\nexport const DEFAULT_DEEP_SCAN_SETTINGS = ${JSON.stringify(deepDefaults)} as const;\n`,
  ],
  [
    "default-severity-rubric.ts",
    `// Generated from the plugin ${rubricPath}. Run pnpm build.\nexport const defaultSeverityRubric = ${JSON.stringify(rubric)};\n`,
  ],
]) {
  const contents = await format(source, { parser: "typescript" });
  const output = new URL(`../src/${filename}`, import.meta.url);
  if (process.argv.includes("--check")) {
    if ((await readFile(output, "utf8")).replaceAll("\r\n", "\n") !== contents)
      throw new Error(`${filename} is out of date. Run pnpm build.`);
  } else {
    await writeFile(output, contents);
  }
}
