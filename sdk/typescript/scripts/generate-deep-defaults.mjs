import { readFile, writeFile } from "node:fs/promises";
import { format } from "prettier";

const defaults = JSON.parse(
  await readFile(
    new URL(
      "../../../plugins/codex-security/scripts/deep_scan_defaults.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const contents = await format(
  `// Generated from the plugin deep_scan_defaults.json. Run pnpm build.\nexport const DEFAULT_DEEP_SCAN_SETTINGS = ${JSON.stringify(defaults)} as const;\n`,
  { parser: "typescript" },
);
const output = new URL("../src/deep-scan-defaults.ts", import.meta.url);
if (process.argv.includes("--check")) {
  if ((await readFile(output, "utf8")).replaceAll("\r\n", "\n") !== contents) {
    throw new Error("Deep scan defaults are out of date. Run pnpm build.");
  }
} else {
  await writeFile(output, contents);
}
