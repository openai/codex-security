import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { format } from "prettier";

const sdk = new URL("../", import.meta.url);
const plugin = new URL("../../plugins/codex-security/", sdk);
const check = process.argv.includes("--check");

async function generate(parser, source, ...outputs) {
  const contents = await format(source, { parser });
  for (const output of outputs) {
    if (check) {
      const current = await readFile(output, "utf8");
      if (current.replaceAll("\r\n", "\n") !== contents)
        throw new Error(
          `${fileURLToPath(output)} is out of date. Run pnpm build.`,
        );
    } else {
      await mkdir(new URL(".", output), { recursive: true });
      await writeFile(output, contents);
    }
  }
}

// The standalone plugin build runs without the SDK checkout. Ship the same verifier
// source there, with package dependencies left for the plugin's own lockfile.
const verifier = await build({
  absWorkingDir: fileURLToPath(sdk),
  entryPoints: ["scripts/plugin-scan-owners.mts"],
  bundle: true,
  packages: "external",
  platform: "node",
  format: "esm",
  write: false,
});
await generate(
  "babel",
  "// Generated from the SDK owner verifier. Run pnpm build in sdk/typescript.\n" +
    verifier.outputFiles[0].text,
  new URL("mcp-app/scripts/scan-owners.mjs", plugin),
);

const deepDefaults = JSON.parse(
  await readFile(new URL("scripts/deep_scan_defaults.json", plugin), "utf8"),
);
const deepSettings = await readFile(
  new URL("mcp-app/src/deep-scan-settings.ts", plugin),
  "utf8",
);
const rubricPath = "references/default-severity-rubric.md";
const rubric = await readFile(new URL(rubricPath, plugin), "utf8");

for (const [filename, source] of [
  [
    "deep-scan-defaults.ts",
    `// Generated from the plugin Deep Scan defaults and settings. Run pnpm build.\nexport const DEFAULT_DEEP_SCAN_SETTINGS = ${JSON.stringify(deepDefaults)} as const;\n\n${deepSettings}`,
  ],
  [
    "default-severity-rubric.ts",
    `// Generated from the plugin ${rubricPath}. Run pnpm build.\nexport const defaultSeverityRubric = ${JSON.stringify(rubric)};\n`,
  ],
]) {
  await generate("typescript", source, new URL(`src/${filename}`, sdk));
}

// The project schema uses the generated Deep Scan defaults.
const bundled = await build({
  entryPoints: [fileURLToPath(new URL("src/project-config-schema.ts", sdk))],
  bundle: true,
  platform: "node",
  format: "esm",
  write: false,
});
const { projectConfigJsonSchema } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);
await generate(
  "json",
  JSON.stringify(projectConfigJsonSchema()),
  new URL("schemas/project-config.schema.json", sdk),
  new URL("mcp-app/src/deep-scan/project-config.schema.json", plugin),
);
