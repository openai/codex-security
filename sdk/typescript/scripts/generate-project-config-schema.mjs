import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { format } from "prettier";

// Load the source schema without requiring a prior SDK build during typechecks.
const bundled = await build({
  entryPoints: [
    fileURLToPath(new URL("../src/project-config-schema.ts", import.meta.url)),
  ],
  bundle: true,
  platform: "node",
  format: "esm",
  write: false,
});
const { projectConfigJsonSchema } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);

const directory = new URL("../schemas/", import.meta.url);
const output = new URL("project-config.schema.json", directory);
const contents = await format(JSON.stringify(projectConfigJsonSchema()), {
  parser: "json",
});
if (process.argv.includes("--check")) {
  if ((await readFile(output, "utf8")).replaceAll("\r\n", "\n") !== contents) {
    throw new Error(
      "Project configuration schema is out of date. Run pnpm build.",
    );
  }
} else {
  await mkdir(directory, { recursive: true });
  await writeFile(output, contents);
}
