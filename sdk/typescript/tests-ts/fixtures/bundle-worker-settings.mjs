import { readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

const [executor, output] = process.argv.slice(2);
const bundled = await build({
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
  define: { "import.meta.url": JSON.stringify(pathToFileURL(executor).href) },
  stdin: {
    contents:
      (await readFile(executor, "utf8")) +
      "\nexport { workerRuntimeSettings };",
    loader: "ts",
    resolveDir: dirname(executor),
    sourcefile: executor,
  },
});
await writeFile(output, bundled.outputFiles[0].contents);
