import { build } from "esbuild";
import { valid } from "semver";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const output = "dist/server/embedding-tokenizer";
const bundle = await build({
  entryPoints: ["src/server/embedding-tokenizer.ts"],
  outfile: output + ".js",
  bundle: true,
  format: "esm",
  platform: "node",
  sourcemap: true,
  sourcesContent: false,
  metafile: true,
});

// Inventory the modules actually included. pnpm can nest multiple node_modules
// directories, including different versions of the same package.
const roots = new Set();
for (const path of Object.keys(bundle.metafile.inputs)) {
  const dependency = /^(.*\bnode_modules\/(?:@[^/]+\/)?[^/]+)\//u.exec(path);
  if (dependency) roots.add(dependency[1]);
}
const components = [];
const required = new Set(["base64-js", "js-tiktoken"]);
for (const directory of [...roots].sort()) {
  const { name, version, license } = JSON.parse(
    await readFile(join(directory, "package.json"), "utf8"),
  );
  if (!required.delete(name) || !valid(version) || license !== "MIT") {
    throw new Error(
      `Review the tokenizer's bundled component ${name}@${version} (${license}).`,
    );
  }
  components.push({
    type: "library",
    name,
    version,
    purl: `pkg:npm/${name}@${encodeURIComponent(version)}`,
    licenses: [{ license: { id: license } }],
  });
}
if (required.size) {
  throw new Error(
    `Missing tokenizer bundle inputs: ${[...required].join(", ")}.`,
  );
}
await writeFile(
  output + ".cdx.json",
  JSON.stringify(
    { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components },
    null,
    2,
  ) + "\n",
);
