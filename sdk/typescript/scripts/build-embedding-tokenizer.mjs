import { build } from "esbuild";
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
for (const directory of [...roots].sort()) {
  const { name, version, license } = JSON.parse(
    await readFile(join(directory, "package.json"), "utf8"),
  );
  if (!["base64-js", "js-tiktoken"].includes(name) || license !== "MIT") {
    throw new Error(
      `Review the tokenizer's bundled license notice for ${name}@${version} (${license}).`,
    );
  }
  components.push({
    type: "library",
    name,
    version,
    purl: `pkg:npm/${name.replace("@", "%40")}@${version}`,
    licenses: [{ license: { id: license } }],
  });
}
await writeFile(
  output + ".cdx.json",
  JSON.stringify(
    { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components },
    null,
    2,
  ) + "\n",
);
