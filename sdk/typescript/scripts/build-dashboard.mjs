import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { build } from "esbuild";
import postcss from "postcss";
import tailwindcss from "@tailwindcss/postcss";

const root = fileURLToPath(new URL("../", import.meta.url));
const destination = new URL("../dist/server/dashboard/", import.meta.url);
await mkdir(destination, { recursive: true });
const built = await build({
  absWorkingDir: root,
  entryPoints: ["dashboard/index.tsx"],
  outfile: fileURLToPath(new URL("app.js", destination)),
  bundle: true,
  platform: "browser",
  format: "esm",
  target: ["es2022"],
  minify: true,
  metafile: true,
  legalComments: "eof",
  define: { "process.env.NODE_ENV": '"production"' },
  plugins: [
    {
      name: "dashboard-styles",
      setup(builder) {
        builder.onLoad(
          { filter: /dashboard[/\\]styles\.css$/ },
          async ({ path }) => {
            const css = await postcss([tailwindcss({ base: root })]).process(
              await readFile(path, "utf8"),
              { from: path },
            );
            // Use system fonts instead of the design system's remote math fonts.
            css.root.walkAtRules("font-face", (rule) => rule.remove());
            return {
              contents: css.root.toString(),
              loader: "css",
              resolveDir: dirname(path),
            };
          },
        );
      },
    },
  ],
});
await copyFile(
  new URL("../dashboard/index.html", import.meta.url),
  new URL("index.html", destination),
);

// Preserve the licenses of packages whose code or design tokens ship in the browser bundle.
const packages = new Set([
  "node_modules/@openai/apps-sdk-ui",
  "node_modules/tailwindcss",
]);
for (const output of Object.values(built.metafile.outputs)) {
  for (const [source, { bytesInOutput }] of Object.entries(output.inputs)) {
    const directory = /^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//.exec(
      source.replaceAll("\\", "/"),
    )?.[1];
    if (directory && bytesInOutput > 0) packages.add(directory);
  }
}
const notices = [];
for (const directory of [...packages].sort()) {
  const path = join(root, directory);
  const manifest = JSON.parse(
    await readFile(join(path, "package.json"), "utf8"),
  );
  const license = (await readdir(path)).find((name) =>
    /^licen[sc]e(?:\.[^.]+)?$/i.test(name),
  );
  if (!license)
    throw new Error(`Missing dashboard dependency license: ${manifest.name}`);
  notices.push(
    `${manifest.name}@${manifest.version}\n\n${await readFile(join(path, license), "utf8")}`,
  );
}
await writeFile(
  new URL("THIRD_PARTY_NOTICES.txt", destination),
  notices.join("\n\n---\n\n"),
);
