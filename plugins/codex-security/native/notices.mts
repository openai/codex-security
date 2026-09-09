import { execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { root } from "./binding.mjs";

interface Package {
  name: string;
  version: string;
  source: string | null;
  manifest_path: string;
}

const metadata = JSON.parse(
  execFileSync(
    "cargo",
    ["metadata", "--locked", "--offline", "--format-version", "1"],
    {
      cwd: root,
      encoding: "utf8",
    },
  ),
) as { packages: Package[] };
const packages = metadata.packages
  .filter((entry) => entry.source?.startsWith("registry+"))
  .sort((left, right) => {
    const leftName = `${left.name}@${left.version}`;
    const rightName = `${right.name}@${right.version}`;
    return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
  });
// These archives omit LICENSE; their pinned upstream revisions share this text.
const napiLicense = new Set([
  "napi@3.12.2",
  "napi-build@2.4.1",
  "napi-derive@3.6.3",
  "napi-derive-backend@6.1.2",
  "napi-sys@3.3.0",
]);
const notices: string[] = [];
for (const entry of packages) {
  const directory = dirname(entry.manifest_path);
  const files = (await readdir(directory, { withFileTypes: true }))
    .filter(
      (file) =>
        file.isFile() &&
        /^(?:licen[sc]e|copying|copyright)(?:$|[._-])/iu.test(file.name),
    )
    .map((file) => join(directory, file.name))
    .sort();
  const name = `${entry.name}@${entry.version}`;
  if (files.length === 0 && napiLicense.has(name)) {
    files.push(join(root, "licenses", "napi.txt"));
  }
  if (files.length === 0)
    throw new Error(`Missing native dependency license: ${name}`);
  notices.push(
    `${name}\n\n${(await Promise.all(files.map((file) => readFile(file, "utf8")))).join("\n\n")}`,
  );
}

const destination = join(root, "dist");
await mkdir(join(destination, "licenses"), { recursive: true });
await writeFile(
  join(destination, "THIRD_PARTY_NOTICES.txt"),
  notices.join("\n\n---\n\n"),
);
const sysroot = execFileSync("rustc", ["--print", "sysroot"], {
  cwd: root,
  encoding: "utf8",
}).trim();
const rustNotices = join(sysroot, "share", "doc", "rust");
await copyFile(
  join(rustNotices, "COPYRIGHT-library.html"),
  join(destination, "COPYRIGHT-library.html"),
);
for (const license of ["MIT", "Apache-2.0", "Unicode-3.0", "BSD-2-Clause"]) {
  await copyFile(
    join(rustNotices, "licenses", `${license}.txt`),
    join(destination, "licenses", `${license}.txt`),
  );
}
console.log(
  `Prepared native notices for ${packages.length} registry packages and the Rust standard library.`,
);
