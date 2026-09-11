import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { transform } from "esbuild";

const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contract = JSON.parse(
  await readFile(join(app, "../plugin-files.json"), "utf8"),
);
const nativeFiles = contract.shippedExact
  .filter((path) => path.startsWith("mcp/native/"))
  .map((path) => path.slice("mcp/native/".length));
const platform = await transform(
  await readFile(join(app, "../native/platform.mts"), "utf8"),
  {
    loader: "ts",
    format: "esm",
  },
);
const { nativeTarget } = await import(
  `data:text/javascript,${encodeURIComponent(platform.code)}`
);
const hostBinary = nativeFiles.find((path) =>
  path.startsWith(`${nativeTarget}/`),
);
assert.ok(hostBinary);
const foreignBinary = nativeFiles.find(
  (path) => path.endsWith(".node") && path !== hostBinary,
);
const notices = nativeFiles.filter((path) => !path.endsWith(".node"));

async function fixture(t) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-package-test-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const mcp = join(root, "mcp-app");
  await mkdir(join(mcp, "scripts"), { recursive: true });
  await symlink(
    join(app, "node_modules"),
    join(mcp, "node_modules"),
    "junction",
  );
  await copyFile(
    join(app, "scripts/build_mcp_app.mjs"),
    join(mcp, "scripts/build_mcp_app.mjs"),
  );
  await writeFile(
    join(mcp, "package.json"),
    JSON.stringify({
      type: "module",
      scripts: { build: "tsc --noEmit" },
    }),
  );
  await writeFile(
    join(mcp, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: { skipLibCheck: true },
      include: ["*.ts"],
    }),
  );
  await writeFile(join(mcp, "main.ts"), 'console.log("server fixture");\n');
  await writeFile(
    join(mcp, "helpers-main.ts"),
    'console.log("helper fixture");\n',
  );
  await writeFile(join(root, "plugin-files.json"), JSON.stringify(contract));
  for (const [directory, files] of [
    ["prebuilt", nativeFiles],
    ["dist", [...notices, hostBinary]],
  ]) {
    for (const path of files) {
      const destination = join(root, "native", directory, path);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, `${directory}:${path}`);
    }
  }
  await writeFile(join(root, "native/platform.mjs"), platform.code);
  const output = join(root, "output");
  return {
    root,
    output,
    build: (...args) =>
      spawnSync(
        process.execPath,
        [join(mcp, "scripts/build_mcp_app.mjs"), "--output", output, ...args],
        { encoding: "utf8" },
      ),
  };
}

test("host packaging uses only the source-built target and shared notices", async (t) => {
  const { root, output, build } = await fixture(t);
  await rm(join(root, "native/prebuilt"), { recursive: true });
  const result = build("--native", "host");
  assert.equal(result.status, 0, result.stderr);
  const files = (
    await readdir(join(output, "native"), {
      recursive: true,
      withFileTypes: true,
    })
  ).filter((entry) => entry.isFile());
  assert.equal(files.length, notices.length + 1);
  for (const path of [...notices, hostBinary]) {
    assert.equal(
      await readFile(join(output, "native", path), "utf8"),
      `dist:${path}`,
    );
  }
  assert.equal(
    spawnSync(process.execPath, [join(output, "server.mjs")], {
      encoding: "utf8",
    }).stdout,
    "server fixture\n",
  );
  assert.equal(
    spawnSync(process.execPath, [join(output, "helpers.mjs")], {
      encoding: "utf8",
    }).stdout,
    "helper fixture\n",
  );
});

test("default packaging retains every verified prebuilt target", async (t) => {
  const { output, build } = await fixture(t);
  const result = build();
  assert.equal(result.status, 0, result.stderr);
  for (const path of nativeFiles) {
    assert.equal(
      await readFile(join(output, "native", path), "utf8"),
      `prebuilt:${path}`,
    );
  }
});

test("host packaging rejects a missing host build even when prebuilt artifacts exist", async (t) => {
  const { root, build } = await fixture(t);
  await rm(join(root, "native/dist", hostBinary));
  const result = build("--native", "host");
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ENOENT/);
});

test("universal packaging still rejects a missing foreign target", async (t) => {
  const { root, build } = await fixture(t);
  await rm(join(root, "native/prebuilt", foreignBinary));
  const result = build();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ENOENT/);
});
