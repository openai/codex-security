import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { extractApplication } from "./invoice-desk-source.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "invoice-desk-source-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repository = join(root, "repository");
  const app = join(repository, "examples/invoice-desk/app");
  mkdirSync(app, { recursive: true });
  const git = (...args) =>
    execFileSync("git", args, { cwd: repository, encoding: "utf8" }).trim();
  git("init", "--quiet");
  writeFileSync(
    join(app, "server.mjs"),
    'export const version = "$Format:%H$";\n',
  );
  writeFileSync(
    join(app, ".gitattributes"),
    "server.mjs export-ignore export-subst\n",
  );
  writeFileSync(
    join(repository, "examples/invoice-desk/README.md"),
    "Sample metadata\n",
  );
  git("add", ".");
  return { root, repository, app, git, destination: join(root, "source") };
}

test("extracts exact blobs despite archive attributes and dirty checkout files", (t) => {
  const { repository, app, git, destination } = fixture(t);
  const tree = git("write-tree");
  writeFileSync(join(app, "server.mjs"), "changed working tree\n");
  assert.equal(extractApplication(repository, tree, destination), 2);
  assert.equal(
    readFileSync(join(destination, "server.mjs"), "utf8"),
    'export const version = "$Format:%H$";\n',
  );
  assert.equal(existsSync(join(destination, "README.md")), false);
});

test("rejects links instead of following or silently omitting them", (t) => {
  const { repository, app, git, destination } = fixture(t);
  writeFileSync(join(app, "link"), "../../outside\n");
  const oid = git("hash-object", "-w", "examples/invoice-desk/app/link");
  git(
    "update-index",
    "--add",
    "--cacheinfo",
    `120000,${oid},examples/invoice-desk/app/link`,
  );
  assert.throws(
    () => extractApplication(repository, git("write-tree"), destination),
    /regular files/,
  );
  assert.equal(existsSync(destination), false);
});

test("missing application source is an error, not an empty clean scan", (t) => {
  const { repository, git, destination } = fixture(t);
  git("rm", "--cached", "-r", "examples/invoice-desk/app");
  assert.throws(() =>
    extractApplication(repository, git("write-tree"), destination),
  );
  assert.equal(existsSync(destination), false);
});
