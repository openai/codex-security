import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";

const { writeHostedScopeInventory: write } = (await importSource(
  join(import.meta.dirname, "../src/helpers/hosted-scope-inventory.ts"),
)) as typeof import("../src/helpers/hosted-scope-inventory.ts");

function fixture(t: TestContext) {
  const base = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "hosted-scope-")));
  t.after(() => fs.rmSync(base, { force: true, recursive: true }));
  // Exercise the fixture's real permissions independently of the runner's
  // temp mount and unmapped UIDs in a user namespace.
  const lstat = fs.lstatSync;
  t.mock.method(fs, "lstatSync", (...args: Parameters<typeof fs.lstatSync>) => {
    const info = lstat(...args);
    const path = String(args[0]);
    if (
      info?.isDirectory() &&
      typeof info.mode === "number" &&
      (path === "/" || base.startsWith(path + "/"))
    ) {
      info.uid = 0;
      info.mode &= ~0o022;
    }
    return info;
  });
  const parent = join(base, "state");
  fs.mkdirSync(parent, { mode: 0o700 });
  const alias = join(base, "state-alias");
  fs.symlinkSync(parent, alias);
  const scopes = join(base, "scopes.json");
  fs.writeFileSync(scopes, '["src"]');
  return {
    base,
    parent,
    alias,
    scopes,
    repo: join(base, "repo"),
    output: join(base, "scan", "input.jsonl"),
  };
}

test(
  "private inventories remain readable through the executor's state directory name",
  { skip: process.platform !== "linux" },
  (t) => {
    const { base, parent, scopes, alias, repo, output } = fixture(t);
    const mask = process.umask(0o777);
    try {
      const first = write(parent, scopes, repo, output, [Buffer.from("one\n")]);
      const second = write(alias, scopes, repo, output, [Buffer.from("two\n")]);
      assert.ok(first && second && first !== second);
      for (const [path, state, expected] of [
        [first, parent, "one\n"],
        [second, alias, "two\n"],
      ]) {
        assert.equal(dirname(path), state);
        assert.match(
          basename(path),
          /^scopes\.json\.scoped-[0-9a-f]{24}\.jsonl$/,
        );
        assert.equal(fs.statSync(path).mode & 0o777, 0o600);
        assert.equal(fs.readFileSync(path, "utf8"), expected);
      }
      const transferred = join(base, "transferred-state");
      fs.renameSync(parent, transferred);
      fs.unlinkSync(alias);
      fs.symlinkSync(transferred, alias);
      assert.equal(fs.readFileSync(second, "utf8"), "two\n");
    } finally {
      process.umask(mask);
    }
  },
);

test(
  "hosted scratch skips a private directory beneath a replaceable ancestor",
  { skip: process.platform !== "linux" },
  (t) => {
    const { base, parent, scopes, repo, output } = fixture(t);
    fs.chmodSync(base, 0o770);
    assert.equal(
      write(parent, scopes, repo, output, [Buffer.from("row")]),
      undefined,
    );
    assert.deepEqual(fs.readdirSync(parent), []);
  },
);

test(
  "an alternate name for the checkout or output still excludes scratch",
  { skip: process.platform !== "linux" },
  (t) => {
    const { base, scopes, repo, output, parent, alias } = fixture(t);
    const row = [Buffer.from("row")];
    assert.equal(write(parent, scopes, alias, output, row), undefined);
    assert.equal(
      write(parent, scopes, repo, join(alias, "inventory"), row),
      undefined,
    );
    fs.mkdirSync(repo, { mode: 0o700 });
    const checkoutLink = join(repo, "link-to-state");
    fs.symlinkSync(parent, checkoutLink);
    const offered = join(base, "offered-state");
    fs.symlinkSync(checkoutLink, offered);
    assert.equal(write(offered, scopes, repo, output, row), undefined);
    assert.deepEqual(fs.readdirSync(parent), []);
  },
);

test(
  "a state alias cannot pass through a replaceable directory",
  { skip: process.platform !== "linux" },
  (t) => {
    const { base, parent, scopes, repo, output } = fixture(t);
    const shared = join(base, "shared");
    fs.mkdirSync(shared);
    fs.chmodSync(shared, 0o770);
    const hop = join(shared, "state-link");
    fs.symlinkSync(parent, hop);
    const nested = join(base, "outer-link");
    fs.symlinkSync("shared/state-link", nested);
    const trailing = join(base, "trailing-link");
    fs.symlinkSync("outer-link/", trailing);
    for (const alias of [hop, nested, trailing]) {
      assert.equal(
        write(alias, scopes, repo, output, [Buffer.from("row")]),
        undefined,
      );
      assert.deepEqual(fs.readdirSync(parent), []);
    }
  },
);

test(
  "state containing a symlink followed by .. falls back",
  { skip: process.platform !== "linux" },
  (t) => {
    const { base, parent, scopes, repo, output } = fixture(t);
    const sub = join(parent, "sub");
    fs.mkdirSync(sub, { mode: 0o700 });
    const link = join(base, "link-to-sub");
    fs.symlinkSync(sub, link);
    assert.equal(
      write(`${link}/..`, scopes, repo, output, [Buffer.from("row")]),
      undefined,
    );
    assert.deepEqual(fs.readdirSync(parent), ["sub"]);
  },
);

test(
  "an already-private state file works when the mount refuses chmod",
  { skip: process.platform !== "linux" },
  (t) => {
    const { parent, scopes, repo, output } = fixture(t);
    const mask = process.umask(0o077);
    t.after(() => process.umask(mask));
    t.mock.method(fs, "fchmodSync", () => {
      throw Object.assign(new Error("chmod denied"), { code: "EPERM" });
    });
    const path = write(parent, scopes, repo, output, [Buffer.from("private")]);
    assert.ok(path);
    assert.equal(fs.statSync(path).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(path, "utf8"), "private");
  },
);

for (const unsupported of ["mode", "owner"] as const) {
  test(
    `a filesystem reporting the wrong ${unsupported} never receives inventory bytes`,
    { skip: process.platform !== "linux" },
    (t) => {
      const { parent, scopes, repo, output } = fixture(t);
      const fstat = fs.fstatSync;
      t.mock.method(
        fs,
        "fstatSync",
        (...args: Parameters<typeof fs.fstatSync>) => {
          const file = fstat(...args);
          if (unsupported === "mode" && typeof file.mode === "number")
            file.mode |= 0o044;
          if (unsupported === "owner" && typeof file.uid === "number")
            file.uid = process.geteuid!() + 1;
          return file;
        },
      );
      const chmod = t.mock.method(fs, "fchmodSync");
      const written = t.mock.method(fs, "writeFileSync");
      assert.equal(
        write(parent, scopes, repo, output, [Buffer.from("private")]),
        undefined,
      );
      assert.equal(chmod.mock.callCount(), 0);
      assert.equal(written.mock.callCount(), 0);
      assert.deepEqual(fs.readdirSync(parent), []);
    },
  );
}

test(
  "a partial scratch write leaves no inventory and preserves a replaced pathname",
  { skip: process.platform !== "linux" },
  (t) => {
    const { parent, scopes, repo, output } = fixture(t);
    const row = Buffer.from("some inventory bytes\n");
    let replacement: string | undefined;
    const actual = fs.writeFileSync;
    const close = fs.closeSync;
    let scratch = "";
    let failedFd: number | undefined;
    let replaceAfterClose = false;
    let linkedAtClose: boolean | undefined;
    t.mock.method(fs, "closeSync", (fd: number) => {
      close(fd);
      if (fd !== failedFd || !replaceAfterClose) return;
      // An unlinked inode can be reused as soon as its last descriptor closes.
      linkedAtClose = fs.existsSync(scratch);
      if (linkedAtClose) fs.unlinkSync(scratch);
      actual(scratch, "new owner");
    });
    const writeRow = t.mock.method(
      fs,
      "writeFileSync",
      (fd: number, bytes: Buffer) => {
        actual(fd, bytes.subarray(0, 3));
        scratch = join(
          parent,
          fs.readdirSync(parent).find((name) => name.endsWith(".jsonl"))!,
        );
        failedFd = fd;
        if (replacement !== undefined) {
          fs.renameSync(scratch, replacement);
          actual(scratch, "other file");
        }
        throw Object.assign(new Error("scratch full"), { code: "ENOSPC" });
      },
    );
    assert.equal(write(parent, scopes, repo, output, [row]), undefined);
    assert.deepEqual(fs.readdirSync(parent), []);
    replacement = join(parent, "moved");
    assert.equal(write(parent, scopes, repo, output, [row]), undefined);
    assert.equal(writeRow.mock.callCount(), 2);
    assert.equal(fs.statSync(replacement).size, 0);
    const remaining = fs
      .readdirSync(parent)
      .find((name) => name.endsWith(".jsonl"))!;
    assert.equal(
      fs.readFileSync(join(parent, remaining), "utf8"),
      "other file",
    );
    fs.unlinkSync(join(parent, remaining));
    t.mock.method(fs, "ftruncateSync", () => {
      throw Object.assign(new Error("truncate denied"), { code: "EPERM" });
    });
    assert.equal(write(parent, scopes, repo, output, [row]), undefined);
    assert.equal(fs.readFileSync(scratch, "utf8"), "other file");
    fs.unlinkSync(scratch);
    replacement = undefined;
    replaceAfterClose = true;
    assert.equal(write(parent, scopes, repo, output, [row]), undefined);
    assert.equal(linkedAtClose, false);
    assert.equal(fs.readFileSync(scratch, "utf8"), "new owner");
  },
);

for (const replace of [false, true]) {
  test(
    `a delayed write error removes only the failed inventory (replaced=${replace})`,
    { skip: process.platform !== "linux" },
    (t) => {
      const { parent, scopes, repo, output } = fixture(t);
      const close = fs.closeSync;
      const writeRow = t.mock.method(fs, "writeFileSync");
      let writerCloses = 0;
      t.mock.method(fs, "closeSync", (fd: number) => {
        if (fd !== writeRow.mock.calls[0]?.arguments[0]) return close(fd);
        writerCloses++;
        close(fd);
        if (replace) {
          const scratch = join(parent, fs.readdirSync(parent)[0]!);
          fs.unlinkSync(scratch);
          fs.writeFileSync(scratch, "replacement");
        }
        throw Object.assign(new Error("quota exceeded on close"), {
          code: "EDQUOT",
        });
      });
      assert.equal(
        write(parent, scopes, repo, output, [Buffer.from("row")]),
        undefined,
      );
      assert.equal(writerCloses, 1);
      const remaining = fs.readdirSync(parent);
      if (replace) {
        assert.equal(remaining.length, 1);
        assert.equal(
          fs.readFileSync(join(parent, remaining[0]!), "utf8"),
          "replacement",
        );
      } else assert.deepEqual(remaining, []);
    },
  );
}
