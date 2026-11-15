import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";

test(
  "hosted scope recovery creates fresh files and replaces links without altering their target",
  { skip: process.platform !== "linux" },
  (t) => {
    const root = fs.mkdtempSync(join(tmpdir(), "hosted-scope-recovery-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const repo = join(root, "repo");
    fs.mkdirSync(repo);
    const scan = join(root, "scan");
    fs.mkdirSync(scan);
    const output = join(scan, "scoped-source-input.jsonl");
    const sentinel = join(root, "sentinel");
    fs.writeFileSync(sentinel, "original");
    const scopes = join(root, "scopes.json");
    const helper = join(
      import.meta.dirname,
      "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
    );
    const mount = join(root, "fixed-permissions.cjs");
    fs.writeFileSync(
      mount,
      `
      const fs = require("node:fs");
      const open = fs.openSync, chmod = fs.fchmodSync;
      const initialMode = process.umask() === 0o777 ? 0 : 0o644;
      fs.openSync = (path, flags, mode) => {
        const fd = open(path, flags, mode);
        if (flags === "wx" && String(path) === ${JSON.stringify(output)}) chmod(fd, initialMode);
        return fd;
      };
      if (initialMode !== 0)
        fs.fchmodSync = () => { throw Object.assign(new Error("chmod unsupported"), { code: "ENOTSUP" }); };
    `,
    );
    const noRename = join(root, "no-rename.cjs");
    const fault = join(root, "storage-fault");
    fs.writeFileSync(
      noRename,
      `
      const fs = require("node:fs");
      const publish = fs.renameSync;
      fs.renameSync = () => { throw Object.assign(new Error("rename unsupported"), { code: "ENOTSUP" }); };
      const fault = ${JSON.stringify(fault)};
      const failure = fs.existsSync(fault) ? fs.readFileSync(fault, "utf8") : "";
      if (failure === "write") {
        const write = fs.writeFileSync;
        fs.writeFileSync = (fd, data, ...args) => {
          if (typeof fd !== "number") return write(fd, data, ...args);
          write(fd, data.subarray(0, 1));
          throw Object.assign(new Error("disk full"), { code: "ENOSPC" });
        };
      } else {
        const open = fs.openSync, close = fs.closeSync;
        let writer;
        fs.openSync = (path, flags, ...args) => {
          if (writer?.path === String(path))
            throw Object.assign(new Error("writer still open"), { code: "EBUSY" });
          const fd = open(path, flags, ...args);
          if (flags === "wx") writer = { fd, path: String(path) };
          return fd;
        };
        fs.closeSync = fd => {
          close(fd);
          if (writer?.fd !== fd) return;
          const path = writer.path;
          writer = undefined;
          if (failure === "close")
            throw Object.assign(new Error("close quota exceeded"), { code: "EDQUOT" });
          // This mount publishes completed bytes as a new inode when the writer closes.
          fs.copyFileSync(path, path + ".published");
          publish(path + ".published", path);
        };
      }
    `,
    );
    const args = ["--repo", repo, "--scopes-file", scopes, "--out", output];
    for (const [name, link, mask, preload] of [
      ["one.ts", fs.symlinkSync, 0o777, mount],
      ["two.ts", fs.linkSync, 0o022, mount],
      ["fresh.ts", undefined, 0o022, noRename],
      ["occupied.ts", fs.linkSync, 0o022, noRename],
    ] as const) {
      fs.writeFileSync(join(repo, name), "source");
      fs.writeFileSync(scopes, JSON.stringify([name]));
      link?.(sentinel, output);
      const run = (command: string) => {
        const stdout = execFileSync(
          process.execPath,
          ["--require", preload, helper, command, ...args],
          { encoding: "utf8", stdio: "pipe" },
        );
        const reported = stdout.match(/^Wrote 1 scoped paths to (.+)$/mu)?.[1];
        assert.ok(reported, stdout);
        return reported;
      };
      const previous = process.umask(mask);
      let reported: string;
      let ordinaryMode: number | undefined;
      try {
        if (!link) {
          assert.equal(run("make-repo-scope-input"), output);
          ordinaryMode = fs.statSync(output).mode & 0o777;
          fs.unlinkSync(output);
          fs.writeFileSync(fault, "write");
          assert.throws(() => run("make-hosted-repo-scope-input"), /disk full/);
          for (const entry of fs.readdirSync(scan))
            assert.equal(entry, basename(output));
          fs.writeFileSync(fault, "close");
          for (let attempt = 0; attempt < 2; attempt++)
            assert.throws(
              () => run("make-hosted-repo-scope-input"),
              /close quota exceeded/,
            );
          fs.unlinkSync(fault);
        }
        reported = run("make-hosted-repo-scope-input");
      } finally {
        process.umask(previous);
      }
      assert.deepEqual(fs.readdirSync(scan), [basename(output)]);
      assert.equal(reported, output);
      const mode = fs.statSync(reported).mode & 0o777;
      assert.ok(mode & 0o400);
      if (ordinaryMode !== undefined) assert.equal(mode, ordinaryMode);
      assert.equal(fs.readFileSync(sentinel, "utf8"), "original");
      assert.equal(
        fs.readFileSync(reported, "utf8"),
        JSON.stringify({ path: name }) + "\n",
      );
      fs.unlinkSync(reported);
      if (link === fs.symlinkSync) {
        fs.mkdirSync(output);
        assert.throws(() => run("make-hosted-repo-scope-input"), { status: 1 });
        assert.deepEqual(fs.readdirSync(scan), [basename(output)]);
        fs.rmdirSync(output);
      }
    }
  },
);
