import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import childProcess from "node:child_process";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { constants, tmpdir } from "node:os";
import { join } from "node:path";
import { importSource } from "./import-module.ts";
import type { WindowsBinding } from "../../native/windows-binding.mjs";

const helperUrl = new URL(
  "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
  import.meta.url,
);
const { git, runTool } = await importSource("src/helpers/inventory-git.ts", {
  define: { "import.meta.url": JSON.stringify(helperUrl.href) },
});

for (const [name, details] of [
  ["named", { code: "ENOEXEC" }],
  [
    "numeric",
    { code: "Unknown system error -8", errno: -constants.errno.ENOEXEC },
  ],
] as const)
  test(
    `POSIX tools run executable text after a ${name} exec-format launch error`,
    { skip: process.platform === "win32" },
    async () => {
      const root = fs.mkdtempSync(join(tmpdir(), "inventory-exec-format-"));
      const tool = join(root, "plain tool");
      const diagnostic =
        "synthetic tool failure\n\u000000000000-0000-4000-8000-000000000000\u0000127\u0000\n";
      fs.writeFileSync(
        tool,
        `printf '%s' "$1"
/bin/cat <&"$2"
printf 'synthetic tool failure\\n\\00000000000-0000-4000-8000-000000000000\\000127\\000\\n' >&2
if [ "$3" = signal ]; then kill -TERM $$; fi
exit "$3"
`,
        { mode: 0o700 },
      );
      const original = childProcess.spawn;
      let failure: NodeJS.ErrnoException = Object.assign(
        new Error("spawn " + details.code),
        details,
      );
      let attempts = 0;
      childProcess.spawn = ((
        ...args: Parameters<typeof childProcess.spawn>
      ) => {
        if (args[0] === tool) {
          attempts++;
          throw failure;
        }
        return original(...args);
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      try {
        const argument = "spaces 'quoted' $literal\n";
        const input = Buffer.from([0, 128, 255, 10]);
        for (const inputFd of [0, 3])
          for (const status of [0, 126, 127, "signal"]) {
            const result = await runTool(
              tool,
              [argument, String(inputFd), String(status)],
              root,
              input,
              inputFd,
            );
            assert.equal(result.status, status === "signal" ? null : status);
            assert.equal(result.signal, status === "signal" ? "SIGTERM" : null);
            assert.deepEqual(
              result.stdout,
              Buffer.concat([Buffer.from(argument), input]),
            );
            assert.equal(result.stderr, diagnostic);
          }
        assert.equal(attempts, 8);
        failure = Object.assign(new Error("unrelated launch failure"), {
          code: "EACCES",
        });
        await assert.rejects(runTool(tool, []), (error) => error === failure);
      } finally {
        childProcess.spawn = original;
        syncBuiltinESMExports();
        fs.rmSync(root, { recursive: true, force: true });
      }
    },
  );

test(
  "POSIX tools keep helper input separate from stdin and startup status",
  { skip: process.platform === "win32" },
  async () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-input-fds-"));
    const denied = join(root, "not-executable");
    fs.writeFileSync(denied, "#!/bin/sh\n", { mode: 0o600 });
    const unavailableInterpreter = join(root, "unavailable-interpreter");
    fs.writeFileSync(
      unavailableInterpreter,
      "#!/missing-codex-test-interpreter\n",
      { mode: 0o700 },
    );
    try {
      for (const argument of ["ordinary", "raw-\udcff"])
        for (const inputFd of [0, 3]) {
          const input = Buffer.from([0, 128, 255, 10]);
          const result = await runTool(
            process.execPath,
            [
              "-e",
              `const fs = require('node:fs');
fs.writeFileSync(1, fs.readFileSync(${inputFd}));
${inputFd === 3 ? "fs.writeFileSync(2, String(fs.readFileSync(0).length));" : ""}`,
              argument,
            ],
            undefined,
            input,
            inputFd,
          );
          assert.equal(result.status, 0, result.stderr);
          assert.deepEqual(result.stdout, input);
          assert.equal(result.stderr, inputFd === 3 ? "0" : "");
          for (const [command, code] of [
            [join(root, "missing"), "ENOENT"],
            [unavailableInterpreter, "ENOENT"],
            [denied, "EACCES"],
          ])
            await assert.rejects(
              runTool(command, [argument], undefined, input, inputFd),
              { code },
            );
          for (const status of [126, 127]) {
            const launched = await runTool(
              process.execPath,
              ["-e", `process.exit(${status})`, argument],
              undefined,
              input,
              inputFd,
            );
            assert.equal(launched.status, status);
          }
          const statusFd = inputFd === 3 ? 4 : 3;
          const descendant = await runTool(
            "/bin/sh",
            [
              "-c",
              `/bin/sh -c 'if ( : >&${statusFd} ) 2>/dev/null; then printf inherited; else printf closed; fi'`,
              "inventory-fixture",
              argument,
            ],
            undefined,
            input,
            inputFd,
          );
          assert.equal(descendant.status, 0, descendant.stderr);
          assert.equal(descendant.stdout.toString(), "closed");
        }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "POSIX tools retain loader settings across the raw argument shell bridge",
  { skip: process.platform === "win32" },
  async () => {
    const names = ["LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"];
    const saved = names.map((name) => [name, process.env[name]] as const);
    try {
      for (const name of names) process.env[name] = "/fixture/libraries";
      for (const argument of ["ordinary", "raw-\udcff"]) {
        const result = await runTool(process.execPath, [
          "-e",
          `process.stdout.write(JSON.stringify(${JSON.stringify(names)}.map(name => process.env[name])));`,
          argument,
        ]);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stderr, "");
        assert.deepEqual(JSON.parse(result.stdout.toString()), [
          "/fixture/libraries",
          "/fixture/libraries",
        ]);
        for (const name of names)
          assert.equal(process.env[name], "/fixture/libraries");
      }
    } finally {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  },
);

const { windowsFileSystem } = (await importSource(
  "../native/windows-files.mts",
)) as typeof import("../../native/windows-files.mjs");

test(
  "Windows inventory honors an explicit Git .com executable beside a .com.exe sibling",
  { skip: process.platform !== "win32" },
  async () => {
    const binary = createRequire(helperUrl).resolve(
      `./native/win32-${process.arch}/windows.node`,
    );
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-git-com-"));
    const repo = join(root, "repository with spaces");
    const tools = join(root, "trusted tools");
    const preload = join(root, "probe.cjs");
    const callerCwd = process.cwd();
    const names = [
      "CODEX_SECURITY_GIT",
      "NODE_OPTIONS",
      "INVENTORY_PROCESS_FIXTURE",
    ];
    const saved = names.map((name) => [name, process.env[name]] as const);
    try {
      fs.mkdirSync(repo);
      fs.mkdirSync(tools);
      // Preloads run before Node handles Git's -c arguments as syntax checking.
      fs.writeFileSync(
        preload,
        `const fs = require('node:fs');
const native = require(${JSON.stringify(binary)});
fs.writeFileSync(1, fs.readFileSync(0));
fs.writeFileSync(2, JSON.stringify({
  executable: process.execPath,
  args: native.windowsArguments().slice(1).map(value => value.toString('utf16le')),
  cwd: process.cwd(),
  setting: process.env.INVENTORY_PROCESS_FIXTURE,
}));
process.exit(23);
`,
      );
      process.env.NODE_OPTIONS = `--require ${JSON.stringify(preload.replaceAll("\\", "/"))}`;
      process.env.INVENTORY_PROCESS_FIXTURE = "configured target";
      for (const basename of ["git.com", ".COM"]) {
        const executable = join(tools, basename);
        fs.copyFileSync(process.execPath, executable);
        fs.copyFileSync(process.execPath, `${executable}.exe`);
        process.env.CODEX_SECURITY_GIT = executable;
        for (const argument of ["ordinary", "raw-\ud800\ttab"]) {
          const args = ["--fixture", argument];
          const result = await git(repo, args);
          assert.equal(result.status, 23, result.stderr);
          assert.equal(result.signal, null);
          assert.deepEqual(result.stdout, Buffer.alloc(0));
          assert.deepEqual(JSON.parse(result.stderr), {
            executable,
            args: [
              "-c",
              "core.fsmonitor=false",
              "-c",
              "i18n.logOutputEncoding=UTF-8",
              "-C",
              repo,
              ...args,
            ],
            cwd: callerCwd,
            setting: "configured target",
          });

          const input = Buffer.from([0, 128, 255, 10]);
          const toolArgs = ["-e", "", argument];
          const tool = await runTool(executable, toolArgs, repo, input);
          assert.equal(tool.status, 23, tool.stderr);
          assert.equal(tool.signal, null);
          assert.deepEqual(tool.stdout, input);
          assert.deepEqual(JSON.parse(tool.stderr), {
            executable,
            args: toolArgs,
            cwd: repo,
            setting: "configured target",
          });
          assert.equal(process.cwd(), callerCwd);
        }
      }
    } finally {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "Windows tools preserve PATH selection and resolve relative PATH and cwd-only executables",
  { skip: process.platform !== "win32" },
  async () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-relative-path-"));
    const repo = join(root, "repo");
    const tools = join(repo, "tools");
    const shim = join(root, "shim");
    const callerCwd = process.cwd();
    const originalExecutable = process.execPath;
    const names = [
      "PATH",
      "INVENTORY_PROCESS_FIXTURE",
      "NoDefaultCurrentDirectoryInExePath",
    ];
    const saved = names.map((name) => [name, process.env[name]] as const);
    try {
      fs.mkdirSync(tools, { recursive: true });
      fs.copyFileSync(process.execPath, join(tools, "rg.exe"));
      fs.mkdirSync(shim);
      fs.copyFileSync(process.execPath, join(shim, "node.exe"));
      fs.copyFileSync(process.execPath, join(shim, "rg.exe"));
      process.env.INVENTORY_PROCESS_FIXTURE = "target setting";
      delete process.env.NoDefaultCurrentDirectoryInExePath;
      for (const location of ["relative PATH", "PATH collision", "cwd only"]) {
        process.env.PATH = location === "relative PATH" ? "tools" : tools;
        process.execPath =
          location === "PATH collision"
            ? join(shim, "node.exe")
            : originalExecutable;
        if (location === "cwd only")
          fs.renameSync(join(tools, "rg.exe"), join(repo, "rg.exe"));
        for (const argument of ["ordinary", "raw-\ud800"]) {
          const result = await runTool(
            "rg",
            [
              "-e",
              "process.stdout.write(JSON.stringify({executable:process.execPath,cwd:process.cwd(),setting:process.env.INVENTORY_PROCESS_FIXTURE}));",
              argument,
            ],
            repo,
          );
          assert.equal(result.status, 0, result.stderr);
          assert.deepEqual(JSON.parse(result.stdout.toString()), {
            executable: join(location === "cwd only" ? repo : tools, "rg.exe"),
            cwd: repo,
            setting: "target setting",
          });
          assert.equal(result.stderr, "");
          assert.equal(process.cwd(), callerCwd);
        }
      }
    } finally {
      process.execPath = originalExecutable;
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

for (const platform of ["linux", "win32"]) {
  test(`Git paths retain platform byte encoding on ${platform}`, async () => {
    const { decodeGitPath, encodeGitPath } = await importSource(
      "src/helpers/inventory-git.ts",
      {
        define: {
          "process.platform": JSON.stringify(platform),
          "import.meta.url": JSON.stringify(helperUrl.href),
        },
      },
    );
    const bytes = Buffer.concat([
      Buffer.from("résumé/😀/high-"),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from("/low-"),
      Buffer.from([0xed, 0xbf, 0xbf]),
      Buffer.from("\0ordinary\0"),
    ]);
    const text =
      platform === "win32"
        ? "résumé/😀/high-\ud800/low-\udfff\0ordinary\0"
        : "résumé/😀/high-\udced\udca0\udc80/low-\udced\udcbf\udcbf\0ordinary\0";
    assert.equal(decodeGitPath(bytes), text);
    assert.deepEqual(encodeGitPath(text), bytes);
  });
}

const { sampleFile, createSourceSampler, PREVIEW_READ_BYTES } =
  await importSource("src/helpers/source-preview.ts", {
    define: {
      "import.meta.url": JSON.stringify(helperUrl.href),
    },
  });

for (const [name, reparseTag, surrogate] of [
  ["cloud directory", 0x9000001a, false],
  ["directory junction", 0xa0000003, true],
  ["symbolic link", 0xa000000c, true],
] as const)
  test(`Windows metadata identifies ${name} without treating every reparse point as a link`, () => {
    const binding = {
      windowsAbsolutePath: (value: Buffer) => ({ error: 0, value }),
      openWindowsFile: () => ({
        error: 0,
        handle: {
          attributes: () => ({ error: 0, attributes: 0x410, reparseTag }),
          fileType: () => ({ error: 0, value: 1 }),
          close: () => 0,
        },
      }),
    } as unknown as WindowsBinding;
    const info = windowsFileSystem(binding).stat(
      Buffer.from("C:\\fixture", "utf16le"),
      false,
    );
    assert.equal(info.isReparsePoint(), true);
    assert.equal(info.isNameSurrogate(), surrogate);
    if (!surrogate) assert.equal(info.isDirectory(), true);
  });

test("POSIX file identities retain all 64 inode bits", async () => {
  const original = fs.statSync;
  fs.statSync = ((path, options) => {
    if (!["left", "right"].includes(String(path)))
      return original(path, options);
    const ino = String(path) === "left" ? 9007199254740992n : 9007199254740993n;
    return options?.bigint ? { dev: 1n, ino } : { dev: 1, ino: Number(ino) };
  }) as typeof fs.statSync;
  syncBuiltinESMExports();
  try {
    const { sameFile } = await importSource("src/helpers/inventory-paths.ts", {
      define: {
        "process.platform": '"linux"',
        "import.meta.url": JSON.stringify(helperUrl.href),
      },
    });
    assert.equal(sameFile("left", "right"), false);
    assert.equal(sameFile("left", "left"), true);
  } finally {
    fs.statSync = original;
    syncBuiltinESMExports();
  }
});

test(
  "short file reads preserve the complete preview prefix and UTF-16 units",
  { skip: process.platform === "win32" },
  () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-short-read-"));
    const file = join(root, "source");
    const original = fs.readSync;
    let calls = 0;
    fs.readSync = ((descriptor, buffer, offset, length, position) =>
      original(
        descriptor,
        buffer,
        offset,
        Math.min(length, [1, 3, 5, 4096][calls++ % 4]!),
        position,
      )) as typeof fs.readSync;
    syncBuiltinESMExports();
    try {
      const utf16 = Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        Buffer.from("Ā source\n".repeat(8000), "utf16le"),
      ]);
      for (const data of [
        Buffer.alloc(0),
        Buffer.from([0xff]),
        Buffer.from([0xff, 0xfe]),
        Buffer.from([0xff, 0xfe, 0]),
        Buffer.from([0xfe, 0xff, 0]),
        Buffer.from("source\n".repeat(12000)),
        utf16,
        Buffer.from(utf16).swap16(),
      ]) {
        fs.writeFileSync(file, data);
        calls = 0;
        const [sample, binary] = sampleFile(file);
        assert.equal(binary, false);
        assert.deepEqual(sample, data.subarray(0, PREVIEW_READ_BYTES));
        fs.writeFileSync(file, Buffer.concat([data, Buffer.from([0, 0])]));
        calls = 0;
        assert.equal(sampleFile(file)[1], true);
      }
    } finally {
      fs.readSync = original;
      syncBuiltinESMExports();
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test("Windows short file reads preserve previews across split BOMs and units", () => {
  const text = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from("Ā source\n".repeat(8000), "utf16le"),
  ]);
  for (const source of [Buffer.alloc(0), Buffer.from([0xff, 0xfe, 0]), text])
    for (const binary of [false, true]) {
      const data = binary
        ? Buffer.concat([source, Buffer.from([0, 0])])
        : source;
      let cursor = 0,
        calls = 0,
        closes = 0;
      const native = {
        windowsAbsolutePath: (value: Buffer) => ({ error: 0, value }),
        openWindowsFile: () => ({
          error: 0,
          handle: {
            read: (buffer: Buffer, offset: number, length: number) => {
              const count = Math.min(
                length,
                data.length - cursor,
                [1, 3, 5, 4096][calls++ % 4]!,
              );
              data.copy(buffer, offset, cursor, cursor + count);
              cursor += count;
              return { error: 0, value: count };
            },
            close: () => {
              closes++;
              return 0;
            },
          },
        }),
      } as unknown as WindowsBinding;
      const sampler = createSourceSampler();
      assert.equal(sampler.consume(Buffer.alloc(0)), true);
      windowsFileSystem(native).readChunks(
        Buffer.from("C:\\fixture", "utf16le"),
        sampler.consume,
      );
      assert.deepEqual(sampler.finish(), [
        binary ? Buffer.alloc(0) : source.subarray(0, PREVIEW_READ_BYTES),
        binary,
      ]);
      assert.equal(closes, 1);
    }
});
