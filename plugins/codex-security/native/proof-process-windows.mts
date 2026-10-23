import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  symlinkSync,
} from "node:fs";
import { join, win32 } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { rootCertificates } from "node:tls";
import { binaryPath } from "./binding.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { widePath, windowsFileSystem } from "./windows-files.mjs";
import { windowsFlags as flags } from "./windows-flags.mjs";
import { spawnWindowsProcess } from "./windows-process.mjs";

async function processExit(
  child: ReturnType<typeof spawnWindowsProcess>,
  scenario: string,
  options?: { signal: AbortSignal },
) {
  try {
    return await once(child, "close", options);
  } catch (cause) {
    throw new Error(`Windows process proof failed: ${scenario}`, { cause });
  }
}

export async function processProof(
  root: string,
  symlinks: boolean,
): Promise<Record<string, boolean>> {
  const native = loadWindowsBinding(),
    files = windowsFileSystem(native);
  const cwd = join(root, "process-\ud800");
  files.mkdir(widePath(cwd));
  const cleanupPaths = [cwd];
  let proofError: unknown;
  try {
    const arguments_ = [
      "high-\ud800",
      "low-\udfff",
      "replacement-�",
      'quote"and\\',
      "",
      "東京 😀",
      ...[0, 1, 2, 3].flatMap((count) => [
        `slashes${"\\".repeat(count)}"quote`,
        `space ${"\\".repeat(count)}`,
      ]),
    ];
    const script = `const fs=require('node:fs'), native=require(${JSON.stringify(binaryPath)}); const argv=native.windowsArguments().map(value=>value.toString('utf16le')); const args=argv.slice(3); const cwd=native.windowsAbsolutePath(Buffer.from('.', 'utf16le')).value.toString('utf16le'); process.stderr.write(JSON.stringify({args,argv0:argv[0],cwd,executable:process.execPath,setting:process.env.INVENTORY_PROCESS_FIXTURE,rawSetting:native.windowsEnvironment(Buffer.from("INVENTORY_PROCESS_RAW", "utf16le")).toString("utf16le")})); process.stdout.write(fs.readFileSync(0)); process.exitCode=23;`;
    const child = spawnWindowsProcess(
      binaryPath,
      process.execPath,
      ["-e", script, ...arguments_],
      {
        cwd,
        env: { ...process.env, INVENTORY_PROCESS_FIXTURE: "inherited" },
        stdio: ["pipe", "pipe", "pipe"],
      },
      { INVENTORY_PROCESS_RAW: "raw-\udfff" },
    );
    const stdout: Buffer[] = [],
      stderr: Buffer[] = [];
    child.stdout!.on("data", (data: Buffer) => stdout.push(data));
    child.stderr!.on("data", (data: Buffer) => stderr.push(data));
    const done = processExit(child, "raw arguments and cwd");
    const bytes = Buffer.concat([
      Buffer.from([0, 255, 128]),
      Buffer.alloc(256 * 1024, 17),
    ]);
    child.stdin!.end(bytes);
    assert.deepEqual(await done, [23, null]);
    assert.deepEqual(Buffer.concat(stdout), bytes);
    const result = JSON.parse(Buffer.concat(stderr).toString("utf8"));
    assert.deepEqual(result.args, arguments_);
    assert.equal(result.argv0, process.execPath);
    assert.equal(result.cwd.toLowerCase(), cwd.toLowerCase());
    assert.equal(result.setting, "inherited");
    assert.equal(result.rawSetting, "raw-\udfff");

    const callerCwd = process.cwd();
    const tools = join(root, "relative-tools");
    mkdirSync(tools);
    copyFileSync(process.execPath, join(tools, "process-probe.exe"));
    copyFileSync(process.execPath, join(tools, "process-probe.com"));
    copyFileSync(process.execPath, join(tools, "process-probe.com.exe"));
    const relativeEnvironment = Object.fromEntries(
      Object.entries(process.env).filter(
        ([name]) =>
          !["PATH", "NODEFAULTCURRENTDIRECTORYINEXEPATH"].includes(
            name.toUpperCase(),
          ),
      ),
    );
    for (const [executable, directory, path, selected] of [
      ["process-probe", cwd, "..\\relative-tools", "process-probe.com"],
      [
        "..\\relative-tools\\process-probe",
        cwd,
        join(root, "absent-tools"),
        "process-probe.com",
      ],
      [
        "..\\relative-tools\\process-probe.",
        cwd,
        join(root, "absent-tools"),
        "process-probe.com",
      ],
      [
        join(tools, "process-probe"),
        cwd,
        join(root, "absent-tools"),
        "process-probe.com",
      ],
      [
        "..\\relative-tools\\process-probe.exe",
        cwd,
        "..\\relative-tools",
        "process-probe.exe",
      ],
      ["process-probe", tools, join(root, "absent-tools"), "process-probe.com"],
      [
        "process-probe.exe",
        tools,
        join(root, "absent-tools"),
        "process-probe.exe",
      ],
      [
        "process-probe.com",
        tools,
        join(root, "absent-tools"),
        "process-probe.com",
      ],
      [
        join(tools, "process-probe.com"),
        cwd,
        join(root, "absent-tools"),
        "process-probe.com",
      ],
    ] as const) {
      const relativeChild = spawnWindowsProcess(
        binaryPath,
        executable,
        ["-e", script, ...arguments_],
        {
          cwd: directory,
          env: {
            ...relativeEnvironment,
            PATH: path,
            INVENTORY_PROCESS_FIXTURE: "relative target",
          },
          stdio: ["pipe", "pipe", "pipe"],
        },
        { INVENTORY_PROCESS_RAW: "raw-\udfff" },
      );
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      relativeChild.stdout!.on("data", (data: Buffer) => output.push(data));
      relativeChild.stderr!.on("data", (data: Buffer) => errors.push(data));
      const completed = processExit(
        relativeChild,
        `lookup ${JSON.stringify(executable)} in ${directory === cwd ? "raw cwd" : "tool cwd"}`,
      );
      relativeChild.stdin!.end(bytes);
      assert.deepEqual(await completed, [23, null]);
      assert.deepEqual(Buffer.concat(output), bytes);
      assert.deepEqual(JSON.parse(Buffer.concat(errors).toString()), {
        args: arguments_,
        argv0: executable,
        cwd: directory,
        executable: join(tools, selected),
        setting: "relative target",
        rawSetting: "raw-\udfff",
      });
      assert.equal(process.cwd(), callerCwd);
    }

    copyFileSync(process.execPath, join(tools, "process-probe.bin"));
    copyFileSync(process.execPath, join(tools, "process-probe.bin.exe"));
    const firstTools = join(root, "first-tools"),
      quotedTools = join(root, "quoted;tools");
    mkdirSync(firstTools);
    mkdirSync(quotedTools);
    copyFileSync(process.execPath, join(firstTools, "process-probe.exe"));
    copyFileSync(process.execPath, join(quotedTools, "process-probe.com"));
    const selectionArgs = [
      "-e",
      "process.stdout.write(JSON.stringify({executable:process.execPath,argv0:process.argv0}))",
    ];
    for (const [executable, path, expected] of [
      [
        "process-probe",
        `"${quotedTools}"`,
        join(quotedTools, "process-probe.com"),
      ],
      [
        "process-probe",
        `'${quotedTools}'`,
        join(quotedTools, "process-probe.com"),
      ],
      [
        "process-probe",
        `${firstTools};${tools}`,
        join(firstTools, "process-probe.exe"),
      ],
      ["process-probe.com", tools, join(tools, "process-probe.com")],
      ["process-probe.exe", tools, join(tools, "process-probe.exe")],
      ["process-probe.", tools, join(tools, "process-probe.com")],
      ["process-probe.bin", tools, join(tools, "process-probe.bin")],
      ...["com", "exe"].map(
        (extension) =>
          [
            `\\\\.\\${join(tools, `process-probe.${extension}`)}\\unused\\..`,
            firstTools,
            `\\\\.\\${join(tools, `process-probe.${extension}`)}`,
          ] as const,
      ),
      [
        ".\\relative-tools\\process-probe.exe",
        firstTools,
        join(tools, "process-probe.exe"),
      ],
      [
        ".\\relative-tools\\process-probe.bin",
        firstTools,
        join(tools, "process-probe.bin"),
      ],
      [
        join(tools, "process-probe.bin"),
        firstTools,
        join(tools, "process-probe.bin"),
      ],
    ] as const) {
      for (const mode of ["node", "native"] as const) {
        const options = {
          cwd: root,
          env: { ...relativeEnvironment, PATH: path },
          stdio: ["ignore", "pipe", "pipe"] as ["ignore", "pipe", "pipe"],
        };
        const selected =
          mode === "node"
            ? spawn(executable, selectionArgs, options)
            : spawnWindowsProcess(
                binaryPath,
                executable,
                selectionArgs,
                options,
              );
        const output: Buffer[] = [],
          diagnostics: Buffer[] = [];
        selected.stdout!.on("data", (chunk: Buffer) => output.push(chunk));
        selected.stderr!.on("data", (chunk: Buffer) => diagnostics.push(chunk));
        assert.deepEqual(
          await processExit(
            selected,
            `${mode} selection ${JSON.stringify(executable)}`,
          ),
          [0, null],
        );
        const actual = JSON.parse(Buffer.concat(output).toString());
        // Node can retain dot components in its reported module filename.
        assert.deepEqual(
          { ...actual, executable: win32.normalize(actual.executable) },
          { executable: expected, argv0: executable },
          `${mode} selection ${JSON.stringify(executable)}`,
        );
        assert.equal(Buffer.concat(diagnostics).toString(), "");
      }
    }

    for (const kind of [
      "directory",
      ...(symlinks ? ["dangling-file", "dangling-directory"] : []),
    ]) {
      const first = join(root, `${kind}-tools`);
      mkdirSync(first);
      const candidate = join(first, "process-probe.exe");
      if (kind === "directory") mkdirSync(candidate);
      else
        symlinkSync(
          join(first, "missing"),
          candidate,
          kind === "dangling-file" ? "file" : "dir",
        );
      for (const mode of ["node", "native"] as const) {
        const options = {
          cwd: root,
          env: { ...relativeEnvironment, PATH: `${first};${tools}` },
          stdio: ["ignore", "pipe", "pipe"] as ["ignore", "pipe", "pipe"],
        };
        const selected =
          mode === "node"
            ? spawn("process-probe", selectionArgs, options)
            : spawnWindowsProcess(
                binaryPath,
                "process-probe",
                selectionArgs,
                options,
              );
        const output: Buffer[] = [],
          diagnostics: Buffer[] = [];
        const errors: Error[] = [];
        selected.stdout!.on("data", (chunk: Buffer) => output.push(chunk));
        selected.stderr!.on("data", (chunk: Buffer) => diagnostics.push(chunk));
        selected.on("error", (error) => errors.push(error));
        const status = await new Promise<number | null>((resolve) =>
          selected.once("close", (code) => resolve(code)),
        );
        if (kind === "dangling-file") {
          assert.equal(
            errors.length,
            1,
            `${mode} must report the first candidate's launch failure`,
          );
          assert.equal(
            Buffer.concat(output).length,
            0,
            "a later PATH image must not run",
          );
        } else {
          assert.deepEqual(errors, []);
          assert.equal(status, 0);
          assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
            executable: join(tools, "process-probe.com"),
            argv0: "process-probe",
          });
        }
        assert.equal(Buffer.concat(diagnostics).length, 0);
      }
    }

    const batchTools = join(root, "batch-tools");
    mkdirSync(batchTools);
    const batchArguments = [
      "value&echo.BATCH_METACHAR",
      'value"&echo.BATCH_QUOTE',
    ];
    const batchOptions = {
      cwd: root,
      env: { ...relativeEnvironment, PATH: batchTools },
      stdio: ["ignore", "pipe", "pipe"] as ["ignore", "pipe", "pipe"],
    };
    async function startupFailure(
      executable: string,
      expectedErrors: number[],
      args = batchArguments,
    ) {
      const child = spawnWindowsProcess(
        binaryPath,
        executable,
        args,
        batchOptions,
      );
      const errors: NodeJS.ErrnoException[] = [];
      const stdout: Buffer[] = [],
        stderr: Buffer[] = [];
      child.on("error", (error) => errors.push(error));
      child.stdout!.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr!.on("data", (chunk: Buffer) => stderr.push(chunk));
      const status = await new Promise<number | null>((resolve) =>
        child.once("close", (code) => resolve(code)),
      );
      assert.equal(status, 127);
      assert.equal(errors.length, 1);
      assert.equal(errors[0]!.code, "WINDOWS_PROCESS_ERROR");
      assert(
        expectedErrors.includes(errors[0]!.errno!),
        `${executable}: ${errors[0]!.message}`,
      );
      assert(errors[0]!.message.length > 0);
      assert.equal(
        Buffer.concat(stdout).length,
        0,
        "neither the batch nor a metacharacter command may run",
      );
      assert.equal(Buffer.concat(stderr).length, 0);
    }
    for (const extension of ["cmd", "bat"] as const) {
      const batch = join(batchTools, `blocked.${extension}`);
      const selected = `${batch}.${extension === "cmd" ? "com" : "exe"}`;
      copyFileSync(process.execPath, selected);
      files.writeFile(
        widePath(batch),
        Buffer.from("@echo off\r\necho BATCH_BODY\r\n"),
      );
      for (const executable of [
        batch,
        `.\\batch-tools\\blocked.${extension}`,
        `blocked.${extension}`,
        join(batchTools, `blocked.${extension.toUpperCase()}`),
        `${batch}. `,
        `${batch}\\.`,
        `${batch}\\unused\\..`,
        `\\\\.\\${batch}`,
        `\\\\.\\${batch}\\.`,
        `\\\\.\\${batch}\\unused\\..`,
        win32.toNamespacedPath(batch),
      ])
        await startupFailure(executable, [87]);
      // Verbatim paths do not resolve the dot segments through a regular file.
      await startupFailure(`${win32.toNamespacedPath(batch)}\\unused\\..`, [2]);
      files.unlink(widePath(batch));
      // Classify the selected image, allowing the existing .com/.exe fallback.
      const image = spawnWindowsProcess(
        binaryPath,
        `blocked.${extension}`,
        selectionArgs,
        batchOptions,
      );
      const output: Buffer[] = [],
        diagnostics: Buffer[] = [];
      image.stdout!.on("data", (chunk: Buffer) => output.push(chunk));
      image.stderr!.on("data", (chunk: Buffer) => diagnostics.push(chunk));
      assert.deepEqual(
        await processExit(image, `batch-name ${extension} image fallback`),
        [0, null],
      );
      assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
        executable: selected,
        argv0: `blocked.${extension}`,
      });
      assert.equal(Buffer.concat(diagnostics).length, 0);
    }
    await startupFailure(join(batchTools, "missing.cmd"), [2]);
    const lockedExecutable = join(batchTools, "locked.exe");
    copyFileSync(process.execPath, lockedExecutable);
    const locked = native.openWindowsFile(
      widePath(win32.toNamespacedPath(lockedExecutable)),
      flags.GENERIC_READ,
      0,
      flags.OPEN_EXISTING,
      flags.FILE_ATTRIBUTE_NORMAL,
    );
    assert.equal(locked.error, 0);
    assert(locked.handle);
    try {
      await startupFailure(lockedExecutable, [5, 32], selectionArgs);
    } finally {
      assert.equal(locked.handle.close(), 0);
    }

    const inheritedPath = process.env["PATH"];
    try {
      process.env["PATH"] = tools;
      const inherited = spawnWindowsProcess(
        binaryPath,
        "process-probe",
        selectionArgs,
        {
          cwd: root,
          env: relativeEnvironment,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      const output: Buffer[] = [];
      inherited.stdout!.on("data", (chunk: Buffer) => output.push(chunk));
      inherited.stderr!.resume();
      assert.deepEqual(
        await processExit(inherited, "omitted PATH inherits caller value"),
        [0, null],
      );
      assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
        executable: join(tools, "process-probe.com"),
        argv0: "process-probe",
      });
    } finally {
      if (inheritedPath === undefined) delete process.env["PATH"];
      else process.env["PATH"] = inheritedPath;
    }

    const executableBytes = readFileSync(process.execPath);
    const rawTools = join(root, "path-tools-\ud800"),
      replacementTools = join(root, "path-tools-�");
    const rawProbe = join(rawTools, "process-probe.exe"),
      replacementProbe = join(replacementTools, "process-probe.exe");
    files.mkdir(widePath(rawTools));
    cleanupPaths.push(rawTools);
    files.mkdir(widePath(replacementTools));
    cleanupPaths.push(replacementTools);
    files.writeFile(widePath(replacementProbe), executableBytes);
    cleanupPaths.push(replacementProbe);
    const callerPath = native.windowsEnvironment(widePath("PATH"));
    const rawPathEnvironment = {
      ...relativeEnvironment,
      PATH: replacementTools,
      NoDefaultCurrentDirectoryInExePath: "1",
    };
    const rawPathSnapshot = { ...rawPathEnvironment };
    for (const available of [false, true]) {
      if (available) {
        files.writeFile(widePath(rawProbe), executableBytes);
        cleanupPaths.push(rawProbe);
      }
      // Model Node's lossy shim PATH separately from the exact target override.
      const pathChild = spawnWindowsProcess(
        binaryPath,
        "process-probe",
        [
          "-e",
          `const native=require(${JSON.stringify(binaryPath)}); process.stdout.write(JSON.stringify({args:native.windowsArguments().slice(3).map(value=>value.toString('utf16le')),path:native.windowsEnvironment(Buffer.from('PATH','utf16le')).toString('utf16le')}));`,
          ...arguments_,
        ],
        {
          cwd,
          env: rawPathEnvironment,
          stdio: ["ignore", "pipe", "pipe"],
        },
        { PATH: rawTools },
      );
      const output: Buffer[] = [],
        diagnostics: Buffer[] = [];
      pathChild.stdout!.on("data", (data: Buffer) => output.push(data));
      pathChild.stderr!.on("data", (data: Buffer) => diagnostics.push(data));
      if (available) {
        assert.deepEqual(
          await processExit(pathChild, "raw PATH collision with target tool"),
          [0, null],
        );
        assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
          args: arguments_,
          path: rawTools,
        });
      } else {
        const errors: NodeJS.ErrnoException[] = [];
        pathChild.on("error", (error) => errors.push(error));
        await new Promise<void>((resolve) =>
          pathChild.once("close", () => resolve()),
        );
        assert.deepEqual(
          errors.map((error) => error.code),
          ["WINDOWS_PROCESS_ERROR"],
          "raw PATH must not fall back to the replacement PATH tool",
        );
        assert.equal(Buffer.concat(output).length, 0);
      }
      assert.equal(Buffer.concat(diagnostics).toString(), "");
      assert.deepEqual(rawPathEnvironment, rawPathSnapshot);
      assert.deepEqual(native.windowsEnvironment(widePath("PATH")), callerPath);
      assert.equal(process.cwd(), callerCwd);
    }

    const longTools = join(
      root,
      ...[0, 1, 2, 3].map((i) => `${i}-${"x".repeat(70)}`),
    );
    files.mkdir(widePath(longTools));
    const rawCom = join(longTools, "program-\udfff.com");
    files.writeFile(widePath(rawCom), executableBytes);
    cleanupPaths.push(rawCom);
    files.writeFile(widePath(`${rawCom}.exe`), executableBytes);
    cleanupPaths.push(`${rawCom}.exe`);
    for (const executable of [rawCom, win32.toNamespacedPath(rawCom)]) {
      const exactChild = spawnWindowsProcess(
        binaryPath,
        executable,
        [
          "-e",
          `const native=require(${JSON.stringify(binaryPath)}); const argv=native.windowsArguments().map(value=>value.toString('utf16le')); process.stdout.write(JSON.stringify({selected:process.execPath.endsWith('.com'),argv0:argv[0],args:argv.slice(3)}));`,
          ...arguments_,
        ],
        { cwd, stdio: ["ignore", "pipe", "pipe"] },
      );
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      exactChild.stdout!.on("data", (data: Buffer) => output.push(data));
      exactChild.stderr!.on("data", (data: Buffer) => errors.push(data));
      assert.deepEqual(
        await processExit(
          exactChild,
          `${executable === rawCom ? "ordinary" : "namespaced"} long raw .com (${executable.length} UTF-16 units)`,
        ),
        [0, null],
      );
      assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
        selected: true,
        argv0: executable,
        args: arguments_,
      });
      assert.equal(Buffer.concat(errors).toString(), "");
    }

    const shimTools = join(root, "shim-tools"),
      absentTools = join(root, "absent-tools");
    mkdirSync(shimTools);
    copyFileSync(process.execPath, join(shimTools, "node.exe"));
    copyFileSync(process.execPath, join(shimTools, "process-probe.exe"));
    for (const overridePath of [undefined, tools, absentTools]) {
      const originalNode = process.execPath;
      let selectedChild: ReturnType<typeof spawnWindowsProcess>;
      try {
        process.execPath = join(shimTools, "node.exe");
        selectedChild = spawnWindowsProcess(
          binaryPath,
          "process-probe",
          [
            "-e",
            "process.stdout.write(JSON.stringify({executable:process.execPath,path:process.env.PATH,setting:process.env.INVENTORY_PROCESS_FIXTURE}));",
          ],
          {
            cwd,
            env: {
              ...relativeEnvironment,
              PATH: overridePath === undefined ? tools : shimTools,
              INVENTORY_PROCESS_FIXTURE: "selected target",
            },
            stdio: ["ignore", "pipe", "pipe"],
          },
          overridePath === undefined ? {} : { Path: overridePath },
        );
      } finally {
        process.execPath = originalNode;
      }
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      selectedChild.stdout!.on("data", (data: Buffer) => output.push(data));
      selectedChild.stderr!.on("data", (data: Buffer) => errors.push(data));
      if (overridePath === absentTools) {
        const errors: NodeJS.ErrnoException[] = [];
        selectedChild.on("error", (error) => errors.push(error));
        await new Promise<void>((resolve) =>
          selectedChild.once("close", () => resolve()),
        );
        assert.deepEqual(
          errors.map((error) => error.code),
          ["WINDOWS_PROCESS_ERROR"],
        );
        assert.equal(
          Buffer.concat(output).length,
          0,
          "missing PATH tool must not resolve beside the shim",
        );
      } else {
        assert.deepEqual(
          await processExit(
            selectedChild,
            `PATH collision (override=${overridePath !== undefined})`,
          ),
          [0, null],
        );
        assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
          executable: join(tools, "process-probe.com"),
          path: tools,
          setting: "selected target",
        });
      }
      assert.equal(Buffer.concat(errors).toString(), "");
    }

    const disabledCwdSearch = spawnWindowsProcess(
      binaryPath,
      "process-probe",
      [],
      {
        cwd: tools,
        env: {
          ...relativeEnvironment,
          PATH: join(root, "absent-tools"),
          NoDefaultCurrentDirectoryInExePath: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const searchErrors: Error[] = [];
    disabledCwdSearch.on("error", (error) => searchErrors.push(error));
    disabledCwdSearch.stdout!.resume();
    disabledCwdSearch.stderr!.resume();
    await new Promise<void>((resolve) =>
      disabledCwdSearch.once("close", () => resolve()),
    );
    assert.equal(searchErrors.length, 1);

    for (const [key, value, override] of [
      ["NODE_DEBUG", "module", undefined],
      ["Node_Debug", "module", undefined],
      ["NODE_DEBUG", "module", "module,net"],
      ["NODE_DEBUG_NATIVE", "code_cache", undefined],
      ["Node_Debug_Native", "code_cache", undefined],
      ["NODE_DEBUG_NATIVE", "code_cache", "async_wrap"],
    ] as const) {
      const env = Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => name.toUpperCase() !== key.toUpperCase(),
        ),
      );
      env[key.toLowerCase()] = "ignored duplicate";
      env[key] = value;
      const snapshot = { ...env };
      const debugChild = spawnWindowsProcess(
        binaryPath,
        process.env["ComSpec"]!,
        ["/d", "/c", `echo %${key}%`],
        { cwd, env, stdio: ["ignore", "pipe", "pipe"] },
        override === undefined ? {} : { [key.toLowerCase()]: override },
      );
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      debugChild.stdout!.on("data", (data: Buffer) => output.push(data));
      debugChild.stderr!.on("data", (data: Buffer) => errors.push(data));
      assert.deepEqual(await processExit(debugChild, `target debug ${key}`), [
        0,
        null,
      ]);
      assert.equal(Buffer.concat(output).toString().trim(), override ?? value);
      assert.equal(Buffer.concat(errors).toString(), "");
      assert.deepEqual(env, snapshot);
    }

    for (const [index, scenario] of [
      { key: "NODE_V8_COVERAGE", value: "coverage" },
      { key: "Node_V8_Coverage", value: "coverage" },
      { key: "NODE_V8_COVERAGE", value: "ignored", override: "coverage" },
      { inherited: "coverage" },
    ].entries()) {
      const caller = join(root, `coverage-caller-${index}`),
        target = join(caller, "target");
      mkdirSync(target, { recursive: true });
      // A separate caller keeps both correct and misplaced coverage inside the fixture.
      const coverageChild = spawn(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `import assert from 'node:assert/strict';
import { spawnWindowsProcess } from ${JSON.stringify(new URL("./windows-process.mjs", import.meta.url).href)};
const scenario = ${JSON.stringify(scenario)};
const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => name.toUpperCase() !== 'NODE_V8_COVERAGE'));
if (scenario.key) env[scenario.key] = scenario.value;
if (scenario.inherited) process.env.NODE_V8_COVERAGE = scenario.inherited;
const snapshot = { ...env };
const child = spawnWindowsProcess(${JSON.stringify(binaryPath)}, process.execPath,
  ['-e', 'process.stdout.write(process.env.NODE_V8_COVERAGE)'],
  { cwd: ${JSON.stringify(target)}, env, stdio: ['ignore', 'pipe', 'pipe'] },
  scenario.override === undefined ? {} : { Node_V8_Coverage: scenario.override });
assert.deepEqual(env, snapshot);
child.stdout.pipe(process.stdout);
child.stderr.pipe(process.stderr);
child.on('error', error => { process.stderr.write(String(error)); process.exitCode = 1; });
child.once('close', code => { process.exitCode = code ?? 1; });`,
        ],
        {
          cwd: caller,
          env: { ...process.env, NODE_V8_COVERAGE: undefined },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      const output: Buffer[] = [],
        diagnostics: Buffer[] = [];
      coverageChild.stdout!.on("data", (chunk: Buffer) => output.push(chunk));
      coverageChild.stderr!.on("data", (chunk: Buffer) =>
        diagnostics.push(chunk),
      );
      assert.deepEqual(
        await processExit(coverageChild, `target coverage ${index}`),
        [0, null],
      );
      assert.equal(Buffer.concat(output).toString(), join(target, "coverage"));
      assert.equal(Buffer.concat(diagnostics).toString(), "");
      assert.deepEqual(readdirSync(caller), ["target"]);
      const reports = readdirSync(join(target, "coverage"));
      assert.equal(reports.length, 1, "only the target writes coverage");
      assert.match(reports[0]!, /^coverage-.*\.json$/u);
      assert.equal(process.cwd(), callerCwd);
    }

    files.writeFile(
      widePath(join(root, "target-certificates.pem")),
      Buffer.from(rootCertificates[0]!),
    );
    for (const [key, inheritedCertificate, override] of [
      ["NODE_EXTRA_CA_CERTS", "target-certificates.pem", undefined],
      ["Node_Extra_Ca_Certs", "target-certificates.pem", undefined],
      [
        "NODE_EXTRA_CA_CERTS",
        "missing-certificates.pem",
        "target-certificates.pem",
      ],
    ] as const) {
      const env = Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => name.toUpperCase() !== "NODE_EXTRA_CA_CERTS",
        ),
      );
      env["node_extra_ca_certs"] = "missing-duplicate.pem";
      env[key] = inheritedCertificate;
      const snapshot = { ...env };
      const certificateChild = spawnWindowsProcess(
        binaryPath,
        process.execPath,
        [
          "-e",
          "process.stdout.write(process.env.NODE_EXTRA_CA_CERTS); process.exitCode=2;",
        ],
        { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] },
        override === undefined ? {} : { Node_Extra_Ca_Certs: override },
      );
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      certificateChild.stdout!.on("data", (data: Buffer) => output.push(data));
      certificateChild.stderr!.on("data", (data: Buffer) => errors.push(data));
      assert.deepEqual(
        await processExit(
          certificateChild,
          `target certificates ${key} (override=${override !== undefined})`,
        ),
        [2, null],
      );
      assert.equal(Buffer.concat(output).toString(), "target-certificates.pem");
      assert.equal(Buffer.concat(errors).toString(), "");
      assert.deepEqual(env, snapshot);
    }

    const moduleOptions = "--input-type=module";
    const moduleChild = spawnWindowsProcess(
      binaryPath,
      process.execPath,
      [
        "-e",
        "import process from 'node:process'; process.stdout.write(process.env.NODE_OPTIONS);",
      ],
      {
        cwd,
        env: { ...process.env, NODE_OPTIONS: moduleOptions },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const moduleOutput: Buffer[] = [];
    moduleChild.stdout!.on("data", (data: Buffer) => moduleOutput.push(data));
    moduleChild.stderr!.resume();
    assert.deepEqual(await processExit(moduleChild, "target module options"), [
      0,
      null,
    ]);
    assert.equal(Buffer.concat(moduleOutput).toString("utf8"), moduleOptions);

    files.writeFile(
      widePath(join(root, "hook.cjs")),
      Buffer.from("process.env.INVENTORY_PRELOAD = 'cjs';"),
    );
    files.writeFile(
      widePath(join(root, "preload.mjs")),
      Buffer.from("process.env.INVENTORY_PRELOAD = 'esm';"),
    );
    for (const [key, nodeOptions, expected, override] of [
      ["NODE_OPTIONS", "--require ./hook.cjs", "cjs", undefined],
      ["Node_Options", "--import=./preload.mjs", "esm", undefined],
      ["NODE_OPTIONS", "--require ./absent.cjs", "cjs", "--require ./hook.cjs"],
    ] as const) {
      const env = Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => name.toUpperCase() !== "NODE_OPTIONS",
        ),
      );
      if (key === "NODE_OPTIONS" && override === undefined)
        env["node_options"] = "--require ./absent.cjs";
      env[key] = nodeOptions;
      const snapshot = { ...env };
      const preloaded = spawnWindowsProcess(
        binaryPath,
        process.execPath,
        [
          "-e",
          "process.stdout.write(JSON.stringify({options:process.env.NODE_OPTIONS,preloaded:process.env.INVENTORY_PRELOAD}));",
        ],
        { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] },
        override === undefined ? {} : { Node_Options: override },
      );
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      preloaded.stdout!.on("data", (data: Buffer) => output.push(data));
      preloaded.stderr!.on("data", (data: Buffer) => errors.push(data));
      assert.deepEqual(
        await processExit(
          preloaded,
          `target preload ${key} (override=${override !== undefined})`,
        ),
        [0, null],
        Buffer.concat(errors).toString(),
      );
      assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
        options: override ?? nodeOptions,
        preloaded: expected,
      });
      assert.deepEqual(env, snapshot);
    }

    for (let attempt = 0; attempt < 3; attempt++) {
      const quick = spawnWindowsProcess(
        binaryPath,
        process.execPath,
        ["-e", "process.exit(19)"],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      assert.deepEqual(await processExit(quick, `quick exit ${attempt}`), [
        19,
        null,
      ]);
    }
    for (const malformed of [Buffer.from([1]), widePath("bad\0value")])
      assert.throws(() =>
        native.runWindowsProcess(widePath(process.execPath), [malformed]),
      );
    const missing = spawnWindowsProcess(
      binaryPath,
      join(cwd, "absent-\udfff.exe"),
      [],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const errors: Error[] = [];
    missing.on("error", (error) => errors.push(error));
    await new Promise<void>((resolve) =>
      missing.once("close", () => resolve()),
    );
    assert.equal(errors.length, 1);
    assert(errors[0]!.message.length > 0);

    const originalExecutable = process.execPath;
    let missingShim: ReturnType<typeof spawnWindowsProcess>;
    try {
      process.execPath = join(root, "absent-node.exe");
      missingShim = spawnWindowsProcess(binaryPath, originalExecutable, [], {
        stdio: ["ignore", "pipe", "pipe"],
      });
    } finally {
      process.execPath = originalExecutable;
    }
    const shimErrors: NodeJS.ErrnoException[] = [];
    missingShim.on("error", (error) => shimErrors.push(error));
    await new Promise<void>((resolve) =>
      missingShim.once("close", () => resolve()),
    );
    assert.deepEqual(
      shimErrors.map((error) => error.code),
      ["ENOENT"],
    );

    for (const mode of ["abort", "kill"] as const) {
      const controller = new AbortController();
      const cancelled = spawnWindowsProcess(binaryPath, process.execPath, [], {
        stdio: ["ignore", "pipe", "pipe"],
        ...(mode === "abort" ? { signal: controller.signal } : {}),
      });
      const errors: NodeJS.ErrnoException[] = [];
      cancelled.on("error", (error) => errors.push(error));
      const closed = new Promise<void>((resolve) =>
        cancelled.once("close", () => resolve()),
      );
      if (mode === "abort") controller.abort();
      else assert.equal(cancelled.kill(), true);
      await closed;
      assert.deepEqual(
        errors.map((error) => error.code),
        mode === "abort" ? ["ABORT_ERR"] : [],
      );
    }

    // Descendant readiness proves that closing the shim also closes every inherited pipe.
    for (const executable of [
      process.execPath,
      join(tools, "process-probe.com"),
    ]) {
      const hanging = spawnWindowsProcess(
        binaryPath,
        executable,
        [
          "-e",
          "require('node:child_process').spawn(process.execPath, ['-e', \"process.stdout.write('ready'); setInterval(()=>{},1000)\"], {stdio:'inherit'}); setInterval(()=>{},1000)",
          "raw-\ud800",
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      const closed = processExit(
        hanging,
        `descendant cancellation ${JSON.stringify(executable)}`,
        {
          signal: AbortSignal.timeout(10_000),
        },
      );
      await once(hanging.stdout!, "data", {
        signal: AbortSignal.timeout(10_000),
      });
      assert.equal(hanging.kill(), true);
      await closed;
      assert(hanging.stdout!.readableEnded);
      assert(hanging.stderr!.readableEnded);
    }
    return {
      wideArgumentsAndCwd: true,
      relativeExecutableAndPathUseTargetCwd: true,
      bareExecutableUsesTargetCwd: true,
      explicitComSelectionAndArgumentQuoting: true,
      pathAndExplicitImageSelectionMatchNode: true,
      originalArgv0Preserved: true,
      executableSymlinkSelectionMatchesNode: symlinks,
      executableDirectoryCandidatesSkipped: true,
      batchImagesRejectedWithoutInterpretingArguments: true,
      batchNamedExecutableFallbackPreserved: true,
      missingAndLockedImageDiagnosticsPreserved: true,
      omittedPathInheritsCallerValue: true,
      longAndNamespacedRawComPaths: true,
      inheritedAndOverriddenPathPrecedeShimDirectory: true,
      rawPathDoesNotFallBackToReplacementTool: true,
      disabledCurrentDirectorySearchPreserved: true,
      inheritedSettingsAndBinaryStreams: true,
      targetDebugSettingsWithoutShimDiagnostics: true,
      targetNativeDebugSettingsWithoutShimDiagnostics: true,
      targetCoverageUsesTargetCwdWithoutShimCoverage: true,
      targetCertificatesWithoutShimDiagnostics: true,
      inheritedModuleModeForTarget: true,
      targetPreloadsAndOverrides: true,
      exitAndSpawnErrors: true,
      failedShimReportsOnce: true,
      earlyCancellationReportsOnce: true,
      killingShimClosesChildStreams: true,
      killingShimClosesComDescendantStreams: true,
    };
  } catch (error) {
    proofError = error;
    throw error;
  } finally {
    const cleanupErrors: unknown[] = [];
    for (const path of cleanupPaths.reverse()) {
      try {
        // Match package-fixture cleanup: exited Windows images can remain delete-pending.
        for (let attempt = 0; ; attempt++) {
          try {
            files.unlink(widePath(path));
            break;
          } catch (error) {
            if (
              ![5, 32, 145].includes(
                (error as { winerror: number }).winerror,
              ) ||
              attempt === 10
            )
              throw error;
            await delay(100 * (attempt + 1));
          }
        }
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length)
      throw new AggregateError(
        proofError === undefined
          ? cleanupErrors
          : [proofError, ...cleanupErrors],
        "Windows process proof fixture cleanup failed",
      );
  }
}
