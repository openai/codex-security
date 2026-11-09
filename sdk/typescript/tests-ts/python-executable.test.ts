import { afterEach, expect, spyOn, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { copyFile, readFile, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { PLUGIN_PYTHON_PROBE } from "../src/plugin-python-probe.js";
import * as pythonProbe from "./support/python-probe.js";
import { useTestPython } from "./support/python.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const pythonExecutable = useTestPython();
const pythonOnPath = useTestPython(false);
const directories = createTemporaryDirectories(true);
afterEach(directories.cleanup);

test.skipIf(process.platform !== "win32")(
  "prepares slow PATH discovery outside the test deadline and bypasses it for an override",
  async () => {
    const root = await directories.create("codex-security-python-discovery-");
    const python = pythonExecutable()!;
    const venv = join(root, "venv");
    const created = pythonProbe.runNodePython(python, [
      "-m",
      "venv",
      "--without-pip",
      "--system-site-packages",
      venv,
    ]);
    expect(created.status, created.stderr).toBe(0);
    const bin = join(venv, "Scripts");
    const fallback = join(bin, "python3.exe");
    await copyFile(join(bin, "python.exe"), fallback);
    const marker = join(root, "probes.txt");
    await writeFile(
      join(venv, "Lib", "site-packages", "sitecustomize.py"),
      [
        "import os, sys, time",
        "from pathlib import Path",
        "if Path(sys.executable).name.lower() == 'python.exe':",
        "    with open(os.environ['PYTHON_FIXTURE_MARKER'], 'a', encoding='utf-8') as record: record.write('probe\\n')",
        "    time.sleep(1.5)",
        "    os._exit(49)",
      ].join("\n"),
    );
    const fixture = join(root, "python.test.ts");
    const helper = new URL("./support/python.ts", import.meta.url).href;
    await writeFile(
      fixture,
      [
        'import { expect, test } from "bun:test";',
        `import { useTestPython } from ${JSON.stringify(helper)};`,
        "const resolve = useTestPython();",
        'test("uses the prepared Python", () => {',
        "  expect(resolve()).toBe(process.env.EXPECTED_PYTHON);",
        "  if (!process.env.PYTHON) {",
        "    const path = process.env.PATH;",
        "    process.env.PATH = process.cwd();",
        "    expect(resolve()).toBeNull();",
        "    process.env.PATH = path;",
        "    expect(resolve()).toBe(process.env.EXPECTED_PYTHON);",
        "  }",
        "});",
      ].join("\n"),
    );
    for (const configured of [python, ""]) {
      const result = spawnSync(
        process.execPath,
        ["test", "--timeout", "300", fixture],
        {
          cwd: root,
          env: {
            ...process.env,
            PATH: [bin, process.env["PATH"]].join(delimiter),
            PYTHON: configured,
            EXPECTED_PYTHON: configured || fallback,
            PYTHON_FIXTURE_MARKER: marker,
          },
          encoding: "utf8",
          windowsHide: true,
        },
      );
      expect(result.status, result.stderr).toBe(0);
      if (configured) expect(await Bun.file(marker).exists()).toBe(false);
    }
    expect((await readFile(marker, "utf8")).split(/\r?\n/u)).toEqual([
      "probe",
      "",
    ]);
  },
);

test("uses a configured Python executable and discovers one for an empty override", () => {
  const previous = process.env["PYTHON"];
  try {
    const discovered = pythonOnPath();
    process.env["PYTHON"] = "";
    expect(pythonExecutable()).toBe(discovered);
    process.env["PYTHON"] = "  synthetic python  ";
    expect(pythonExecutable()).toBe("synthetic python");
    expect(pythonOnPath()).toBe(discovered);
  } finally {
    if (previous === undefined) delete process.env["PYTHON"];
    else process.env["PYTHON"] = previous;
  }
});

test.skipIf(process.platform !== "win32")(
  "falls back to the Python launcher after a timeout and an unusable Windows alias",
  () => {
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    using _which = spyOn(Bun, "which").mockImplementation((name) =>
      name === "py" ? python : process.execPath,
    );
    using probes = spyOn(pythonProbe, "runNodePython").mockReturnValueOnce({
      pid: 0,
      output: [],
      stdout: "",
      stderr: "",
      signal: "SIGTERM",
      status: null,
      error: Object.assign(new Error("Timed out"), { code: "ETIMEDOUT" }),
    });
    expect(pythonOnPath()).toBe(python);
    expect(probes.mock.calls.map((call) => call[2]?.timeout)).toEqual([
      30_000, 30_000, 30_000,
    ]);
  },
);

test("the Python probe rejects unsupported versions and checks tomli on Python 3.10", () => {
  const python = pythonExecutable();
  expect(python).not.toBeNull();
  for (const [minor, tomli, status] of [
    [9, true, 1],
    [10, false, 1],
    [10, true, 0],
    [11, false, 0],
  ] as const) {
    const program = [
      "import importlib.util, sys",
      `sys.version_info = (3, ${minor})`,
      `importlib.util.find_spec = lambda name: object() if name == 'tomli' and ${tomli ? "True" : "False"} else None`,
      PLUGIN_PYTHON_PROBE,
    ].join("\n");
    expect(pythonProbe.runPython(python!, ["-c", program]).exitCode).toBe(
      status,
    );
  }
});
