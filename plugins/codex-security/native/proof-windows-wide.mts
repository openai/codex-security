import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { output } from "./binding.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

const self = fileURLToPath(import.meta.url);

export function wideProcessProof(root: string): Record<string, boolean> {
  const child = spawnSync(
    join(output, "windows-wide-launcher.exe"),
    [process.execPath, self, root],
    { encoding: "utf8", maxBuffer: Infinity, timeout: 30_000 },
  );
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, "");
  return JSON.parse(child.stdout) as Record<string, boolean>;
}

function worker(root: string): Record<string, boolean> {
  const native = loadWindowsBinding();
  const files = windowsFileSystem(native);
  const cwd = win32.join(root, "cwd-\ud800");
  const expectedArguments = [
    "arg-high-\ud800",
    "arg-low-\udc80",
    "arg-tail-\udfff",
    "replacement-\ufffd",
    "Unicode 🔐 東京",
    "",
    "space and\ttab",
    'quoted "value" and trailing\\',
    'backslash\\"quote',
  ];
  const arguments_ = native.windowsArguments().map(pathText);
  assert.deepEqual(arguments_.slice(4), expectedArguments);
  assert.equal(arguments_[2], "wide-worker");
  assert.equal(arguments_[3], root);

  function environment(name: string): Buffer | null {
    return native.windowsEnvironment(widePath(name));
  }
  assert.deepEqual(
    environment("CODEX_SECURITY_WIDE_VALUE"),
    widePath("value-\ud800"),
  );
  assert.deepEqual(environment("CODEX_SECURITY_WIDE_EMPTY"), Buffer.alloc(0));
  assert.equal(environment("CODEX_SECURITY_WIDE_ABSENT"), null);
  assert.deepEqual(
    environment("CODEX_SECURITY_WIDE_NAME_\udfff"),
    widePath("wide name value"),
  );
  assert.deepEqual(
    environment("CODEX_SECURITY_WIDE_LONG"),
    widePath("x".repeat(1024)),
  );
  assert.deepEqual(environment("USERPROFILE"), widePath(cwd));

  function samePath(actual: Buffer, expected: string): void {
    assert.equal(
      win32.toNamespacedPath(pathText(actual)).toLowerCase(),
      win32.toNamespacedPath(expected).toLowerCase(),
    );
  }
  samePath(files.absolute(widePath(".")), cwd);
  samePath(
    files.absolute(widePath("missing/../high-\ud800")),
    win32.join(cwd, "high-\ud800"),
  );
  samePath(files.absolute(widePath(cwd)), cwd);
  const emptyAbsolute = native.windowsAbsolutePath(Buffer.alloc(0));
  assert(Number.isInteger(emptyAbsolute.error));
  assert.deepEqual(emptyAbsolute.value, Buffer.alloc(0));
  const drive = win32.parse(cwd).root.slice(0, 2);
  assert.match(drive, /^[a-z]:$/iu);
  samePath(
    files.absolute(widePath(`${drive}high-\ud800`)),
    win32.join(cwd, "high-\ud800"),
  );
  samePath(
    files.absolute(widePath("\\rooted-\ud800")),
    `${drive}\\rooted-\ud800`,
  );
  samePath(files.realpath(widePath(".")), cwd);

  const names = [
    "high-\ud800",
    "high-\ufffd",
    "low-\udc80",
    "low-\ufffd",
    "tail-\udfff",
    "tail-\ufffd",
    "unicode-🔐-東京",
  ];
  const listed = files.entriesWithTypes(widePath("."));
  assert.deepEqual(
    listed.map((entry) => pathText(entry.name)).sort(),
    [
      ...names,
      "empty",
      "trailing",
      "trailing.",
      "space",
      "space ",
      "directory-\udc80",
      "file-link",
      "directory-link",
      "dangling-directory-link",
      "locked-\udfff",
    ].sort(),
  );
  for (const spelling of [".", `${drive}.`, cwd, win32.toNamespacedPath(cwd)]) {
    const result = native.windowsDirectoryEntries(widePath(spelling));
    assert.equal(result.error, 0);
    assert.deepEqual(
      result.value.map((entry) => pathText(entry.name)).sort(),
      listed.map((entry) => pathText(entry.name)).sort(),
    );
  }
  const directories = listed
    .filter((entry) => entry.isDirectory())
    .map((entry) => pathText(entry.name))
    .sort();
  assert.deepEqual(directories, [
    "dangling-directory-link",
    "directory-link",
    "directory-\udc80",
    "empty",
  ]);
  assert.deepEqual(
    listed
      .filter((entry) => entry.isSymbolicLink())
      .map((entry) => pathText(entry.name))
      .sort(),
    ["dangling-directory-link", "directory-link", "file-link"],
  );
  assert.throws(
    () => files.readInto(widePath("locked-\udfff"), Buffer.alloc(1)),
    { winerror: 32 },
  );
  assert.equal(
    listed
      .find((entry) => entry.name.equals(widePath("locked-\udfff")))
      ?.isDirectory(),
    false,
  );
  assert.deepEqual(native.windowsDirectoryEntries(widePath("empty")), {
    error: 0,
    value: [],
  });
  assert.deepEqual(native.windowsDirectoryEntries(widePath("missing")), {
    error: 3,
    value: [],
  });
  assert.deepEqual(native.windowsDirectoryEntries(Buffer.alloc(0)), {
    error: 3,
    value: [],
  });
  const notDirectory = native.windowsDirectoryEntries(widePath(names[0]!));
  assert.notEqual(notDirectory.error, 0);
  assert(Number.isInteger(notDirectory.error));
  assert.deepEqual(notDirectory.value, []);
  for (const [index, name] of names.entries()) {
    const buffer = Buffer.alloc(64);
    const length = files.readInto(widePath(name), buffer);
    assert.equal(buffer.subarray(0, length).toString(), `sentinel-${index}`);
    assert(files.stat(widePath(name)).isFile());
    assert(!files.stat(widePath(name), false).isSymbolicLink());
    samePath(files.realpath(widePath(name)), win32.join(cwd, name));
    for (const input of [
      `${name}/`,
      `${name}\\`,
      `${drive}${name}/`,
      `${win32.join(cwd, name)}\\`,
    ]) {
      samePath(files.realpath(widePath(input)), win32.join(cwd, name));
    }
  }
  samePath(files.realpath(widePath(`${drive}///`)), `${drive}\\`);
  samePath(
    files.realpath(widePath(`${drive}.\\..\\parent-\ud800`)),
    win32.join(root, "parent-\ud800"),
  );
  assert(files.stat(widePath(".")).isDirectory());
  const bounded = Buffer.alloc(4);
  assert.equal(files.readInto(widePath(names[0]!), bounded), 4);
  assert.equal(bounded.toString(), "sent");

  const rawOutput = widePath("output-\ud800");
  const replacementOutput = widePath("output-\ufffd");
  files.writeFile(
    replacementOutput,
    Buffer.from("replacement output untouched"),
  );
  files.writeFile(rawOutput, Buffer.from("a longer initial output"));
  files.writeFile(rawOutput, Buffer.from("short"));
  const contents = Buffer.alloc(64);
  assert.equal(files.readInto(rawOutput, contents), 5);
  assert.equal(contents.subarray(0, 5).toString(), "short");
  files.writeFile(rawOutput, Buffer.alloc(0));
  assert.equal(files.readInto(rawOutput, contents), 0);
  const replacementLength = files.readInto(replacementOutput, contents);
  assert.equal(
    contents.subarray(0, replacementLength).toString(),
    "replacement output untouched",
  );

  for (const [name, literal, ordinary] of [
    ["trailing.", "literal dot file", "ordinary dot sibling"],
    ["space ", "literal space file", "ordinary space sibling"],
  ] as const) {
    const exact = widePath(win32.toNamespacedPath(win32.join(cwd, name)));
    assert.deepEqual(files.absolute(exact), exact);
    const length = files.readInto(exact, contents);
    assert.equal(contents.subarray(0, length).toString(), literal);
    samePath(files.realpath(exact), pathText(exact));
    files.writeFile(exact, Buffer.from("updated literal file"));
    const ordinaryLength = files.readInto(
      widePath(name.slice(0, -1)),
      contents,
    );
    assert.equal(contents.subarray(0, ordinaryLength).toString(), ordinary);
    const directory = widePath(
      win32.toNamespacedPath(win32.join(cwd, `directory-${name}`)),
    );
    files.mkdir(directory);
    files.writeFile(
      widePath(`${pathText(directory)}\\child`),
      Buffer.from("literal directory"),
    );
    assert.deepEqual(
      files.entriesWithTypes(directory).map((entry) => pathText(entry.name)),
      ["child"],
    );
    const ordinaryDirectory = widePath(
      win32.join(cwd, `directory-${name.slice(0, -1)}`),
    );
    files.mkdir(ordinaryDirectory);
    assert.deepEqual(files.entriesWithTypes(ordinaryDirectory), []);
  }

  const longDirectory = win32.join(
    cwd,
    ...Array.from({ length: 6 }, (_, i) => `${i}-${"x".repeat(48)}`),
    "directory-\udfff",
  );
  assert(files.absolute(widePath(longDirectory)).length > 512);
  files.mkdir(widePath(longDirectory));
  files.mkdir(widePath(longDirectory));
  assert(files.stat(widePath(longDirectory)).isDirectory());
  const longFile = widePath(win32.join(longDirectory, "file-\udc80"));
  files.writeFile(longFile, Buffer.from("long raw path"));
  const longLength = files.readInto(longFile, contents);
  assert.equal(contents.subarray(0, longLength).toString(), "long raw path");
  samePath(files.realpath(longFile), pathText(longFile));
  const longEntries = native.windowsDirectoryEntries(widePath(longDirectory));
  assert.equal(longEntries.error, 0);
  assert.deepEqual(
    longEntries.value.map((entry) => pathText(entry.name)),
    ["file-\udc80"],
  );

  for (const malformed of [Buffer.from([0x61]), widePath("bad\0value")]) {
    assert.throws(() => native.windowsEnvironment(malformed));
    assert.throws(() => native.windowsAbsolutePath(malformed));
    assert.throws(() => native.windowsDirectoryEntries(malformed));
  }
  return {
    rawArgumentsAndCrtQuoting: true,
    rawEnvironmentEmptyAndUnset: true,
    rawCwdAndDriveRelativePaths: true,
    completeWideDirectoryIteration: true,
    cachedDirectoryAttributesWithoutFileAccess: true,
    cachedSymlinkTagsIncludingDanglingDirectories: true,
    existingFilesWithTrailingSeparators: true,
    distinctRawAndReplacementFiles: true,
    canonicalPathsBoundedReadsAndTruncation: true,
    verbatimTrailingDotsAndSpaces: true,
    recursiveLongWideDirectories: true,
    numericErrorsAndFfiRepresentations: true,
  };
}

if (process.argv[2] === "wide-worker")
  console.log(JSON.stringify(worker(process.argv[3]!)));
