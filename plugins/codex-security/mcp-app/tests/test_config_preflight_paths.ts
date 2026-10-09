import assert from "node:assert/strict";
import { test } from "node:test";
import { importSource } from "./import-module.ts";

const { projectAncestors } = (await importSource(
  "src/helpers/config-preflight.ts",
  { define: { "process.platform": '"win32"' } },
)) as typeof import("../src/helpers/config-preflight.ts");
const { windowsJoin } = (await importSource(
  "src/helpers/resolve-security-md.ts",
  { define: { "process.platform": '"win32"' } },
)) as typeof import("../src/helpers/resolve-security-md.ts");

test("Windows project discovery stops at ordinary and extended share roots", () => {
  for (const prefix of ["\\\\", "\\\\?\\UNC\\"]) {
    const share = `${prefix}server\\share`;
    const ancestors = [...projectAncestors(`${share}\\folder\\child`)];
    assert.deepEqual(ancestors, [
      `${share}\\folder\\child`,
      `${share}\\folder`,
      `${share}\\`,
    ]);
    assert.deepEqual([...projectAncestors(`${share}\\`)], [`${share}\\`]);
  }
});

test("Windows project discovery retains drive roots and raw path units", () => {
  for (const root of ["C:\\", "\\\\?\\C:\\"]) {
    assert.deepEqual(
      [...projectAncestors(`${root}folder-\udfff\\child`)],
      [`${root}folder-\udfff\\child`, `${root}folder-\udfff`, root],
    );
  }
});

test("root-relative project markers retain the candidate drive or share", () => {
  for (const root of [
    "D:\\",
    "\\\\server\\share\\",
    "\\\\?\\UNC\\server\\share\\",
  ]) {
    const marker = windowsJoin(`${root}repo\\child`, "\\marker");
    assert.equal(marker, root.replace("\\\\?\\UNC\\", "\\\\") + "marker");
  }
  assert.equal(
    windowsJoin("D:\\repo\\child", "D:marker"),
    "D:\\repo\\child\\marker",
  );
  assert.equal(windowsJoin("D:\\repo\\child", "C:\\marker"), "C:\\marker");
});
