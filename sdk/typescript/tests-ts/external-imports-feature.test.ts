import { expect, test } from "bun:test";
import { externalImportsEnabled } from "../src/external-imports-feature.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const flag = "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS";
const mixed = "Codex_Security_Enable_External_Imports";
const lower = flag.toLowerCase();

test.each([undefined, "", "0", "true", " 1 ", "1"])(
  "requires exact opt-in for %p",
  (value) => {
    expect(externalImportsEnabled({ [flag]: value })).toBe(value === "1");
  },
);

test("resolves mixed-case and inherited settings on the host platform", () => {
  const windows = process.platform === "win32";
  for (const [environment, expected] of [
    [{ [mixed]: "1" }, windows],
    [{ [mixed]: "0" }, false],
    [{ [mixed]: "true" }, false],
    [{ [mixed]: "1", [flag]: undefined }, false],
    [{ [lower]: "1", [mixed]: "0" }, false],
    [{ [lower]: "0", [mixed]: "1" }, windows],
    [Object.create({ [flag]: "1" }), true],
    [Object.assign(Object.create({ [flag]: "0" }), { [mixed]: "1" }), false],
    [Object.defineProperty({}, flag, { value: "1" }), true],
    [Object.defineProperty({ [lower]: "1" }, flag, { value: "0" }), false],
    [
      Object.defineProperty({ [lower]: "1" }, flag, { value: undefined }),
      windows,
    ],
    [{}, false],
  ] as const) {
    expect(externalImportsEnabled(environment)).toBe(expected);
  }
});

const overlay = "prefers a caller's own Windows setting over process.env";
test.skipIf(process.platform !== "win32")(overlay, () => {
  if (runTestInSubprocess(import.meta.path, overlay)) return;
  for (const name of Object.keys(process.env))
    if (name.toUpperCase() === flag) delete process.env[name];
  for (const host of [flag, mixed, lower]) {
    for (const own of ["0", "1"]) {
      process.env[host] = own === "0" ? "1" : "0";
      const environment = Object.create(process.env, {
        [mixed]: { value: own, enumerable: true },
      });
      expect(externalImportsEnabled(environment)).toBe(own === "1");
    }
    delete process.env[host];
  }
});
