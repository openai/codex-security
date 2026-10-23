import assert from "node:assert/strict";
import { test } from "node:test";
import { importModule } from "./import-module.ts";

test("bundled test errors preserve diagnostics without copying the module into stacks", async () => {
  const payload = "large bundled fixture ".repeat(10_000);
  const module = await importModule({
    stdin: {
      contents: `
        export const payload = ${JSON.stringify(payload)};
        export function fail() {
          throw new Error("Synthetic failure token=SYNTHETIC_DIAGNOSTIC_VALUE");
        }
      `,
    },
  });
  assert.equal(module.payload, payload);
  assert.throws(module.fail, (error: Error) => {
    assert.equal(
      error.message,
      "Synthetic failure token=SYNTHETIC_DIAGNOSTIC_VALUE",
    );
    assert.match(error.stack!, /file:\/\/.*\.mjs:\d+:\d+/);
    assert.doesNotMatch(error.stack!, /data:text\/javascript;base64,/);
    assert.ok(!error.stack!.includes(payload));
    return true;
  });
});

test("identical test bundles retain their module identity", async () => {
  const options = {
    stdin: { contents: "export const state = { count: 0 };" },
  };
  const [first, second] = await Promise.all([
    importModule(options),
    importModule(options),
  ]);
  first.state.count++;
  assert.equal(first, second);
  assert.equal(second.state.count, 1);
});

test("different build options keep test module state isolated", async () => {
  const options = {
    stdin: { contents: "export const state = { value: FIXTURE_VALUE };" },
  };
  const first = await importModule({
    ...options,
    define: { FIXTURE_VALUE: '"first"' },
  });
  const second = await importModule({
    ...options,
    define: { FIXTURE_VALUE: '"second"' },
  });
  assert.equal(first.state.value, "first");
  assert.equal(second.state.value, "second");
  assert.notEqual(first, second);
});
