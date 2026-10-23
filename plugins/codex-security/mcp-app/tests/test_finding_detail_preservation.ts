import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { finding } from "./scan-draft-fixture.ts";

const { parseCurrentFindings } = await importSource(
  "src/artifact-scan-draft.ts",
);
const { preserveFindingDetails } = await importSource(
  fileURLToPath(
    new URL(
      "../../../../sdk/typescript/src/scan-semantics.ts",
      import.meta.url,
    ),
  ),
);

function parsedFinding(auditJson: string) {
  return parseCurrentFindings([
    {
      ...finding("saved-detail", "src/example.ts"),
      extensions: { audit: JSON.parse(auditJson) },
    },
  ])[0];
}

for (const auditJson of [
  '{"__proto__":{}}',
  '{"__proto__":{"__proto__":null}}',
]) {
  test(`retains missing own JSON detail ${auditJson}`, () => {
    const previous = parsedFinding(auditJson);
    const current = parsedFinding("{}");
    const previousBefore = structuredClone(previous);
    assert.equal(Object.hasOwn(previous.extensions.audit, "__proto__"), true);
    assert.equal(Object.hasOwn(current.extensions.audit, "__proto__"), false);

    preserveFindingDetails(current, previous);

    assert.deepEqual(current.provenance.previousFindings, [previousBefore]);
    assert.deepEqual(current.extensions.audit, {});
    assert.deepEqual(previous, previousBefore);
    assert.deepEqual(JSON.parse(JSON.stringify(current)), current);

    const retained = structuredClone(current);
    preserveFindingDetails(current, previous);
    assert.deepEqual(current, retained);
  });
}

for (const [previousJson, currentJson] of [
  ['{"__proto__":{}}', '{"__proto__":{}}'],
  ['{"__proto__":{"__proto__":null}}', '{"__proto__":{"__proto__":null}}'],
  [
    '{"proof":{"kind":"source"},"metadata":{}}',
    '{"proof":{"kind":"source","line":7},"metadata":{"revision":2},"extra":true}',
  ],
  [
    '{"items":[{"kind":"source"},{"kind":"source"},"reviewed"]}',
    '{"items":["extra","reviewed",{"kind":"source","line":7}]}',
  ],
  ['{"note":null}', '{"note":null}'],
]) {
  test(`accepts retained JSON detail ${previousJson}`, () => {
    const previous = parsedFinding(previousJson);
    const current = parsedFinding(currentJson);
    const previousBefore = structuredClone(previous);
    const currentBefore = structuredClone(current);

    preserveFindingDetails(current, previous);

    assert.deepEqual(current, currentBefore);
    assert.deepEqual(previous, previousBefore);
  });
}

test("retains a missing null-valued member", () => {
  const previous = parsedFinding('{"note":null}');
  const current = parsedFinding("{}");

  preserveFindingDetails(current, previous);

  assert.deepEqual(current.provenance.previousFindings, [previous]);
});
