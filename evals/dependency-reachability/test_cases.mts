import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { cases, type ReachabilityCase } from "./cases.mts";

function scenario(id: string) {
  const item = cases.find((entry) => entry.id === id);
  assert.ok(item, `missing scenario ${id}`);
  return item;
}

function overlay(item: ReachabilityCase, destination: string) {
  const file = item.stage.find((entry) => entry.destination === destination);
  assert.ok(file, `missing ${destination} in ${item.id}`);
  return file;
}

test("each case and each fetched overlay has a stable identity", () => {
  assert.equal(new Set(cases.map(({ id }) => id)).size, cases.length);
  for (const item of cases) {
    assert.match(item.revision, /^[a-f0-9]{40}$/u, item.id);
    const targets = item.stage.map(({ destination }) => destination);
    assert.equal(new Set(targets).size, targets.length, item.id);
    for (const file of item.stage) {
      if (file.kind === "git") assert.match(file.revision, /^[a-f0-9]{40}$/u);
    }
  }
});

test("local evidence anchors match each case's staged fixtures and JSON", async () => {
  const destinations = new Set(
    cases.flatMap((c) =>
      c.stage.filter((f) => f.kind !== "git").map((f) => f.destination),
    ),
  );
  for (const item of cases) {
    for (const anchor of item.evidenceGroups.flat()) {
      if (!destinations.has(anchor.path)) continue;
      const file = overlay(item, anchor.path);
      assert.ok(file.kind !== "git");
      const source =
        file.kind === "fixture"
          ? await readFile(new URL(file.source, import.meta.url), "utf8")
          : JSON.stringify(file.value, null, 2);
      assert.ok(
        anchor.contains && source.includes(anchor.contains),
        `${item.id}: ${anchor.path} (${anchor.contains})`,
      );
    }
  }
});

for (const [exploitable, ruledOut, path, vulnerableValue, safeValue] of [
  [
    "archive-east",
    "archive-west",
    "service/archive.json",
    "archive=3Dpart",
    "archive=_part",
  ],
  [
    "archive-worker-pinned-original",
    "archive-worker-pinned-normalized",
    "archive/stack.json",
    "Enabled",
    "Suspended",
  ],
  [
    "thumbnail-green",
    "thumbnail-blue",
    "edge/caddy.json",
    "127.0.0.1:9101",
    "127.0.0.1:9100",
  ],
]) {
  test(`${exploitable} and ${ruledOut} differ by exactly one deployment value`, () => {
    const positive = scenario(exploitable);
    const negative = scenario(ruledOut);
    assert.equal(positive.question, negative.question);
    assert.equal(positive.repository, negative.repository);
    assert.equal(positive.revision, negative.revision);
    assert.equal(positive.version, negative.version);
    assert.equal(positive.verdict, "exploitable");
    assert.equal(negative.verdict, "ruled_out");
    const before = overlay(positive, path);
    const after = overlay(negative, path);
    assert.ok(before.kind === "json" && after.kind === "json");
    const encoded = JSON.stringify(before.value);
    assert.ok(encoded.includes(JSON.stringify(vulnerableValue)));
    assert.deepEqual(
      JSON.parse(
        encoded.replace(
          JSON.stringify(vulnerableValue),
          JSON.stringify(safeValue),
        ),
      ),
      after.value,
    );
    assert.deepEqual(
      positive.stage.filter((file) => file !== before),
      negative.stage.filter((file) => file !== after),
    );
  });
}

test("Pillow independently varies the release and the calling operation", () => {
  const decode = scenario("affected-decode");
  const fixed = scenario("fixed-decode");
  const encode = scenario("affected-encode-only");
  assert.equal(fixed.question, decode.question);
  assert.notEqual(fixed.revision, decode.revision);
  assert.notEqual(fixed.version, decode.version);
  assert.notDeepEqual(fixed.stage, decode.stage);
  assert.equal(encode.revision, decode.revision);
  assert.equal(encode.version, decode.version);
  assert.deepEqual(encode.stage, decode.stage);
  assert.notEqual(encode.question, decode.question);
  assert.equal(decode.verdict, "exploitable");
  assert.equal(fixed.verdict, "ruled_out");
  assert.equal(encode.verdict, "ruled_out");
});

test("the two ZIP imports differ only in their deployed catalog", () => {
  const first = scenario("zip-import-alpha");
  const second = scenario("zip-import-beta");
  assert.equal(first.question, second.question);
  assert.deepEqual(
    [first.verdict, second.verdict],
    ["exploitable", "ruled_out"],
  );
  const catalog = "bundle/catalog.py";
  assert.notDeepEqual(overlay(first, catalog), overlay(second, catalog));
  assert.deepEqual(
    first.stage.filter((file) => file.destination !== catalog),
    second.stage.filter((file) => file.destination !== catalog),
  );
});

test("the backport changes only the installed address parser, keeping the vulnerable package version", () => {
  const raw = scenario("address-groups");
  const patched = scenario("address-backport");
  assert.equal(raw.revision, patched.revision);
  assert.equal(raw.question, patched.question);
  assert.equal(raw.version, patched.version);
  assert.equal(raw.verdict, "exploitable");
  assert.equal(patched.verdict, "ruled_out");
  const path = "node_modules/nodemailer/lib/addressparser/index.js";
  const before = overlay(raw, path);
  const after = overlay(patched, path);
  assert.ok(before.kind === "git" && after.kind === "git");
  assert.notEqual(before.revision, after.revision);
  assert.deepEqual({ ...after, revision: before.revision }, before);
  assert.deepEqual(
    raw.stage.filter((x) => x !== before),
    patched.stage.filter((x) => x !== after),
  );
  const metadata = overlay(patched, "node_modules/nodemailer/package.json");
  assert.ok(metadata.kind === "git");
  assert.equal(metadata.revision, before.revision);
});

test("unknown remote processing cannot be proved by citing the available local worker", () => {
  const local = scenario("queued-links");
  const remote = scenario("external-worker");
  assert.equal(local.question, remote.question);
  assert.equal(local.revision, remote.revision);
  assert.equal(local.version, remote.version);
  assert.equal(local.verdict, "exploitable");
  assert.equal(remote.verdict, "unknown");
  const worker = "service/worker.cjs";
  assert.ok(
    local.evidenceGroups.some(
      (g) => g.length > 0 && g.every((e) => e.path === worker),
    ),
  );
  assert.ok(!remote.evidenceGroups.flat().some((e) => e.path === worker));
  assert.ok(
    remote.evidenceGroups
      .flat()
      .some(
        (e) =>
          e.path === "service/server.cjs" && e.contains?.includes("fetch("),
      ),
  );
});
