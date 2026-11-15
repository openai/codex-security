import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { cases, type ReachabilityCase } from "./cases.mts";
import { gradeAnswer, type ReachabilityAnswer } from "./grade.mts";

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
    assert.match(item.cve, /^CVE-\d{4}-\d{4,}$/u, item.id);
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

test("task catalog evidence can omit unrelated authentication and use split citations", async (t) => {
  const item = scenario("task-parameter");
  const path = "portal/app-config.yaml";
  const file = overlay(item, path);
  assert.ok(file.kind === "fixture");
  const source = await readFile(new URL(file.source, import.meta.url), "utf8");
  const lines = source.trimEnd().split(/\r?\n/u);
  const start = lines.indexOf("catalog:") + 1;
  const target = lines.findIndex((line) => line.includes("target:")) + 1;
  const end = lines.length;
  assert.ok(start > 1 && target > start);

  const root = await mkdtemp(join(tmpdir(), "catalog-evidence-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "portal"));
  await writeFile(join(root, path), source);
  const expected = {
    verdict: "ruled_out" as const,
    version: item.version,
    evidenceGroups: item.evidenceGroups.filter((group) =>
      group.some((anchor) => anchor.path === path),
    ),
  };
  assert.ok(expected.evidenceGroups.length);
  const answer = (
    ranges: readonly (readonly [number, number])[],
  ): ReachabilityAnswer => ({
    verdict: "ruled_out",
    dependency_version: item.version,
    reason:
      "The configured catalog is read-only and selects the fixed template.",
    evidence: ranges.map(([startLine, endLine]) => ({
      path,
      startLine,
      endLine,
      code: lines.slice(startLine - 1, endLine).join("\n"),
    })),
  });
  for (const ranges of [
    [[start, end]],
    [
      [start, start + 2],
      [start + 3, end],
    ],
    [
      [start + 2, end],
      [start, start + 2],
    ],
  ] as const) {
    assert.equal(
      (await gradeAnswer(answer(ranges), expected, root)).pass,
      true,
    );
  }
  for (const ranges of [
    [[start + 1, start + 1]],
    [
      [start, target - 1],
      [target + 1, end],
    ],
    [[1, start - 2]],
  ] as const) {
    assert.equal(
      (await gradeAnswer(answer(ranges), expected, root)).pass,
      false,
    );
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
    assert.equal(positive.verdict, "potentially_exploitable");
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

test("archive worker variants use the same public intake scope", () => {
  const scope =
    "An unauthenticated sender can submit an RFC 5322 message to POST /messages and has no other access. " +
    "Assess jobs produced by this endpoint under the deployment configuration supplied in the checkout.";
  for (const id of [
    "archive-worker-pinned-original",
    "archive-worker-pinned-normalized",
    "archive-worker-mime-parts",
  ]) {
    assert.equal(scenario(id).callerScope, scope);
  }
});

test("archive workers keep installed metadata or a complete selected lock and import chain", () => {
  for (const caseId of [
    "archive-worker-mime-parts",
    "archive-worker-pinned-original",
    "archive-worker-pinned-normalized",
  ]) {
    const item = scenario(caseId);
    const manifest = "node_modules/nodemailer/package.json";
    const alternatives = item.evidenceGroups.filter((group) =>
      group.some(({ path }) => path === manifest),
    );
    assert.equal(alternatives.length, 5);
    assert.ok(
      alternatives.some((group) =>
        group.some(
          ({ path, contains }) =>
            path === "package-lock.json" &&
            contains?.includes('"node_modules/nodemailer": {\n') &&
            contains.includes('"version": "7.0.10"') &&
            contains.includes('"integrity": "sha512-Us/Se1'),
        ),
      ),
    );
    for (const path of [
      "deploy/Dockerfile",
      "archive/index-mail.cjs",
      ...(item.verdict === "potentially_exploitable"
        ? ["node_modules/nodemailer/lib/addressparser/index.js"]
        : []),
    ]) {
      assert.ok(
        item.evidenceGroups.some((group) =>
          group.every((anchor) => anchor.path === path),
        ),
        path,
      );
    }
  }
});

test("caller scope stays constant across route and bundle variants", () => {
  for (const [first, second, entrypoint] of [
    ["direct-links", "unmounted-route", /POST \/inbox/u],
    ["archive-east", "archive-west", /POST \/archive/u],
    ["zip-import-alpha", "zip-import-beta", /ZIP mail bundle/u],
    ["affected-decode", "fixed-decode", /POST \/thumbnail/u],
    ["affected-decode", "affected-encode-only", /POST \/thumbnail/u],
    ["thumbnail-blue", "thumbnail-green", /POST \/thumbnail/u],
    ["thumbnail-blue", "thumbnail-receipt-window", /POST \/thumbnail/u],
  ] as const) {
    const scope = scenario(first).callerScope;
    assert.ok(scope);
    assert.match(scope, entrypoint);
    assert.equal(scenario(second).callerScope, scope);
  }
  assert.match(
    scenario("task-parameter").callerScope ?? "",
    /POST \/v2\/tasks/u,
  );
  assert.ok(
    cases.every((item) => item.callerScope),
    "every application has caller context",
  );
});

test("the unmounted CLI route accepts an unresolved copy without weakening its own guard proof", () => {
  const item = scenario("unmounted-route");
  assert.deepEqual(item.commandVersion, [null, "5.0.0"]);
  assert.equal(item.evidenceGroups.length, 3);
  assert.equal(
    item.evidenceGroups
      .flat()
      .some(({ path }) => path.includes("package.json")),
    false,
  );
  assert.match(
    item.question,
    /Report the dependency version in the supplied image/u,
  );
  assert.doesNotMatch(item.callerScope ?? "", /version/u);
});

test("task caller scope includes its build assumption and resolved-version request", () => {
  const item = scenario("task-parameter");
  assert.match(
    item.callerScope ?? "",
    /Assume the backend and its dependencies are built from this checkout and its lockfile\./u,
  );
  assert.match(item.callerScope ?? "", /Report the resolved vm2 version\./u);
  assert.equal(item.version, "3.9.19");
  assert.equal(item.commandVersion, undefined);
});

test("the bounded task requester requires its normal operation without unrelated gateway or storage evidence", () => {
  const item = scenario("task-parameter");
  assert.equal(overlay(item, "portal/portal.conf").kind, "fixture");
  assert.match(item.callerScope ?? "", /normal POST \/v2\/tasks/u);
  assert.match(item.callerScope ?? "", /cannot.*edit the registered template/u);
  assert.equal(
    item.evidenceGroups.some((group) =>
      group.some(({ path }) => path === "portal/portal.conf"),
    ),
    false,
  );
  assert.deepEqual(item.commandCallSite, {
    path: "plugins/scaffolder-backend/src/lib/templating/SecureTemplater.ts",
    line: 170,
  });
  assert.equal(
    item.evidenceGroups
      .flat()
      .some(({ contains }) => contains?.includes(":memory:")),
    false,
  );
  for (const [path, contains] of [
    [
      "packages/backend/package.json",
      '"@backstage/plugin-scaffolder-backend": "workspace:^"',
    ],
    [
      "packages/backend/Dockerfile",
      "yarn.lock package.json packages/backend/dist/skeleton.tar.gz",
    ],
    ["packages/backend/Dockerfile", "packages/backend/dist/bundle.tar.gz"],
    ["portal/compose.yaml", "dockerfile: packages/backend/Dockerfile"],
    ["portal/compose.yaml", "--config, app-config.yaml, --config, portal.yaml"],
    ["portal/template.yaml", "parameters.name"],
  ]) {
    assert.ok(
      item.evidenceGroups.some((group) =>
        group.some(
          (anchor) => anchor.path === path && anchor.contains === contains,
        ),
      ),
      `${path}: ${contains}`,
    );
  }
});

test("native charset retains runtime context and its decisive UTF-8 source anchors", () => {
  const item = scenario("native-charset");
  const runtime = overlay(item, "service/runtime.json");
  assert.ok(runtime.kind === "json");
  assert.equal(item.version, "2.39");
  assert.equal(item.commandVersion, null);
  assert.deepEqual(runtime.value, {
    glibc: { version: "2.39", distribution_patches: [] },
    iconv: {
      version: "3.0.1",
      node_iconv_use_system_libiconv: 1,
      linked_library: "glibc",
    },
  });
  for (const [path, contains] of [
    ["service/deploy.json", '"nativeCharset": true'],
    ["service/parse.cjs", "options.Iconv = require('iconv').Iconv"],
    ["lib/mail-parser.js", "new Iconv(charset, 'UTF-8"],
  ]) {
    assert.ok(
      item.evidenceGroups.some((group) =>
        group.some(
          (anchor) => anchor.path === path && anchor.contains === contains,
        ),
      ),
      `${path}: ${contains}`,
    );
  }
});

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
  assert.notDeepEqual(
    overlay(encode, "service/media.py"),
    overlay(decode, "service/media.py"),
  );
  assert.deepEqual(
    encode.stage.filter((file) => file.destination !== "service/media.py"),
    decode.stage.filter((file) => file.destination !== "service/media.py"),
  );
  assert.notEqual(encode.question, decode.question);
  assert.equal(decode.verdict, "potentially_exploitable");
  assert.equal(fixed.verdict, "ruled_out");
  assert.equal(encode.verdict, "ruled_out");
});

test("the two ZIP imports differ only in their deployed catalog", () => {
  const first = scenario("zip-import-alpha");
  const second = scenario("zip-import-beta");
  assert.equal(first.question, second.question);
  assert.deepEqual(
    [first.verdict, second.verdict],
    ["potentially_exploitable", "ruled_out"],
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
  assert.equal(raw.verdict, "potentially_exploitable");
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
  assert.equal(local.verdict, "potentially_exploitable");
  assert.equal(remote.verdict, "unknown");
  assert.equal(remote.commandVersion, null);
  const worker = "service/worker.cjs";
  assert.ok(
    local.evidenceGroups.some(
      (g) => g.length > 0 && g.every((e) => e.path === worker),
    ),
  );
  assert.deepEqual(
    remote.evidenceGroups.flat().filter((e) => e.path === worker),
    [],
  );
  assert.ok(
    remote.evidenceGroups
      .flat()
      .some(
        (e) =>
          e.path === "service/server.cjs" &&
          e.contains?.includes("config.worker === 'local'"),
      ),
  );
  assert.ok(
    remote.evidenceGroups
      .flat()
      .some(
        (e) =>
          e.path === "service/server.cjs" && e.contains?.includes("fetch("),
      ),
  );
});
