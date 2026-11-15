import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { cases } from "./cases.mts";
import { cve, gradeCommand, readFixture } from "./command.mts";

const { files } = await readFixture();
const cite = (path: string, startLine: number, endLine = startLine) => ({
  path,
  startLine,
  endLine,
});
const image = cite("Dockerfile", 4, 8);
const notes = {
  location: "notes",
  component: "linkify-it",
  version: "5.0.0",
  verdict: "potentially_exploitable",
  deployment: "configured",
  reason: "The HTTP handler passes submitted text to the affected version.",
  evidence: [
    cite("notes/package-lock.json", 13),
    cite("compose.yaml", 5),
    image,
    cite("server.mjs", 12),
  ],
};
const reviews = {
  location: "reviews",
  component: "linkify-it",
  version: "5.0.1",
  verdict: "ruled_out",
  deployment: "configured",
  reason: "The service lockfile resolves the fixed version.",
  evidence: [
    cite("reviews/package-lock.json", 13),
    cite("compose.yaml", 10),
    image,
  ],
};
const result = {
  cve,
  status: "potentially_exploitable",
  uses: [reviews, notes],
};

test("the scoped adapter passes context separately from CLI arguments", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "scoped-cli-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  const dist = join(root, "dist");
  await Promise.all([mkdir(bin), mkdir(dist)]);
  const binary = join(bin, "codex-security.mjs");
  await Promise.all([
    writeFile(join(root, "package.json"), '{"type":"module"}'),
    writeFile(
      binary,
      'throw new Error("The package launcher should not run");',
    ),
    writeFile(
      join(dist, "cli.js"),
      "export const supportsDependencyCallerScope = true; " +
        "export function main(...args) { console.log(JSON.stringify(args)); return 17; }",
    ),
  ]);
  const adapter = fileURLToPath(new URL("./scoped-cli.mts", import.meta.url));
  const scope = "An unauthenticated sender can access only POST /messages.";
  const argv = ["exploitability", "check", cve, "--json", "--model", "fixture"];
  const invoke = () =>
    spawnSync(process.execPath, [adapter, binary, scope, ...argv], {
      encoding: "utf8",
    });
  const result = invoke();
  assert.equal(result.status, 17, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [
    argv,
    null,
    null,
    null,
    { dependencyCallerScope: scope },
  ]);

  await writeFile(
    join(dist, "cli.js"),
    "export function main() { throw new Error('Old CLI unexpectedly invoked'); }",
  );
  const oldBuild = invoke();
  assert.equal(oldBuild.status, 1);
  assert.match(
    oldBuild.stderr,
    /The selected CLI build does not support caller scope/u,
  );
});

test("scoped image cases retain their configured artifact and capture files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "scoped-image-files-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const id of ["fixed-decode", "thumbnail-blue"]) {
    const item = cases.find((entry) => entry.id === id);
    assert.ok(item?.callerScope);
    const home = join(root, id);
    const snapshot = join(home, "snapshot");
    const binary = join(home, "bin", "codex-security.mjs");
    const cli = join(home, "dist", "cli.js");
    await Promise.all([
      mkdir(snapshot, { recursive: true }),
      mkdir(join(home, "bin"), { recursive: true }),
      mkdir(join(home, "dist"), { recursive: true }),
    ]);
    const files: Record<string, string> = {};
    for (const file of item.stage) {
      if (file.kind === "git") continue;
      const contents =
        file.kind === "fixture"
          ? await readFile(new URL(file.source, import.meta.url), "utf8")
          : JSON.stringify(file.value, null, 2) + "\n";
      const destination = join(snapshot, file.destination);
      await mkdir(join(destination, ".."), { recursive: true });
      await writeFile(destination, contents);
      files[file.destination] = contents;
    }
    await Promise.all([
      writeFile(join(home, "package.json"), '{"type":"module"}'),
      writeFile(binary, 'throw new Error("Package launcher should not run");'),
      writeFile(
        cli,
        `import { readFile } from 'node:fs/promises';
export const supportsDependencyCallerScope = true;
export async function main(...args) {
  const files = Object.fromEntries(await Promise.all(
    ${JSON.stringify(Object.keys(files))}.map(async path => [path, await readFile(path, 'utf8')])
  ));
  console.log(JSON.stringify({ args, cwd: process.cwd(), files }));
  return 0;
}`,
      ),
    ]);
    const adapter = fileURLToPath(new URL("./scoped-cli.mts", import.meta.url));
    const argv = ["exploitability", "check", item.cve, "--json"];
    const result = spawnSync(
      process.execPath,
      [adapter, binary, item.callerScope, ...argv],
      { cwd: snapshot, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      args: [
        argv,
        null,
        null,
        null,
        { dependencyCallerScope: item.callerScope },
      ],
      cwd: await realpath(snapshot),
      files,
    });
  }
});

test("requires an independent grounded verdict for both configured services", () => {
  assert.equal(gradeCommand(result, files).pass, true);
  for (const uses of [
    [notes],
    [notes, notes],
    [{ ...notes, verdict: "exploitable" }, reviews],
    [notes, { ...reviews, verdict: "exploitable" }],
    [notes, { ...reviews, deployment: "confirmed" }],
    [{ ...notes, evidence: reviews.evidence }, reviews],
    [
      {
        ...notes,
        evidence: notes.evidence.filter((e) => e.path !== "server.mjs"),
      },
      reviews,
    ],
  ]) {
    assert.equal(gradeCommand({ ...result, uses }, files).pass, false);
  }
});

test("requires a version citation inside the installed linkify-it record", () => {
  const checkout = new Map(files);
  for (const use of result.uses) {
    const path = `${use.location}/package-lock.json`;
    // Make the adjacent package's version match too, so the path and version
    // string alone cannot distinguish any of the three records.
    checkout.set(
      path,
      files
        .get(path)!
        .replace('"version": "2.1.0"', `"version": "${use.version}"`),
    );
  }
  for (const line of [9, 13, 14, 22]) {
    const uses = result.uses.map((use) => ({
      ...use,
      evidence: use.evidence.map((entry) =>
        entry.path.endsWith("package-lock.json")
          ? cite(entry.path, line)
          : entry,
      ),
    }));
    const grade = gradeCommand({ ...result, uses }, checkout);
    const installed = line === 13 || line === 14;
    assert.equal(grade.pass, installed, `version citation on line ${line}`);
    assert.deepEqual(
      grade.uses.map((use) => use.errors),
      installed
        ? [[], []]
        : [
            ["Missing resolved version evidence"],
            ["Missing resolved version evidence"],
          ],
    );
  }
});

test("requires the build link between the service lockfile and the running application", () => {
  const withoutImage = reviews.evidence.filter((e) => e.path !== "Dockerfile");
  for (const evidence of [
    withoutImage,
    [...withoutImage, cite("Dockerfile", 4, 5)],
    [...withoutImage, cite("Dockerfile", 8)],
  ]) {
    const grade = gradeCommand(
      { ...result, uses: [notes, { ...reviews, evidence }] },
      files,
    );
    assert.equal(grade.pass, false);
    assert.equal(grade.uses.find((use) => use.service === "notes")?.pass, true);
  }
});

test("every citation must select lines inside the graded checkout", () => {
  for (const citation of [
    cite("../answer.json", 1),
    cite("server.mjs", 0),
    cite("server.mjs", 420),
  ]) {
    const uses = [
      notes,
      { ...reviews, evidence: [...reviews.evidence, citation] },
    ];
    assert.equal(gradeCommand({ ...result, uses }, files).pass, false);
  }
});
