import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { patchSnapshotEnvironment } from "./support/patch-snapshot-environment.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test("snapshot fixture children use private temporary directories without changing the parent", async () => {
  const shared = await fixtures.create("patch-shared-temp-");
  const directories = await Promise.all([
    fixtures.create("patch-private-temp-"),
    fixtures.create("patch-private-temp-"),
  ]);
  const environment = Object.freeze({
    ...process.env,
    Temp: shared,
    tMp: shared,
    TMPDIR: shared,
    SNAPSHOT_FIXTURE_VALUE: "preserved",
  });
  const parentTemporarySettings = ["TEMP", "TMP", "TMPDIR"].map(
    (name) => process.env[name],
  );
  for (const directory of directories) {
    const selected = patchSnapshotEnvironment(directory, environment);
    const child = JSON.parse(
      execFileSync(
        process.execPath,
        [
          "-e",
          'process.stdout.write(JSON.stringify({directory:require("node:os").tmpdir(),temp:process.env.TEMP,tmp:process.env.TMP,tmpdir:process.env.TMPDIR,value:process.env.SNAPSHOT_FIXTURE_VALUE}))',
        ],
        { env: selected, encoding: "utf8" },
      ),
    );
    expect(child).toEqual({
      directory,
      temp: directory,
      tmp: directory,
      tmpdir: directory,
      value: "preserved",
    });
    expect(selected).not.toHaveProperty("Temp");
    expect(selected).not.toHaveProperty("tMp");
  }
  expect(environment.Temp).toBe(shared);
  expect(environment.tMp).toBe(shared);
  expect(environment.TMPDIR).toBe(shared);
  expect(["TEMP", "TMP", "TMPDIR"].map((name) => process.env[name])).toEqual(
    parentTemporarySettings,
  );
});
