import assert from "node:assert/strict";
import { mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { TestClient } from "../support/api-client.js";
import type { JsonObject } from "../../src/config.js";
import { main } from "../../src/cli.js";
import { dependencies, fakeResult } from "../cli-fixtures.js";
import { createCliTest } from "../support/cli-run.js";

const root = process.argv[2]!;
const entry = join(root, "entry");
const repository = join(root, "physical", "repository");
const sibling = join(entry, "repository");
await mkdir(join(sibling, "scope"), { recursive: true, mode: 0o700 });
await writeFile(join(sibling, "app.ts"), "export const sibling = true;\n");
await mkdir(join(root, "physical", "child"), { recursive: true, mode: 0o700 });
await mkdir(join(repository, "components", "child"), {
  recursive: true,
  mode: 0o700,
});
await writeFile(join(repository, "components", "app.ts"), "export {};\n");
await writeFile(join(repository, "app.ts"), "export const sibling = true;\n");
await symlink(join(root, "physical", "child"), join(entry, "link"));
await symlink(
  join(repository, "components", "child"),
  join(repository, "scope"),
);
const requestedRepository = `${entry}/link/../repository`;
const localClient = () =>
  new TestClient(
    {},
    {
      environment: {},
      prepareRuntime: async () => {
        throw new Error("Runtime must not initialize");
      },
    },
  );
const client = localClient();
try {
  for (const mode of ["standard", "deep"] as const) {
    for (const requested of [
      requestedRepository,
      relative(process.cwd(), entry) + "/link/../repository",
      "~/entry/link/../repository",
      "~//entry/link/../repository",
    ]) {
      const result = await client.preflight(requested, {
        target: ["scope/../app.ts"],
        mode,
        outputDir: join(root, `output-${mode}`),
      });
      assert.equal(result.repository, await realpath(repository));
      assert.deepEqual(result.target, {
        kind: "paths",
        paths: ["components/app.ts"],
      });
    }
    await rm(sibling, { recursive: true, force: true });
    await rm(join(repository, "app.ts"), { force: true });
  }
  for (const command of ["scan", "policy"]) {
    const { runCli, stdout, stderr } = createCliTest(main);
    assert.equal(
      await runCli([command, requestedRepository, "--dry-run", "--json"], {
        ...dependencies({ currentDirectory: root }),
        createSecurity: localClient,
        createPolicySecurity: localClient,
      }),
      0,
      stderr.text(),
    );
    assert.equal(
      JSON.parse(stdout.text()).repository,
      await realpath(repository),
    );
  }
  const otherHome = join(root, "other-home");
  await mkdir(otherHome, { mode: 0o700 });
  for (const home of [root, undefined, ""]) {
    const profile = home === undefined ? root : otherHome;
    process.env["USERPROFILE"] = profile;
    if (home === undefined) delete process.env["HOME"];
    else process.env["HOME"] = home;
    try {
      {
        const home = homedir();
        const requested = `~/${relative(home === "" ? root : home, entry)}/link/../repository`;
        assert.equal(
          (await client.preflight(requested)).repository,
          await realpath(repository),
        );
        assert.deepEqual(
          (
            await client.preflight(repository, {
              target: [`${requested}/scope/../app.ts`],
            })
          ).target,
          { kind: "paths", paths: ["components/app.ts"] },
        );
        if (home === "") {
          await writeFile(
            join(root, "app.ts"),
            "export const caller = true;\n",
          );
          await writeFile(
            join(repository, "app.ts"),
            "export const caller = false;\n",
          );
          await assert.rejects(
            client.preflight(repository, { target: ["~/app.ts"] }),
            /outside the repository/,
          );
        }
      }
      const cliEntry = relative(home || profile, entry);
      const windowsEntry = cliEntry.replaceAll("/", "\\");
      for (const requested of [
        `~/${cliEntry}/link/../repository`,
        `~\\${windowsEntry}\\link\\..\\repository`,
        `~\\\\${windowsEntry}\\link\\..\\repository`,
      ]) {
        const fallback = createCliTest(main);
        assert.equal(
          await fallback.runCli(["policy", requested, "--dry-run", "--json"], {
            ...dependencies({ currentDirectory: root }),
            createPolicySecurity: localClient,
          }),
          0,
          fallback.stderr.text(),
        );
        assert.equal(
          JSON.parse(fallback.stdout.text()).repository,
          await realpath(repository),
        );
      }
    } finally {
      process.env["HOME"] = root;
      process.env["USERPROFILE"] = root;
    }
  }
  const planned = createCliTest(main);
  assert.equal(
    await planned.runCli(
      [
        "scan-components",
        requestedRepository,
        "--component",
        "components",
        "--plan-only",
        "--output-dir",
        join(root, "component-plan"),
        "--json",
      ],
      dependencies({ currentDirectory: root }),
    ),
    0,
    planned.stderr.text(),
  );
  const backslashRepository = join(root, "physical\\repository");
  await mkdir(backslashRepository, { mode: 0o700 });
  assert.equal(
    (await client.preflight("~\\physical\\repository")).repository,
    await realpath(backslashRepository),
  );
  for (const [requested, expected] of [
    [requestedRepository, repository],
    ["~\\physical\\repository", backslashRepository],
  ] as const) {
    let editorOpened = false;
    const interactive = createCliTest(main, { stderr: true });
    assert.equal(
      await interactive.runCli(["scan", requested], {
        ...dependencies({
          currentDirectory: root,
          result: fakeResult(["high"]),
        }),
        confirmPatchReview: async () => true,
        patchEditor: async (selected) => {
          assert.equal(selected, await realpath(expected));
          editorOpened = true;
          return null;
        },
      }),
      0,
      interactive.stderr.text(),
    );
    assert.equal(editorOpened, true);
  }
  for (const patchReview of [false, true]) {
    const link = join(entry, "temporary-link");
    await symlink(join(root, "physical", "child"), link);
    const lifecycle = createCliTest(main, { stderr: patchReview });
    let editorOpened = false;
    assert.equal(
      await lifecycle.runCli(
        ["scan", `${link}/../repository`, ...(patchReview ? [] : ["--json"])],
        {
          ...dependencies({ currentDirectory: root }),
          createSecurity: () => ({
            preflight: client.preflight.bind(client),
            run: async (selected, options) => {
              assert.equal(
                (await client.preflight(selected, options)).repository,
                await realpath(repository),
              );
              await rm(link);
              return fakeResult(["high"]);
            },
            close: async () => {},
          }),
          confirmPatchReview: async () => true,
          patchEditor: async (selected) => {
            assert.equal(selected, await realpath(repository));
            editorOpened = true;
            return null;
          },
        },
      ),
      0,
      lifecycle.stderr.text(),
    );
    assert.equal(editorOpened, patchReview);
    if (!patchReview)
      assert.equal(
        JSON.parse(lifecycle.stdout.text()).manifest.scan.status,
        "completed",
      );
  }
  await mkdir(sibling, { mode: 0o700 });
  async function checkHistory(expectedTarget: string | undefined) {
    const history = createCliTest(main);
    let selectedTarget: string | undefined;
    assert.equal(
      await history.runCli(
        ["findings", "list", requestedRepository, "--json"],
        dependencies({
          currentDirectory: root,
          onWorkbench: (args): JsonObject => {
            if (args[0] === "list-repositories") {
              return {
                repositories: [
                  { targetId: "sibling", targetPath: sibling },
                  { targetId: "physical", targetPath: repository },
                ],
              };
            }
            selectedTarget = args[2];
            return {
              findings: [{ title: `${selectedTarget} finding` }],
              nextOffset: null,
            };
          },
        }),
      ),
      0,
      history.stderr.text(),
    );
    assert.equal(selectedTarget, expectedTarget);
    assert.deepEqual(
      JSON.parse(history.stdout.text()).findings,
      expectedTarget === undefined
        ? []
        : [{ title: `${expectedTarget} finding` }],
    );
  }
  await checkHistory("physical");
  await assert.rejects(
    client.preflight(requestedRepository, {
      outputDir: join(repository, "output"),
    }),
    { name: "OutputInsideProtectedRootError" },
  );
  await mkdir(join(entry, "missing"), { mode: 0o700 });
  await assert.rejects(
    client.preflight(`${entry}/link/../missing`),
    /Repository is not a directory/,
  );
  await mkdir(join(root, "outside", "child"), { recursive: true, mode: 0o700 });
  await writeFile(join(root, "outside", "app.ts"), "export {};\n");
  await writeFile(join(repository, "app.ts"), "export {};\n");
  await symlink(join(root, "outside", "child"), join(repository, "outside"));
  await assert.rejects(
    client.preflight(repository, { target: ["outside/../app.ts"] }),
    /outside the repository/,
  );
  await rm(repository, { recursive: true });
  await checkHistory("physical");
  await rm(join(root, "physical", "child"), { recursive: true });
  await checkHistory(undefined);
  await rm(join(entry, "link"));
  await checkHistory(undefined);
} finally {
  await client.close();
}
