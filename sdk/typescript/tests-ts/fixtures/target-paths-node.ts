import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { TestClient } from "../support/api-client.js";
import type { JsonObject } from "../../src/config.js";
import { main } from "../../src/cli.js";
import { runComponentScans } from "../../src/component-scan.js";
import { runWorkbench } from "../../src/runtime.js";
import { runArtifactExport } from "../../src/artifact-export.js";
import { prepareNormalizedLocalImport } from "../../src/external-findings-local.js";
import { dependencies, fakeResult } from "../cli-fixtures.js";
import { createCliTest } from "../support/cli-run.js";
import { copyCompletedScan } from "../plugin-root.js";

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
      if (home === undefined) {
        for (const requested of [
          "~/physical/repository",
          "~\\physical\\repository",
        ]) {
          const validated = createCliTest(main);
          let selected;
          assert.equal(
            await validated.runCli(
              ["scan", requested, "--validate", "--json"],
              dependencies({
                currentDirectory: root,
                onTurn: (path) => {
                  selected = path;
                },
              }),
            ),
            0,
            validated.stderr.text(),
          );
          assert.equal(selected, repository);
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
            validate: client.validate.bind(client),
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
  const savedAlias = join(root, "owner", "alias");
  async function checkHistory(
    expectedTarget: string | undefined,
    requested = requestedRepository,
  ) {
    const history = createCliTest(main);
    let selectedTarget: string | undefined;
    assert.equal(
      await history.runCli(
        ["findings", "list", requested, "--json"],
        dependencies({
          currentDirectory: root,
          onWorkbench: (args): JsonObject => {
            if (args[0] === "list-repositories") {
              return {
                repositories: [
                  { targetId: "sibling", targetPath: sibling },
                  { targetId: "physical", targetPath: repository },
                  { targetId: "saved-alias", targetPath: savedAlias },
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
  const publication = createCliTest(main);
  const published: string[] = [];
  assert.equal(
    await publication.runCli(
      [
        "publish",
        "scan",
        requestedRepository,
        "--scan-dir",
        repository,
        "--to",
        "cloud",
        "--dry-run",
      ],
      {
        ...dependencies({ currentDirectory: root }),
        publishScanToCloud: async (directory) => {
          published.push(directory);
          return { scanId: "scan-1", findingIds: [], findingCount: 0 };
        },
      },
    ),
    0,
    publication.stderr.text(),
  );
  assert.deepEqual(published, [await realpath(repository)]);
  const sourceOptions = dependencies({ currentDirectory: root });
  sourceOptions.readLocalExternalFindings = async ({
    repository: selected,
  }) => {
    assert.equal(await realpath(selected), repository);
    return { repository, findings: [] };
  };
  sourceOptions.exportFindings = async ({ sourceRoot }) => {
    assert.equal(await realpath(sourceRoot!), repository);
    return "";
  };
  await writeFile(join(root, "vendor.json"), "[]");
  await writeFile(join(repository, "vendor.json"), "[]");
  await writeFile(join(sibling, "vendor.json"), "invalid sibling report");
  const publish = (selected: string, file = "vendor.json") => [
    "publish",
    "findings",
    file,
    "--to",
    "local",
    "--repository",
    selected,
    "--provider",
    "wiz",
    "--source-key",
    "fixture",
    "--dry-run",
    "--json",
  ];
  for (const command of [
    ["findings", "imported", requestedRepository, "--json"],
    publish(requestedRepository, `${requestedRepository}/vendor.json`),
    ["export", "scan", "--output", "-", "--source-root", requestedRepository],
  ]) {
    const cli = createCliTest(main);
    assert.equal(
      await cli.runCli(command, sourceOptions),
      0,
      cli.stderr.text(),
    );
    if (command[0] !== "export")
      assert.equal(JSON.parse(cli.stdout.text()).repository, repository);
  }
  const outputDir = `${requestedRepository}/output`;
  await assert.rejects(client.preflight(requestedRepository, { outputDir }), {
    name: "OutputInsideProtectedRootError",
  });
  const output = createCliTest(main);
  assert.equal(
    await output.runCli(
      [
        "scan",
        requestedRepository,
        "--dry-run",
        "--output-dir",
        outputDir,
        "--json",
      ],
      {
        ...dependencies({ currentDirectory: root }),
        createSecurity: localClient,
      },
    ),
    2,
  );
  assert.match(output.stderr.text(), /outside the scanned directory/);
  const owner = join(root, "owner");
  await mkdir(join(owner, "tools"), { recursive: true, mode: 0o700 });
  execFileSync("git", ["init", "--quiet", owner]);
  execFileSync("git", ["init", "--quiet", repository]);
  await symlink(repository, savedAlias);
  const selected = join(repository, "components");
  const physical = join(root, "physical");
  const saved = join(physical, "saved-output");
  await mkdir(saved, { mode: 0o700 });
  await writeFile(join(saved, "prior-marker"), "existing output");
  await symlink(join(physical, "child"), join(repository, "build"));
  await symlink(join(repository, "build"), join(owner, "linked-build"));
  await symlink(selected, join(owner, "selected"));
  const outside = {
    name: "OutputInsideProtectedRootError",
    protectedRoot: await realpath(repository),
  };
  const workflowOutput = join(physical, "workflow-output");
  const writer = new TestClient(
    {},
    {
      environment: {
        PATH: process.env["PATH"],
        HOME: root,
        CODEX_SECURITY_STATE_DIR: join(workflowOutput, "state"),
      },
      runWorkbench,
    },
  );
  try {
    for (const outputDir of [
      `${repository}/build/../saved-output`,
      `${owner}/alias/build/../saved-output`,
      `${owner}/linked-build/../saved-output`,
    ]) {
      await assert.rejects(
        writer.run(selected, { mock: true, outputDir, archiveExisting: true }),
        outside,
      );
    }
    assert.deepEqual(await readdir(saved), ["prior-marker"]);
    assert.equal(
      await readFile(join(saved, "prior-marker"), "utf8"),
      "existing output",
    );
    for (const outputDir of [
      workflowOutput,
      `${entry}/link/../workflow-output`,
    ]) {
      await assert.rejects(
        writer.run(selected, { mock: true, outputDir, workflowId: "guard" }),
        /Workflow state must be outside the sealed scan artifacts/,
      );
    }
    assert.equal(
      existsSync(join(workflowOutput, "state", "workbench.sqlite3")),
      false,
    );
  } finally {
    await writer.close();
  }
  const plan = (outputDir: string) =>
    runComponentScans({
      repository: selected,
      outputDir,
      components: [{ name: "Source", paths: ["."] }],
      planOnly: true,
    });
  await assert.rejects(plan(`${owner}/selected/../build/new-plan`), outside);
  for (const [outputDir, name] of [
    [`${entry}/link/../operator-plan`, "operator-plan"],
    [`${repository}/../plain-plan`, "plain-plan"],
  ] as const) {
    const result = await plan(outputDir);
    assert.equal(result.planPath, join(physical, name, "components.json"));
    assert.equal(
      JSON.parse(await readFile(result.planPath, "utf8")).components[0].name,
      "Source",
    );
  }
  await checkHistory("saved-alias", savedAlias);
  await checkHistory("saved-alias", "owner/tools/../alias");
  const requestedAlias = `${owner}/tools/../alias`;
  const alias = createCliTest(main);
  assert.equal(
    await alias.runCli(
      publish(requestedAlias),
      dependencies({
        currentDirectory: root,
        environment: {
          ...process.env,
          CODEX_SECURITY_STATE_DIR: join(owner, "state"),
        },
      }),
    ),
    2,
  );
  assert.match(alias.stderr.text(), /outside the protected scan root/);
  const exportRoot = process.argv[3]!;
  const source = join(exportRoot, "source");
  const physicalSource = join(exportRoot, "physical");
  await mkdir(source);
  await mkdir(join(physicalSource, "child"), { recursive: true });
  await symlink(join(physicalSource, "child"), join(source, "link"));
  const traversedSource = `${source}/link/..`;
  const scan = await copyCompletedScan(exportRoot);
  if (process.platform === "linux" && existsSync("/proc/self/fd")) {
    await mkdir(join(physicalSource, "src"));
    await writeFile(
      join(physicalSource, "src", "extract.py"),
      "\n".repeat(40) + "extract(member)\n",
    );
    await using directory = await open(join(physicalSource, "child"));
    const sarif = await runArtifactExport({
      scanDir: scan,
      sourceRoot: `/proc/self/fd/${directory.fd}/..`,
      format: "sarif",
      output: "-",
    });
    const [finding] = JSON.parse(sarif!).runs[0].results;
    assert.equal(
      finding.partialFingerprints.primaryLocationLineHash,
      "68da6fe4396c35f9:1",
    );
  }
  for (const [sourceRoot, directory] of [
    [requestedAlias, owner],
    [traversedSource, source],
    [traversedSource, physicalSource],
    [traversedSource, exportRoot],
  ] as const) {
    const python = join(directory, "fixture-python");
    await writeFile(
      python,
      '#!/bin/sh\necho run >> "$0-ran"\nexec python3 "$@"\n',
      { mode: 0o755 },
    );
    const exported = createCliTest(main);
    const code = await exported.runCli(
      [
        "export",
        scan,
        "--output",
        "-",
        "--source-root",
        sourceRoot,
        "--python",
        python,
      ],
      {
        ...dependencies({ currentDirectory: root }),
        exportFindings: runArtifactExport,
      },
    );
    if (directory === exportRoot) {
      assert.equal(code, 0, exported.stderr.text());
      assert.equal(JSON.parse(exported.stdout.text()).version, "2.1.0");
      assert.equal(await readFile(`${python}-ran`, "utf8"), "run\nrun\n");
    } else {
      assert.equal(code, 2);
      assert.match(
        exported.stderr.text(),
        /configured plugin Python interpreter is unavailable/,
      );
      await assert.rejects(realpath(`${python}-ran`), { code: "ENOENT" });
    }
  }
  await assert.rejects(
    prepareNormalizedLocalImport(
      { read: 0, findings: [], excluded: [] },
      {
        repository: `${requestedRepository}/components`,
        provider: "wiz",
        sourceKey: "fixture",
      },
      {
        environment: {
          ...process.env,
          CODEX_SECURITY_STATE_DIR: join(repository, "state"),
        },
      },
    ),
    /outside the protected scan root/,
  );
  const prompt = createCliTest(main);
  await writeFile(join(repository, "prompt.md"), "physical");
  await writeFile(join(sibling, "prompt.md"), "sibling");
  let selectedPrompt: string | undefined;
  assert.equal(
    await prompt.runCli(
      [
        "scan",
        requestedRepository,
        "--scan-prompt-file",
        `${requestedRepository}/prompt.md`,
        "--json",
      ],
      dependencies({
        currentDirectory: root,
        onTurn: (_, options) => {
          selectedPrompt = options.scanPrompt;
        },
      }),
    ),
    0,
    prompt.stderr.text(),
  );
  assert.equal(selectedPrompt, "physical");
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
    client.preflight(requestedRepository, {
      scanPromptFile: `${requestedRepository}/outside/../app.ts`,
    }),
    /directory links outside the selected repository/,
  );
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
