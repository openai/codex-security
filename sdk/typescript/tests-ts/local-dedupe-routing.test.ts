import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import { Tiktoken } from "js-tiktoken/lite";
import cl100kBase from "js-tiktoken/ranks/cl100k_base";
import { LocalDeduplication } from "../src/deduplication/local.js";
import type { Finding, FindingsDocument } from "../src/models.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
} from "../src/server/embeddings.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { sha256 } from "./support/finding-identity.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories(true);
afterEach(directories.cleanup);

async function fixture() {
  const root = await directories.create("local-dedupe-routing-");
  const repository = join(root, "repository");
  await mkdir(repository);
  const repositoryId = `target_sha256_${sha256(`local-workspace\0${repository}`)}`;
  const document = JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
      "utf8",
    ),
  ) as FindingsDocument;
  const finding = document.findings[0]!;
  const stateDirectory = join(root, "state with spaces");
  const options = {
    pluginRoot: PLUGIN_ROOT,
    environment: process.env,
    python: join(root, "missing-python"),
    stateDirectory,
    protectedRoot: repository,
  };
  const prepare = {
    action: "prepare",
    repositoryPath: repository,
    anchorRepositoryId: repositoryId,
    repositoryId,
    space: "synthetic-embedding-space",
    model: "synthetic-embedding",
    dimensions: 2,
    findings: [finding],
  };
  return { options, prepare, finding, stateDirectory };
}

test("bundled local dedupe retains raw integer bytes and SDK number values without Python", async () => {
  const { options, prepare, finding } = await fixture();
  finding.extensions = {
    integer: "9007199254740993",
    text: "synthetic evidence \0 λ",
  };
  const input = JSON.stringify(prepare).replace(
    '"integer":"9007199254740993"',
    '"integer":9007199254740993',
  );
  const prepared = await runWorkbench(options, ["local-dedupe"], input);
  expect(prepared["findingsToEmbed"] as unknown).toEqual([
    {
      ...finding,
      extensions: { ...finding.extensions, integer: 9007199254740992 },
    },
  ]);
  const cacheKeys = prepared["cacheKeys"] as Record<string, string>;
  expect(Object.keys(cacheKeys)).toEqual([finding.findingId]);
  const stored = spawnSync(
    "node",
    [
      "-e",
      `const { DatabaseSync } = require("node:sqlite");
const database = new DatabaseSync(process.argv[1]);
console.log(database.prepare("SELECT details_json FROM findings WHERE id = ?").get(process.argv[2]).details_json);
database.close();`,
      join(options.stateDirectory, "workbench.sqlite3"),
      finding.findingId,
    ],
    { encoding: "utf8" },
  );
  expect(stored.status, stored.stderr).toBe(0);
  const storedBody = stored.stdout.trim();
  expect(storedBody).toMatch(/"integer":\s*9007199254740993/u);
  expect(cacheKeys[finding.findingId]).toBe(
    sha256(`${prepare.space}\0${storedBody}`),
  );

  expect(
    await runWorkbench(
      options,
      ["local-dedupe"],
      JSON.stringify({
        action: "embed",
        space: prepare.space,
        model: prepare.model,
        dimensions: prepare.dimensions,
        entries: [
          {
            findingId: finding.findingId,
            cacheKey: cacheKeys[finding.findingId],
            embedding: { model: prepare.model, vector: [1, 0] },
          },
        ],
      }),
    ),
  ).toEqual({});
  expect(await runWorkbench(options, ["local-dedupe"], input)).toEqual({
    cacheKeys,
    findingsToEmbed: [],
  });
  const largeFinding = {
    ...finding,
    extensions: { ...finding.extensions, integer: 9007199254740992 },
  } as Finding;
  const embed = mock(async (batch: readonly Finding[]) => {
    expect(batch).toEqual([largeFinding]);
    return batch.map(() => ({ model: prepare.model, vector: [1, 0] }));
  });
  const local = new LocalDeduplication(
    {
      ...options.environment,
      CODEX_SECURITY_STATE_DIR: options.stateDirectory,
      PYTHON: options.python,
    },
    { repositoryId: prepare.repositoryId },
    prepare.repositoryPath,
    undefined,
    undefined,
    {
      model: prepare.model,
      dimensions: prepare.dimensions,
      cacheNamespace: "synthetic-adapter",
      embedder: { embed },
    },
  );
  await local.prepare([largeFinding], prepare.repositoryId);
  await local.prepare([largeFinding], prepare.repositoryId);
  expect(embed).toHaveBeenCalledTimes(1);
});

test("default embeddings retain historical key order and SDK number values and reuse their cache", async () => {
  const { options, prepare, finding } = await fixture();
  await runWorkbench(options, ["local-dedupe"], JSON.stringify(prepare));
  const storedBody =
    `{"z":true,"findingId":${JSON.stringify(finding.findingId)},` +
    '"extensions":{"😀":"astral","z":{"z":2,"a":1},"integer":9007199254740993,' +
    '"\\ue000":"BMP","a":[{"z":4,"a":3}]},"a":false}';
  const stored = spawnSync(
    "node",
    [
      "-e",
      `const { DatabaseSync } = require("node:sqlite");
const database = new DatabaseSync(process.argv[1]);
database.prepare("UPDATE findings SET details_json = ? WHERE id = ?").run(process.argv[3], process.argv[2]);
database.close();`,
      join(options.stateDirectory, "workbench.sqlite3"),
      finding.findingId,
      storedBody,
    ],
    { encoding: "utf8" },
  );
  expect(stored.status, stored.stderr).toBe(0);
  const expectedInput = JSON.stringify({
    a: false,
    extensions: {
      a: [{ a: 3, z: 4 }],
      integer: 9007199254740992,
      z: { a: 1, z: 2 },
      "\ue000": "BMP",
      "😀": "astral",
    },
    findingId: finding.findingId,
    z: true,
  });
  const encoding = new Tiktoken(cl100kBase);
  const request = spyOn(globalThis, "fetch").mockResolvedValue(
    Response.json({
      model: EMBEDDING_MODEL,
      data: [
        {
          index: 0,
          embedding: [1, ...Array<number>(EMBEDDING_DIMENSIONS - 1).fill(0)],
        },
      ],
    }),
  );
  try {
    const local = new LocalDeduplication(
      {
        ...options.environment,
        CODEX_SECURITY_STATE_DIR: options.stateDirectory,
        PYTHON: options.python,
        OPENAI_API_KEY: "synthetic-key",
      },
      { repositoryId: prepare.repositoryId },
      prepare.repositoryPath,
    );
    await local.prepare([finding], prepare.repositoryId);
    expect(request).toHaveBeenCalledTimes(1);
    const body = JSON.parse(String(request.mock.calls[0]![1]!.body)) as {
      input: number[][];
    };
    expect(body.input).toHaveLength(1);
    expect(body.input[0]).toEqual(encoding.encode(expectedInput, [], []));
    expect(encoding.decode(body.input[0]!)).toBe(expectedInput);
    await local.prepare([finding], prepare.repositoryId);
    expect(request).toHaveBeenCalledTimes(1);
  } finally {
    request.mockRestore();
  }
});

test("pre-aborted native local dedupe does not initialize its database", async () => {
  const { options, prepare, stateDirectory } = await fixture();
  await expect(
    runWorkbench(
      { ...options, signal: AbortSignal.abort() },
      ["local-dedupe"],
      JSON.stringify(prepare),
    ),
  ).rejects.toMatchObject({ name: "AbortError" });
  expect(existsSync(join(stateDirectory, "workbench.sqlite3"))).toBe(false);
});

test("malformed local dedupe input cannot replace the selected state directory", async () => {
  const { options, prepare, stateDirectory } = await fixture();
  const otherState = join(stateDirectory, "..", "alternate state");
  const input =
    JSON.stringify(prepare) + ',"stateDirectory":' + JSON.stringify(otherState);
  await expect(
    runWorkbench(options, ["local-dedupe"], input),
  ).rejects.toMatchObject({ cause: expect.any(SyntaxError) });
  expect(existsSync(stateDirectory)).toBe(false);
  expect(existsSync(otherState)).toBe(false);
});

test("explicit external plugins retain their Python local dedupe protocol", async () => {
  const { options, stateDirectory } = await fixture();
  const pluginRoot = join(stateDirectory, "external-plugin");
  await mkdir(join(pluginRoot, "scripts"), { recursive: true });
  await writeFile(
    join(pluginRoot, "scripts", "workbench_db.py"),
    `import json, sys
request = json.load(sys.stdin)
print(json.dumps({"action": request["action"], "arguments": sys.argv[1:]}))
`,
  );
  const python = await resolvePluginPython({
    environment: options.environment,
    protectedRoot: options.protectedRoot,
  });
  expect(
    await runWorkbench(
      { ...options, pluginRoot, python },
      ["local-dedupe"],
      '{"action":"embed","entries":[]}',
    ),
  ).toEqual({ action: "embed", arguments: ["local-dedupe"] });
});

for (const failure of ["non-finite body", "BLOB finding ID"]) {
  test(`native local dedupe emits no partial JSON when a stored ${failure} fails after commit`, async () => {
    const { options, prepare, finding, stateDirectory } = await fixture();
    await runWorkbench(options, ["local-dedupe"], JSON.stringify(prepare));
    const database = join(stateDirectory, "workbench.sqlite3");
    function sql(script: string) {
      const result = spawnSync(
        "node",
        [
          "-e",
          `const { DatabaseSync } = require("node:sqlite");
const database = new DatabaseSync(process.argv[1]);
${script}
database.close();`,
          database,
          finding.findingId,
        ],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
      return result.stdout;
    }
    let payload: Omit<typeof prepare, "repositoryId"> & {
      repositoryId?: string;
    } = prepare;
    if (failure === "non-finite body") {
      sql(`
database.prepare("UPDATE findings SET details_json = ? WHERE id = ?")
  .run('{"overflow":1e400}', process.argv[2]);
database.exec("DELETE FROM finding_repositories");
`);
    } else {
      sql(`
database.exec("DELETE FROM finding_repositories");
database.prepare("UPDATE findings SET id = CAST(id AS BLOB) WHERE id = ?")
  .run(process.argv[2]);
`);
      payload = {
        ...prepare,
        repositoryId: undefined,
        findings: [
          {
            ...finding,
            findingId: `${finding.findingId}-new`,
            fingerprints: {
              ...finding.fingerprints,
              primary: `${finding.fingerprints.primary}-new`,
            },
          },
        ],
      };
    }
    const result = spawnSync(
      "node",
      [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), "local-dedupe"],
      {
        input: JSON.stringify({ stateDirectory, payload }),
        encoding: "utf8",
      },
    );
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    if (failure === "non-finite body")
      expect(result.stderr).toContain("non-finite");
    else expect(result.stderr).toMatch(/key|blob|bytes/iu);
    expect(
      sql(
        'console.log(database.prepare("SELECT COUNT(*) AS total FROM finding_repositories").get().total);',
      ).trim(),
    ).toBe("1");
  });
}
