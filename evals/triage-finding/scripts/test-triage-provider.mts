import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import { createServer } from "node:net";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { beforeAll } from "./triage-provider.mts";
const require = createRequire(import.meta.url);
const { parse } = createRequire(require.resolve("promptfoo"))("yaml");

const evalRoot = path.resolve(import.meta.dirname, "..");
const runner = path.join(import.meta.dirname, "run-promptfoo.mts");
const extensions = [
  `file://${path.join(import.meta.dirname, "triage-provider.mts")}:beforeAll`,
];
interface Capture {
  cwd: string;
  policy: string;
  proxies: Record<string, string>;
  nodePath: string;
  nodeTarget: string;
  directories: string[];
  overrides: string[];
}

const proxies = {
  HTTP_PROXY: "http://http.example.test:8080",
  HTTPS_PROXY: "http://https.example.test:8080",
  ALL_PROXY: "http://all.example.test:8080",
  NO_PROXY: "localhost,.example.test",
};

function invoke(args: string[], environment: NodeJS.ProcessEnv) {
  return new Promise<{ code: number | null; output: string }>(
    (resolve, reject) => {
      const child = spawn(
        process.execPath,
        ["--experimental-strip-types", runner, ...args],
        {
          cwd: evalRoot,
          env: { ...process.env, ...environment, NODE_USE_ENV_PROXY: "" },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk;
      });
      child.stderr.on("data", (chunk) => {
        output += chunk;
      });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, output }));
    },
  );
}

test(
  "runtime extension preserves native credential precedence and wraps providers once",
  { skip: process.platform === "win32" },
  async (t) => {
    const root = fs.realpathSync(
      fs.mkdtempSync(path.join(os.tmpdir(), "triage-auth-")),
    );
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const priorRuntime = process.env.TRIAGE_RUNTIME_ROOT;
    process.env.TRIAGE_RUNTIME_ROOT = root;
    t.after(() => {
      if (priorRuntime === undefined) delete process.env.TRIAGE_RUNTIME_ROOT;
      else process.env.TRIAGE_RUNTIME_ROOT = priorRuntime;
    });
    const fakeCodex = path.join(root, "codex");
    fs.writeFileSync(
      fakeCodex,
      `#!${process.execPath}
console.log(JSON.stringify({type:'thread.started',thread_id:'synthetic-auth'}));
console.log(JSON.stringify({type:'item.completed',item:{id:'message',type:'agent_message',text:JSON.stringify({apiKey:process.env.CODEX_API_KEY,cwd:process.argv[process.argv.indexOf('--cd')+1],directories:process.argv.flatMap((arg,index)=>arg==='--add-dir'?[process.argv[index+1]]:[])})}}));
console.log(JSON.stringify({type:'turn.completed',usage:{input_tokens:1,output_tokens:1}}));
`,
      { mode: 0o755 },
    );
    const { loadApiProvider } = await import("promptfoo");
    const cases = [
      {
        env: { OPENAI_API_KEY: "synthetic-global" },
        providerEnv: { CODEX_API_KEY: "synthetic-provider" },
        expected: "synthetic-provider",
      },
      {
        env: { CODEX_API_KEY: "synthetic-global" },
        providerEnv: { OPENAI_API_KEY: "synthetic-provider" },
        expected: "synthetic-provider",
      },
      {
        env: { OPENAI_API_KEY: "synthetic-global" },
        providerEnv: {
          OPENAI_API_KEY: "synthetic-openai",
          CODEX_API_KEY: "synthetic-codex",
        },
        expected: "synthetic-openai",
      },
      {
        env: { OPENAI_API_KEY: "synthetic-global" },
        providerEnv: { CODEX_API_KEY: "synthetic-provider" },
        apiKey: "synthetic-explicit",
        expected: "synthetic-explicit",
      },
      {
        env: { OPENAI_API_KEY: "synthetic-global" },
        providerEnv: { CODEX_API_KEY: "" },
        expected: "synthetic-global",
      },
    ];
    for (const entry of cases) {
      const load = () =>
        loadApiProvider("openai:codex-sdk:gpt-5.5", {
          basePath: root,
          env: entry.env,
          options: {
            env: entry.providerEnv,
            config: {
              working_dir: root,
              codex_path_override: fakeCodex,
              skip_git_repo_check: true,
              model: "gpt-5.5",
              maxRetries: 0,
              apiKey: entry.apiKey,
              cli_env: { CODEX_MCP_NODE_PATH: process.execPath },
            },
          },
        });
      const native = await load();
      const adapted = await load();
      try {
        const context = { suite: { providers: [adapted] } };
        beforeAll(context);
        beforeAll(context);
        const original = await native.callApi("synthetic");
        const result = await adapted.callApi("synthetic");
        assert.equal(original.error, undefined);
        assert.equal(result.error, undefined);
        const originalOutput = JSON.parse(String(original.output));
        const output = JSON.parse(String(result.output));
        assert.equal(originalOutput.apiKey, entry.expected);
        assert.equal(output.apiKey, originalOutput.apiKey);
        assert.equal(output.cwd, root);
        assert.equal(adapted.id(), native.id());
        assert.deepEqual(output.directories, [
          path.dirname(fs.realpathSync(process.execPath)),
          path.dirname(process.execPath),
          path.dirname(fakeCodex),
        ]);
      } finally {
        await native.cleanup?.();
        await adapted.cleanup?.();
      }
    }
  },
);

// Exercise the pinned provider and Codex SDK subprocess without a model request.
// The normal setup command supplies the host helper build used by the runner.
test(
  "provider preserves proxies and rebinds saved evaluations to fresh runtimes",
  { skip: process.platform === "win32", timeout: 120000 },
  async (t) => {
    const root = fs.realpathSync(
      fs.mkdtempSync(path.join(os.tmpdir(), "triage-provider-")),
    );
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const capture = path.join(root, "captures.jsonl");
    const fakeCodex = path.join(root, "codex");
    const fail = path.join(root, "fail");
    fs.writeFileSync(
      fakeCodex,
      `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const cwd = process.argv[process.argv.indexOf('--cd') + 1];
const launcher = path.join(cwd, 'plugins/codex-security/scripts/launch_codex_security_mcp');
const fixture = path.join(cwd, 'evals/triage-finding/fixtures/repo');
fs.writeFileSync(path.join(fixture, 'SECURITY.md'), '# Synthetic policy\\n');
const policy = cp.execFileSync(launcher, ['--helper', 'resolve-security-md', '--repo', fixture, '--scope', 'src/server.js', '--out', '-'], {encoding:'utf8'});
const directories = process.argv.flatMap((arg, index) => arg === '--add-dir' ? [process.argv[index + 1]] : []);
const overrides = process.argv.flatMap((arg, index) => arg === '--config' ? [process.argv[index + 1]] : []);
fs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify({cwd,policy,directories,overrides,nodePath:process.env.CODEX_MCP_NODE_PATH,nodeTarget:fs.realpathSync.native(process.env.CODEX_MCP_NODE_PATH), proxies: Object.fromEntries(${JSON.stringify(Object.keys(proxies))}.map(key => [key,process.env[key]]))}) + '\\n');
console.log(JSON.stringify({type:'thread.started', thread_id:'synthetic-thread'}));
if (fs.existsSync(${JSON.stringify(fail)})) {
 console.log(JSON.stringify({type:'turn.failed',error:{message:'synthetic retryable failure'}}));
} else {
 console.log(JSON.stringify({type:'item.completed', item:{id:'message',type:'agent_message',text:'ok'}}));
 console.log(JSON.stringify({type:'turn.completed',usage:{input_tokens:1,cached_input_tokens:0,output_tokens:1}}));
}
`,
      { mode: 0o755 },
    );
    const ambientNode = path.join(root, "ambient-node", "bin", "node");
    fs.mkdirSync(path.dirname(ambientNode), { recursive: true });
    fs.copyFileSync(
      process.execPath,
      ambientNode,
      fs.constants.COPYFILE_FICLONE,
    );
    const environment = {
      ...proxies,
      CODEX_MCP_NODE_PATH: ambientNode,
      OPENAI_API_KEY: "synthetic-test-key",
      PROMPTFOO_CONFIG_DIR: path.join(root, "state"),
      PROMPTFOO_DISABLE_WAL_MODE: "true",
      PROMPTFOO_DISABLE_TELEMETRY: "1",
      PROMPTFOO_DISABLE_UPDATE: "1",
    };
    const configPath = path.join(root, "config.json");
    const provider = parse(
      fs.readFileSync(path.join(evalRoot, "promptfooconfig.yaml"), "utf8"),
    ).providers[0];
    provider.config.codex_path_override = fakeCodex;
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        extensions,
        providers: [provider],
        prompts: ["hello"],
        tests: [{ assert: [{ type: "equals", value: "ok" }] }],
      }),
    );
    const calibration = parse(
      fs.readFileSync(
        path.join(evalRoot, "promptfooconfig.calibration.yaml"),
        "utf8",
      ),
    ).providers[0];
    calibration.id = provider.id;
    calibration.config.codex_path_override = fakeCodex;
    const customNode = path.join(root, "custom-node", "bin", "node");
    fs.mkdirSync(path.dirname(customNode), { recursive: true });
    fs.copyFileSync(
      process.execPath,
      customNode,
      fs.constants.COPYFILE_FICLONE,
    );
    calibration.config.cli_env.CODEX_MCP_NODE_PATH = customNode;
    const selectedNode = path.join(
      root,
      "selected-node",
      "bin",
      "synthetic-node",
    );
    fs.mkdirSync(path.dirname(selectedNode), { recursive: true });
    fs.copyFileSync(
      process.execPath,
      selectedNode,
      fs.constants.COPYFILE_FICLONE,
    );
    const nodeAlias = path.join(root, "node-alias");
    const nodeDispatcher = path.join(root, "node-runtime", "dispatcher");
    fs.mkdirSync(path.dirname(nodeDispatcher));
    fs.writeFileSync(
      nodeDispatcher,
      `#!/bin/sh
case "$0" in */node-alias) exec '${process.execPath.replaceAll("'", "'\\''")}' "$@" ;; *) echo 'synthetic dispatcher requires node-alias' >&2; exit 42 ;; esac
`,
      { mode: 0o755 },
    );
    fs.symlinkSync(nodeDispatcher, nodeAlias);
    const nodeChoices = [
      customNode,
      path.relative(path.join(os.tmpdir(), "runtime-placeholder"), customNode),
      "node",
      nodeAlias,
      path.join(root, "missing-node"),
      "synthetic-node",
    ];
    const calibrationConfig = path.join(root, "calibration.json");
    fs.mkdirSync(path.join(root, "case"));
    fs.writeFileSync(
      calibrationConfig,
      JSON.stringify({
        extensions,
        defaultTest: {
          options: {
            transformVars: `file://${path.join(import.meta.dirname, "runtime-vars.mts")}`,
          },
        },
        providers: nodeChoices.map((nodePath, index) => ({
          ...calibration,
          label: `custom-runtime-${index}`,
          config: {
            ...calibration.config,
            cli_env: {
              ...calibration.config.cli_env,
              CODEX_MCP_NODE_PATH: nodePath,
              PATH: `${path.dirname(selectedNode)}${path.delimiter}${path.dirname(customNode)}${path.delimiter}${process.env.PATH}`,
            },
          },
        })),
        prompts: ["hello"],
        tests: [
          {
            vars: { calibration_repo_root: root, calibration_repo: "case" },
            assert: [{ type: "equals", value: "ok" }],
          },
        ],
      }),
    );
    const simultaneous = await Promise.all(
      [configPath, calibrationConfig, configPath].map((config, index) =>
        invoke(
          [
            "eval",
            "-c",
            config,
            "--no-cache",
            "--no-share",
            "--no-progress-bar",
          ],
          {
            ...environment,
            CODEX_MCP_NODE_PATH: index === 0 ? undefined : ambientNode,
            PROMPTFOO_CONFIG_DIR: path.join(root, `concurrent-${index}`),
          },
        ),
      ),
    );
    for (const result of simultaneous)
      assert.equal(result.code, 0, result.output);
    const rows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Capture);
    assert.equal(rows.length, 8);
    assert.equal(new Set(rows.map((row) => row.cwd)).size, 3);
    for (const row of rows) {
      assert.deepEqual(row.proxies, proxies);
      assert.match(row.policy, /Synthetic policy/);
      assert.equal(fs.existsSync(row.cwd), false);
      assert.match(
        row.overrides.join("\n"),
        /permissions\.triage_runtime_only\.filesystem\.:workspace_roots="read"/,
      );
      assert.deepEqual(row.directories, [
        ...([customNode, selectedNode, nodeDispatcher].includes(row.nodeTarget)
          ? [path.join(root, "case")]
          : []),
        path.dirname(row.nodeTarget),
        path.dirname(row.nodePath),
        path.dirname(fakeCodex),
      ]);
    }
    assert.equal(rows.filter((row) => row.nodeTarget === customNode).length, 4);
    assert.equal(rows.filter((row) => row.nodePath === nodeAlias).length, 1);
    assert.equal(rows.filter((row) => row.nodePath === selectedNode).length, 1);
    assert.equal(rows.filter((row) => row.nodePath === ambientNode).length, 1);
    assert.equal(
      rows.filter((row) => row.nodePath === fs.realpathSync(process.execPath))
        .length,
      1,
    );

    // Prompt-specific settings merge and render separately for each concurrent
    // case, including the original configuration saved for retry and resume.
    const templatedConfig = path.join(root, "templated.json");
    fs.writeFileSync(
      templatedConfig,
      JSON.stringify({
        extensions,
        providers: [
          {
            ...provider,
            config: {
              ...provider.config,
              cli_env: {
                ...provider.config.cli_env,
                CODEX_MCP_NODE_PATH: "{{node_path}}",
              },
              additional_directories: ["{{permission_root}}"],
            },
          },
        ],
        prompts: [
          "hello",
          {
            id: "hello with an override",
            label: "per-case runtime override",
            config: {
              cli_env: {
                ...provider.config.cli_env,
                CODEX_MCP_NODE_PATH: "{{override_node_path}}",
              },
              additional_directories: ["{{override_permission_root}}"],
            },
          },
        ],
        tests: [customNode, selectedNode].map((nodePath) => ({
          vars: {
            node_path: nodePath,
            permission_root: path.dirname(nodePath),
            override_node_path:
              nodePath === customNode ? selectedNode : customNode,
            override_permission_root: path.dirname(
              nodePath === customNode ? selectedNode : customNode,
            ),
          },
          assert: [{ type: "equals", value: "ok" }],
        })),
      }),
    );
    const templatedEnvironment = {
      ...environment,
      PROMPTFOO_CONFIG_DIR: path.join(root, "templated-state"),
    };
    const startingRows = rows.length;
    fs.writeFileSync(fail, "");
    const templatedInitial = await invoke(
      [
        "eval",
        "-c",
        templatedConfig,
        "--max-concurrency",
        "2",
        "--no-cache",
        "--no-share",
        "--no-progress-bar",
      ],
      templatedEnvironment,
    );
    assert.notEqual(templatedInitial.code, 0, templatedInitial.output);
    assert.match(templatedInitial.output, /synthetic retryable failure/);
    fs.rmSync(fail);
    const templatedRetry = await invoke(
      [
        "eval",
        "--retry-errors",
        "--no-cache",
        "--no-share",
        "--no-progress-bar",
      ],
      templatedEnvironment,
    );
    assert.equal(templatedRetry.code, 0, templatedRetry.output);
    const templatedDatabase = new DatabaseSync(
      path.join(templatedEnvironment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
      { enableForeignKeyConstraints: false },
    );
    templatedDatabase.prepare("DELETE FROM eval_results").run();
    templatedDatabase.close();
    const templatedResume = await invoke(
      ["eval", "--resume", "--no-cache", "--no-share", "--no-progress-bar"],
      templatedEnvironment,
    );
    assert.equal(templatedResume.code, 0, templatedResume.output);
    const templatedRows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Capture)
      .slice(startingRows);
    assert.equal(templatedRows.length, 12);
    assert.equal(new Set(templatedRows.map((row) => row.cwd)).size, 3);
    assert.equal(
      templatedRows.filter((row) => row.nodePath === customNode).length,
      6,
    );
    assert.equal(
      templatedRows.filter((row) => row.nodePath === selectedNode).length,
      6,
    );
    for (const row of templatedRows) {
      assert.deepEqual(row.proxies, proxies);
      assert.equal(fs.existsSync(row.cwd), false);
      assert.deepEqual(row.directories, [
        path.dirname(row.nodePath),
        path.dirname(row.nodePath),
        path.dirname(row.nodePath),
        path.dirname(fakeCodex),
      ]);
    }
  },
);

test(
  "provider resolves each call's Node template without leaking sibling configuration",
  { skip: process.platform === "win32", timeout: 120000 },
  async (t) => {
    const root = fs.realpathSync(
      fs.mkdtempSync(path.join(os.tmpdir(), "triage-provider-vars-")),
    );
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const nodes = [
      "first & node/node",
      "second/node",
      "literal/{{custom_node}}",
    ].map((name) => path.join(root, name)) as [string, string, string];
    for (const node of nodes) {
      fs.mkdirSync(path.dirname(node), { recursive: true });
      fs.writeFileSync(node, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    }
    const extra = path.join(root, "extra");
    fs.mkdirSync(extra);
    const fakeCodex = path.join(root, "codex");
    fs.writeFileSync(
      fakeCodex,
      `#!${process.execPath}
const details = {executable:process.env.CODEX_TEST_EXECUTABLE || require('node:fs').realpathSync(process.argv[1]), path:process.env.PATH, node:process.env.CODEX_MCP_NODE_PATH, marker:process.env.EXTRA_MARKER, directories:process.argv.flatMap((arg,index)=>arg==='--add-dir'?[process.argv[index+1]]:[])};
console.log(JSON.stringify({type:'thread.started',thread_id:'synthetic-thread'}));
console.log(JSON.stringify({type:'item.completed',item:{id:'message',type:'agent_message',text:JSON.stringify(details)}}));
console.log(JSON.stringify({type:'turn.completed',usage:{input_tokens:1,cached_input_tokens:0,output_tokens:1}}));
`,
      { mode: 0o755 },
    );
    const environment = {
      TRIAGE_RUNTIME_ROOT: root,
      PROMPTFOO_CONFIG_DIR: path.join(root, "state"),
      PROMPTFOO_DISABLE_TELEMETRY: "1",
      PROMPTFOO_DISABLE_UPDATE: "1",
      PROMPTFOO_DISABLE_WAL_MODE: "true",
      PROMPTFOO_DISABLE_TEMPLATING: "",
      NODE_BASENAME: "node",
      CODEX_MCP_NODE_PATH: "",
      OPENAI_API_KEY: "synthetic-test-key",
    };
    const original = new Map(
      Object.keys(environment).map((key) => [key, process.env[key]]),
    );
    t.after(() => {
      for (const [key, value] of original) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });
    Object.assign(process.env, environment);
    const { loadApiProvider } = await import("promptfoo");
    const load = (
      template: string | undefined,
      command = fakeCodex,
      cliEnvironment: Record<string, string> = {},
    ) =>
      loadApiProvider("openai:codex-sdk:gpt-5.5", {
        basePath: root,
        options: {
          config: {
            working_dir: root,
            codex_path_override: command,
            skip_git_repo_check: true,
            model: "gpt-5.5",
            maxRetries: 0,
            cli_env: {
              ...cliEnvironment,
              EXTRA_MARKER: "{{marker}}",
              ...(template === undefined
                ? {}
                : { CODEX_MCP_NODE_PATH: template }),
            },
          },
        },
      }).then((provider) => {
        beforeAll({ suite: { providers: [provider] } });
        return provider;
      });
    for (const template of [
      "{{custom_node}}",
      '{{custom_node | replace("second", "second")}}',
      "{{custom_node_json | load}}",
      nodes[0],
    ]) {
      const provider = await load(template);
      const overrides = template === nodes[0];
      const invoke = async (node: string) => {
        const context = {
          vars: {
            custom_node: node,
            custom_node_json: JSON.stringify(node),
            marker: node,
          },
          prompt: { raw: "synthetic", label: "synthetic" },
          ...(overrides
            ? {
                prompt: {
                  raw: "synthetic",
                  label: "synthetic",
                  config: {
                    cli_env: {
                      CODEX_MCP_NODE_PATH: "{{custom_node}}",
                      EXTRA_MARKER: "{{marker}}",
                    },
                    additional_directories: [extra],
                  },
                },
              }
            : {}),
        };
        const saved = structuredClone(context);
        const result = await provider.callApi(
          "Return synthetic launch details",
          context as Parameters<typeof provider.callApi>[1],
        );
        assert.equal(result.error, undefined);
        const captured = JSON.parse(String(result.output));
        assert.equal(captured.node, node);
        assert.deepEqual(captured.directories, [
          ...(overrides ? [extra] : []),
          path.dirname(node),
          path.dirname(node),
          path.dirname(fakeCodex),
        ]);
        if (overrides) assert.equal(captured.marker, node);
        assert.deepEqual(context, saved);
      };
      try {
        for (const node of nodes.slice(0, 2)) await invoke(node);
        await Promise.all(nodes.slice(0, 2).map(invoke));
      } finally {
        await provider.cleanup?.();
      }
    }
    for (const sibling of [false, true]) {
      const nodeRoot = path.join(
        root,
        sibling ? "node-sibling" : "node-missing",
      );
      const target = path.join(nodeRoot, "target", "node");
      const alias = path.join(nodeRoot, "alias");
      fs.mkdirSync(path.join(nodeRoot, "target", "child"), { recursive: true });
      fs.copyFileSync(nodes[0], target);
      fs.symlinkSync(path.join(nodeRoot, "target", "child"), alias);
      if (sibling) fs.copyFileSync(nodes[1], path.join(nodeRoot, "node"));
      for (const [command, expected, searchPath] of [
        [`${alias}/../node`, target, process.env.PATH],
        [`${path.relative(root, alias)}/../node`, target, process.env.PATH],
        ["node", target, `${alias}/..`],
        ["node", target, `${path.relative(root, alias)}/..`],
        [
          path.join(nodeRoot, "target") + "/child/../node",
          target,
          process.env.PATH,
        ],
        [path.join(nodeRoot, "missing"), nodes[0], path.dirname(nodes[0])],
      ] as const) {
        const provider = await load(command, fakeCodex, { PATH: searchPath! });
        try {
          const result = await provider.callApi("synthetic");
          assert.equal(result.error, undefined);
          const captured = JSON.parse(String(result.output));
          assert.equal(
            fs.realpathSync.native(captured.node),
            expected,
            command,
          );
          assert.deepEqual(captured.directories, [
            path.dirname(expected),
            path.dirname(captured.node),
            path.dirname(fakeCodex),
          ]);
        } finally {
          await provider.cleanup?.();
        }
      }
    }
    const alias = path.join(root, "codex-alias");
    fs.symlinkSync(fakeCodex, alias);
    const selectedPath = `${root}${path.delimiter}${process.env.PATH}`;
    const builtinCodex = path.join(root, "test");
    fs.copyFileSync(fakeCodex, builtinCodex);
    const literalCodex = path.join(root, String.raw`codex\probe`);
    fs.copyFileSync(fakeCodex, literalCodex);
    const targetRoot = path.join(root, "path-target");
    fs.mkdirSync(path.join(targetRoot, "child"), { recursive: true });
    const directoryAlias = path.join(root, "path-alias");
    fs.symlinkSync(path.join(targetRoot, "child"), directoryAlias);
    const targetCodex = path.join(targetRoot, "codex");
    const shellQuote = (value: string) =>
      "'" + value.replaceAll("'", "'\\''") + "'";
    fs.writeFileSync(
      targetCodex,
      `#!/bin/sh\nCODEX_TEST_EXECUTABLE=${shellQuote(targetCodex)} exec ${shellQuote(process.execPath)} ${shellQuote(fakeCodex)} "$@"\n`,
      { mode: 0o755 },
    );
    const relativePath = path.relative(process.cwd(), root);
    for (const [command, executable, searchPath] of [
      [fakeCodex, fakeCodex, selectedPath],
      [path.relative(process.cwd(), fakeCodex), fakeCodex, selectedPath],
      [path.basename(fakeCodex), fakeCodex, selectedPath],
      [alias, fakeCodex, selectedPath],
      ["test", builtinCodex, selectedPath],
      [path.basename(literalCodex), literalCodex, selectedPath],
      ["codex", targetCodex, `${directoryAlias}/..`],
      [
        "codex",
        targetCodex,
        `${path.relative(process.cwd(), directoryAlias)}/..`,
      ],
      [`${directoryAlias}/../codex`, targetCodex, selectedPath],
      ["test", builtinCodex, relativePath],
      ["test", builtinCodex, `${path.delimiter}${relativePath}`],
    ] as const) {
      const provider = await load(nodes[0], command, { PATH: searchPath });
      try {
        const result = await provider.callApi("synthetic");
        assert.equal(result.error, undefined);
        const captured = JSON.parse(String(result.output));
        assert.equal(captured.executable, executable);
        assert.equal(captured.path, searchPath);
        assert.deepEqual(captured.directories, [
          path.dirname(nodes[0]),
          path.dirname(nodes[0]),
          path.dirname(executable),
        ]);
      } finally {
        await provider.cleanup?.();
      }
    }
    const otherCodex = path.join(root, "other", "codex");
    fs.mkdirSync(path.dirname(otherCodex));
    fs.copyFileSync(fakeCodex, otherCodex);
    const selectedCodex = await load(nodes[0], "{{selected_codex}}");
    try {
      await Promise.all(
        [fakeCodex, otherCodex, fakeCodex].map(async (command) => {
          const context = {
            vars: { selected_codex: command },
            prompt: { raw: "synthetic", label: "synthetic" },
          };
          const result = await selectedCodex.callApi("synthetic", context);
          assert.equal(result.error, undefined);
          const captured = JSON.parse(String(result.output));
          assert.equal(captured.executable, command);
          assert.deepEqual(captured.directories, [
            path.dirname(nodes[0]),
            path.dirname(nodes[0]),
            path.dirname(command),
          ]);
          assert.deepEqual(context, {
            vars: { selected_codex: command },
            prompt: { raw: "synthetic", label: "synthetic" },
          });
        }),
      );
    } finally {
      await selectedCodex.cleanup?.();
    }
    const packages = ["first", "second", "vendored"].map((name) => {
      const modules = path.join(root, name, "node_modules", "@openai");
      const packageRoot = path.join(modules, "codex");
      const nativePackage =
        name === "vendored"
          ? packageRoot
          : path.join(modules, `codex-${process.platform}-${process.arch}`);
      const nativeRoot = path.join(nativePackage, "vendor", "synthetic-target");
      const native = path.join(nativeRoot, "bin", "codex");
      const tools = path.join(nativeRoot, "codex-path");
      const launcher = path.join(packageRoot, "bin", "codex.js");
      fs.mkdirSync(path.dirname(launcher), { recursive: true });
      fs.mkdirSync(path.dirname(native), { recursive: true });
      fs.mkdirSync(tools);
      fs.writeFileSync(
        path.join(packageRoot, "package.json"),
        JSON.stringify({
          name: "@openai/codex",
          bin: { codex: "bin/codex.js" },
        }),
      );
      if (name !== "vendored")
        fs.writeFileSync(path.join(nativePackage, "package.json"), "{}");
      fs.copyFileSync(fakeCodex, native);
      fs.writeFileSync(
        launcher,
        `#!${process.execPath}
const child = require('node:child_process').spawnSync(${JSON.stringify(native)}, process.argv.slice(2), {stdio:'inherit',env:process.env});
process.exit(child.status ?? 1);
`,
        { mode: 0o755 },
      );
      return {
        launcher,
        native,
        tools,
        configured: name === "vendored" ? [path.dirname(native), tools] : [],
      };
    });
    const packaged = await load(nodes[0], "{{selected_codex}}");
    try {
      await Promise.all(
        packages.map(async ({ launcher, native, tools, configured }) => {
          const result = await packaged.callApi("synthetic", {
            vars: { selected_codex: launcher },
            prompt: {
              raw: "synthetic",
              label: "synthetic",
              config: { additional_directories: configured },
            },
          });
          assert.equal(result.error, undefined);
          const captured = JSON.parse(String(result.output));
          assert.equal(captured.executable, native);
          assert.equal(captured.path, process.env.PATH);
          assert.deepEqual(captured.directories, [
            ...configured,
            path.dirname(nodes[0]),
            path.dirname(nodes[0]),
            path.dirname(launcher),
            ...(configured.length ? [] : [path.dirname(native), tools]),
          ]);
        }),
      );
    } finally {
      await packaged.cleanup?.();
    }
    const mixed = await load("{{prefix}}/{{env.NODE_BASENAME}}");
    try {
      const result = await mixed.callApi("synthetic", {
        vars: { prefix: path.dirname(nodes[1]) },
        prompt: { raw: "synthetic", label: "synthetic" },
      });
      assert.equal(JSON.parse(String(result.output)).node, nodes[1]);
    } finally {
      await mixed.cleanup?.();
    }
    for (const [ambient, template, value, expected] of [
      [undefined, undefined, "", process.execPath],
      ["", undefined, "", process.execPath],
      [nodes[0], "", "", process.execPath],
      [nodes[0], "{{custom_node}}", "", process.execPath],
      [undefined, "{{missing_node}}", "", process.execPath],
      [nodes[0], undefined, "", nodes[0]],
      [nodes[0], "{{custom_node}}", nodes[1]!, nodes[1]],
    ] as const) {
      if (ambient === undefined) delete process.env.CODEX_MCP_NODE_PATH;
      else process.env.CODEX_MCP_NODE_PATH = ambient;
      const provider = await load(template);
      try {
        const result = await provider.callApi("synthetic", {
          vars: { custom_node: value },
          prompt: { raw: "synthetic", label: "synthetic" },
        });
        assert.equal(result.error, undefined);
        const captured = JSON.parse(String(result.output));
        const selected = fs.realpathSync(expected!);
        assert.equal(captured.node, selected);
        assert.deepEqual(captured.directories, [
          path.dirname(selected),
          path.dirname(captured.node),
          path.dirname(fakeCodex),
        ]);
      } finally {
        await provider.cleanup?.();
      }
    }
    const withoutContext = await load(nodes[0]);
    try {
      const result = await withoutContext.callApi("synthetic");
      const captured = JSON.parse(String(result.output));
      assert.equal(captured.node, nodes[0]);
      assert.equal(captured.marker, "{{marker}}");
    } finally {
      await withoutContext.cleanup?.();
    }
    process.env.PROMPTFOO_DISABLE_TEMPLATING = "true";
    const disabled = await load(nodes[2]!);
    try {
      const result = await disabled.callApi("synthetic", {
        vars: { custom_node: "other" },
        prompt: { raw: "synthetic", label: "synthetic" },
      });
      assert.equal(JSON.parse(String(result.output)).node, nodes[2]);
    } finally {
      await disabled.cleanup?.();
    }
  },
);

test(
  "saved native-provider configs retain legacy paths through retry, resume, and viewer replay",
  { skip: process.platform === "win32", timeout: 120000 },
  async (t) => {
    const root = fs.realpathSync(
      fs.mkdtempSync(path.join(os.tmpdir(), "legacy-provider-")),
    );
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    // Keep the saved source layout independent of the checkout and its path.
    const legacySourceRoot = path.join(root, "source.checkout");
    const legacyEvalRoot = path.join(
      legacySourceRoot,
      "evals",
      "triage-finding",
    );
    const legacyTransform = path.join(
      legacyEvalRoot,
      "scripts",
      "runtime-vars.mts",
    );
    fs.mkdirSync(path.dirname(legacyTransform), { recursive: true });
    fs.copyFileSync(
      path.join(import.meta.dirname, "runtime-vars.mts"),
      legacyTransform,
    );
    const skill = path.join(
      legacySourceRoot,
      "plugins",
      "codex-security",
      "skills",
      "triage-finding",
      "SKILL.md",
    );
    fs.mkdirSync(path.dirname(skill), { recursive: true });
    fs.writeFileSync(skill, "Synthetic legacy skill fixture.\n");
    const fixture = path.join(
      legacyEvalRoot,
      "fixtures",
      "repo",
      "src",
      "server.js",
    );
    fs.mkdirSync(path.dirname(fixture), { recursive: true });
    fs.writeFileSync(fixture, "// Synthetic repository fixture.\n");
    const capture = path.join(root, "captures.jsonl");
    const failure = path.join(root, "failure");
    const fakeCodex = path.join(root, "codex");
    fs.writeFileSync(
      fakeCodex,
      `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const cwd = process.argv[process.argv.indexOf('--cd') + 1];
const prompt = fs.readFileSync(0, 'utf8');
const target = prompt.match(/^TARGET=(.+)$/m)[1];
const skill = fs.readFileSync(path.join(cwd, 'skills/triage-finding/SKILL.md'), 'utf8');
fs.readFileSync(path.join(target, 'src/server.js'), 'utf8');
fs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify({cwd,target,skillLoaded:skill.length>0,nodePath:process.env.CODEX_MCP_NODE_PATH,directories:process.argv.flatMap((arg,index)=>arg==='--add-dir'?[process.argv[index+1]]:[])})+'\\n');
console.log(JSON.stringify({type:'thread.started',thread_id:'synthetic-legacy'}));
if (fs.existsSync(${JSON.stringify(failure)})) {
 console.log(JSON.stringify({type:'turn.failed',error:{message:'synthetic legacy retryable failure'}}));
} else {
 console.log(JSON.stringify({type:'item.completed',item:{id:'message',type:'agent_message',text:'ok'}}));
 console.log(JSON.stringify({type:'turn.completed',usage:{input_tokens:1,output_tokens:1}}));
}
`,
      { mode: 0o755 },
    );
    const configPath = path.join(root, "config.json");
    // These are the native-provider placeholders saved by the previous configs.
    // No startup extension is available when Promptfoo reloads those records.
    const provider = {
      id: "openai:codex-sdk:gpt-5.5",
      config: {
        working_dir: "{{triage_runtime_root}}",
        codex_path_override: fakeCodex,
        skip_git_repo_check: true,
        approval_policy: "never",
        additional_directories: [
          "{{triage_fixture_root}}",
          "{{triage_node_root}}",
        ],
        cli_env: { CODEX_MCP_NODE_PATH: "{{triage_node_path}}" },
      },
    };
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        providers: [provider],
        prompts: [
          "Read and follow skills/triage-finding/SKILL.md.\nTARGET={{target_repo}}",
        ],
        defaultTest: {
          options: {
            transformVars: `file://${legacyTransform}`,
          },
        },
        tests: [
          {
            vars: { target_repo: "evals/triage-finding/fixtures/repo" },
            assert: [{ type: "equals", value: "ok" }],
          },
        ],
      }),
    );
    const environment = {
      OPENAI_API_KEY: "synthetic-test-key",
      PROMPTFOO_CONFIG_DIR: path.join(root, "state"),
      PROMPTFOO_DISABLE_WAL_MODE: "true",
      PROMPTFOO_DISABLE_TELEMETRY: "1",
      PROMPTFOO_DISABLE_UPDATE: "1",
    };
    fs.writeFileSync(failure, "");
    const initial = await invoke(
      [
        "eval",
        "-c",
        configPath,
        "--no-cache",
        "--no-share",
        "--no-progress-bar",
      ],
      environment,
    );
    assert.notEqual(initial.code, 0, initial.output);
    assert.match(initial.output, /synthetic legacy retryable failure/);
    fs.rmSync(failure);
    const retry = await invoke(
      [
        "eval",
        "--retry-errors",
        "--no-cache",
        "--no-share",
        "--no-progress-bar",
      ],
      environment,
    );
    assert.equal(retry.code, 0, retry.output);
    const database = new DatabaseSync(
      path.join(environment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
      { enableForeignKeyConstraints: false },
    );
    const stored = database
      .prepare("SELECT id, config FROM evals ORDER BY created_at DESC LIMIT 1")
      .get();
    assert.ok(stored && typeof stored.config === "string");
    const saved = JSON.parse(stored.config);
    assert.equal(saved.providers[0].id, provider.id);
    assert.equal(
      saved.providers[0].config.working_dir,
      "{{triage_runtime_root}}",
    );
    assert.equal(saved.extensions?.length || 0, 0);
    database.exec("DELETE FROM eval_results");
    database.close();
    const resumed = await invoke(
      ["eval", "--resume", "--no-cache", "--no-share", "--no-progress-bar"],
      environment,
    );
    assert.equal(resumed.code, 0, resumed.output);
    const resumedDatabase = new DatabaseSync(
      path.join(environment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
      { enableForeignKeyConstraints: false },
    );
    const resumedResult = resumedDatabase
      .prepare(
        "SELECT metadata, test_case FROM eval_results WHERE eval_id = ? LIMIT 1",
      )
      .get(String(stored.id));
    resumedDatabase.close();
    assert.ok(resumedResult && typeof resumedResult.test_case === "string");
    const replayVariables =
      JSON.parse((resumedResult.metadata as string) || "{}").inputVars ||
      JSON.parse(resumedResult.test_case).vars;
    const listener = createServer();
    await new Promise<void>((resolve) =>
      listener.listen(0, "127.0.0.1", resolve),
    );
    const address = listener.address();
    assert.ok(address && typeof address !== "string");
    const port = address.port;
    await new Promise<void>((resolve, reject) =>
      listener.close((error) => (error ? reject(error) : resolve())),
    );
    const viewer = spawn(
      process.execPath,
      [
        "--experimental-strip-types",
        runner,
        "view",
        "--port",
        String(port),
        "--no",
      ],
      {
        cwd: evalRoot,
        env: { ...process.env, ...environment, NODE_USE_ENV_PROXY: "" },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let viewerOutput = "";
    for (const stream of [viewer.stdout, viewer.stderr])
      stream.on("data", (chunk) => {
        viewerOutput += chunk;
      });
    const closed = new Promise<number | null>((resolve, reject) => {
      viewer.once("error", reject);
      viewer.once("close", resolve);
    });
    t.after(async () => {
      if (viewer.exitCode === null) viewer.kill("SIGTERM");
      await closed;
    });
    const url = `http://127.0.0.1:${port}`;
    while (true) {
      try {
        if ((await fetch(`${url}/api/eval`)).ok) break;
      } catch {}
      assert.equal(viewer.exitCode, null, viewerOutput);
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const replay = await fetch(`${url}/api/eval/replay`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        evaluationId: stored.id,
        testIndex: 0,
        prompt:
          "Read and follow skills/triage-finding/SKILL.md.\nTARGET=" +
          replayVariables.target_repo,
        variables: replayVariables,
      }),
    });
    assert.equal(replay.status, 200, viewerOutput);
    const replayResult = (await replay.json()) as { output: unknown };
    assert.equal(replayResult.output, "ok", JSON.stringify(replayResult));
    viewer.kill("SIGTERM");
    await closed;
    const rows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(rows.length, 4);
    assert.equal(new Set(rows.map((row) => row.cwd)).size, 1);
    const nodePath = fs.realpathSync(process.execPath);
    for (const row of rows) {
      const runtimeRoot = legacySourceRoot;
      const fixtureRoot = path.join(
        runtimeRoot,
        "evals",
        "triage-finding",
        "fixtures",
      );
      assert.equal(
        row.cwd,
        path.join(runtimeRoot, "plugins", "codex-security"),
      );
      assert.equal(row.target, path.join(fixtureRoot, "repo"));
      assert.equal(row.nodePath, nodePath);
      assert.deepEqual(row.directories, [fixtureRoot, path.dirname(nodePath)]);
      assert.equal(row.skillLoaded, true);
      assert.equal(fs.existsSync(row.cwd), true);
    }
  },
);

for (const suite of ["SAST", "calibration"] as const) {
  test(
    `${suite} provider survives persisted retry, resume, and viewer replay`,
    { skip: process.platform === "win32", timeout: 120000 },
    async (t) => {
      const root = fs.realpathSync(
        fs.mkdtempSync(path.join(os.tmpdir(), "sast-provider-replay-")),
      );
      t.after(() => fs.rmSync(root, { recursive: true, force: true }));
      const targetRoot = fs.realpathSync(
        fs.mkdtempSync(path.join(os.tmpdir(), "sast-custom-target-")),
      );
      t.after(() => fs.rmSync(targetRoot, { recursive: true, force: true }));
      const targetRepository = path.join(targetRoot, "selected-case");
      const siblingRepository = path.join(targetRoot, "other-case");
      fs.mkdirSync(targetRepository);
      fs.mkdirSync(siblingRepository);
      const capture = path.join(root, "captures.jsonl");
      const failure = path.join(root, "failure");
      const fakeCodex = path.join(root, "codex");
      fs.writeFileSync(
        fakeCodex,
        `#!${process.execPath}
const fs = require('node:fs');
const cwd = process.argv[process.argv.indexOf('--cd') + 1];
fs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify({ cwd, directories: process.argv.flatMap((arg, index) => arg === '--add-dir' ? [process.argv[index + 1]] : []) }) + '\\n');
console.log(JSON.stringify({ type: 'thread.started', thread_id: 'synthetic-sast-replay' }));
if (fs.existsSync(${JSON.stringify(failure)})) {
 console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'synthetic retryable failure' } }));
} else {
 console.log(JSON.stringify({ type: 'item.completed', item: { id: 'message', type: 'agent_message', text: 'ok' } }));
 console.log(JSON.stringify({ type: 'turn.completed', usage: { input_tokens: 1, output_tokens: 1 } }));
}
`,
        { mode: 0o755 },
      );
      const environment = {
        OPENAI_API_KEY: "synthetic-test-key",
        CODEX_MCP_NODE_PATH: process.execPath,
        PROMPTFOO_CONFIG_DIR: path.join(root, "state"),
        PROMPTFOO_DISABLE_WAL_MODE: "true",
        PROMPTFOO_DISABLE_TELEMETRY: "1",
        PROMPTFOO_DISABLE_UPDATE: "1",
      };
      const template = parse(
        fs.readFileSync(
          path.join(
            evalRoot,
            suite === "SAST"
              ? "sastbench/promptfooconfig.sastbench.yaml"
              : "promptfooconfig.calibration.yaml",
          ),
          "utf8",
        ),
      );
      const provider = template.providers[0];
      provider.config.codex_path_override = fakeCodex;
      // Keep the real YAML provider reference and its original configuration directory.
      const configPath = path.join(
        evalRoot,
        suite === "SAST" ? "sastbench" : ".",
        `.provider-replay-${process.pid}.json`,
      );
      t.after(() => fs.rmSync(configPath, { force: true }));
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          extensions: template.extensions,
          providers: [provider],
          prompts: ["hello"],
          defaultTest:
            suite === "calibration"
              ? {
                  options: {
                    transformVars: `file://${path.join(import.meta.dirname, "runtime-vars.mts")}`,
                  },
                }
              : undefined,
          tests: [
            {
              metadata:
                suite === "SAST"
                  ? { ground_truth: "true_positive" }
                  : undefined,
              vars:
                suite === "SAST"
                  ? { target_repo: targetRepository }
                  : {
                      calibration_repo: "calibration-0123456789abcdef",
                      calibration_repo_root: "",
                    },
              assert: [{ type: "equals", value: "ok" }],
            },
          ],
        }),
      );
      fs.writeFileSync(failure, "");
      const initial = await invoke(
        [
          "eval",
          "-c",
          configPath,
          "--no-cache",
          "--no-share",
          "--no-progress-bar",
        ],
        environment,
      );
      assert.notEqual(initial.code, 0, initial.output);
      assert.match(initial.output, /synthetic retryable failure/);
      if (suite === "SAST") {
        const initialDatabase = new DatabaseSync(
          path.join(environment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
          { enableForeignKeyConstraints: false },
        );
        const initialResult = initialDatabase
          .prepare("SELECT metadata FROM eval_results LIMIT 1")
          .get();
        initialDatabase.close();
        assert.ok(
          JSON.parse((initialResult?.metadata as string) || "{}").sastbench,
          initial.output,
        );
      }
      fs.rmSync(failure);
      const retry = await invoke(
        [
          "eval",
          "--retry-errors",
          "--no-cache",
          "--no-share",
          "--no-progress-bar",
        ],
        environment,
      );
      assert.equal(retry.code, 0, retry.output);
      const database = new DatabaseSync(
        path.join(environment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
        { enableForeignKeyConstraints: false },
      );
      const stored = database
        .prepare(
          "SELECT id, config FROM evals ORDER BY created_at DESC LIMIT 1",
        )
        .get();
      assert.ok(stored && typeof stored.config === "string");
      assert.equal(JSON.parse(stored.config).providers[0].id, provider.id);
      assert.deepEqual(
        JSON.parse(stored.config).extensions,
        template.extensions.map((extension: string) =>
          extension.replace(
            "{{env.TRIAGE_PROVIDER_PATH}}",
            path.join(import.meta.dirname, "triage-provider.mts"),
          ),
        ),
      );
      database.prepare("DELETE FROM eval_results").run();
      database.close();
      const resumed = await invoke(
        ["eval", "--resume", "--no-cache", "--no-share", "--no-progress-bar"],
        environment,
      );
      assert.equal(resumed.code, 0, resumed.output);

      const resumedDatabase = new DatabaseSync(
        path.join(environment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
        { enableForeignKeyConstraints: false },
      );
      const resumedResult = resumedDatabase
        .prepare(
          "SELECT metadata, test_case FROM eval_results WHERE eval_id = ? LIMIT 1",
        )
        .get(String(stored.id));
      resumedDatabase.close();
      assert.ok(resumedResult && typeof resumedResult.test_case === "string");
      // Match the viewer: prefer saved inputVars, then the resolved test-case vars.
      const replayVariables =
        JSON.parse((resumedResult.metadata as string | null) ?? "{}")
          .inputVars || JSON.parse(resumedResult.test_case).vars;
      assert.equal(typeof replayVariables.target_repo, "string");

      const listener = createServer();
      await new Promise<void>((resolve) =>
        listener.listen(0, "127.0.0.1", resolve),
      );
      const address = listener.address();
      assert.ok(address && typeof address !== "string");
      const port = address.port;
      await new Promise<void>((resolve, reject) =>
        listener.close((error) => (error ? reject(error) : resolve())),
      );
      const viewer = spawn(
        process.execPath,
        [
          "--experimental-strip-types",
          runner,
          "view",
          "--port",
          String(port),
          "--no",
        ],
        {
          cwd: evalRoot,
          env: { ...process.env, ...environment, NODE_USE_ENV_PROXY: "" },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let viewerOutput = "";
      for (const stream of [viewer.stdout, viewer.stderr])
        stream.on("data", (chunk) => {
          viewerOutput += chunk;
        });
      const closed = new Promise<number | null>((resolve, reject) => {
        viewer.once("error", reject);
        viewer.once("close", resolve);
      });
      t.after(async () => {
        if (viewer.exitCode === null) viewer.kill("SIGTERM");
        await closed;
      });
      const url = `http://127.0.0.1:${port}`;
      while (true) {
        try {
          const response = await fetch(`${url}/api/eval`);
          if (response.ok) break;
        } catch {
          /* The actual viewer is still building its staged runtime. */
        }
        assert.equal(viewer.exitCode, null, viewerOutput);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const replay = await fetch(`${url}/api/eval/replay`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          evaluationId: stored.id,
          testIndex: 0,
          prompt: "hello",
          variables: replayVariables,
        }),
      });
      assert.equal(replay.status, 200, viewerOutput);
      const replayResult = (await replay.json()) as { output: unknown };
      assert.equal(replayResult.output, "ok", JSON.stringify(replayResult));
      viewer.kill("SIGTERM");
      await closed;
      assert.doesNotMatch(viewerOutput, /afterEach extension hook failed/);
      const rows = fs
        .readFileSync(capture, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      assert.equal(rows.length, 4);
      assert.equal(new Set(rows.map((row) => row.cwd)).size, 4);
      for (const row of rows) {
        assert.equal(fs.existsSync(row.cwd), false);
        assert.deepEqual(row.directories, [
          ...(suite === "SAST"
            ? [
                path.join(evalRoot, "artifacts", "sastbench-git-cache"),
                targetRepository,
              ]
            : [
                path.join(
                  evalRoot,
                  "artifacts",
                  "calibration-repos",
                  "calibration-0123456789abcdef",
                ),
              ]),
          path.dirname(fs.realpathSync(process.execPath)),
          path.dirname(process.execPath),
          path.dirname(fakeCodex),
        ]);
        assert.ok(
          row.directories.every(
            (directory: string) =>
              siblingRepository !== directory &&
              !siblingRepository.startsWith(directory + path.sep),
          ),
        );
      }
    },
  );
}
