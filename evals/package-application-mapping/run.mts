import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import * as auth from "../../sdk/typescript/dist/auth.js";
import { readSkillCommandOutput } from "../../sdk/typescript/dist/cli.js";
import { untrustedProjectConfigOverrides } from "../../sdk/typescript/dist/config.js";
import { openDependencyGraph } from "../../sdk/typescript/dist/dependency-graph-tools.js";
import { createDependencyServiceCatalog } from "../../sdk/typescript/dist/dependency-service-catalog.js";
import { preflightReadOnlyProfileCodex } from "../../sdk/typescript/dist/provider-profile.js";
import {
  createIsolatedHome,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../../sdk/typescript/dist/thread-source.js";
import { modelSettings } from "../dependency-reachability/model.mts";
import { withEvalState } from "../secret-discovery/runtime.mts";
import {
  cases,
  catalogServer,
  catalogTool,
  type MappingCase,
} from "./cases.mts";
import { gradeMapping } from "./grade.mts";

const { values } = parseArgs({
  options: {
    case: { type: "string" },
    model: { type: "string" },
    effort: { type: "string", default: "medium" },
  },
});
const selected = cases.filter((c) => !values.case || values.case === c.id);
if (!selected.length) throw new Error(`Unknown case ${values.case}`);

const sdk = join(import.meta.dirname, "../../sdk/typescript");
const plugin = join(sdk, "_bundled_plugin");
const skill = await readFile(
  join(plugin, "skills/dependency-exploitability/SKILL.md"),
  "utf8",
);
const start = skill.indexOf("\n## Identify the service\n");
const end = skill.indexOf("\n## Check deployment and access\n");
if (start < 0 || end <= start) throw new Error("Rebuild the bundled plugin.");
const guidance = skill.slice(start, end).trim();
const reports = join(import.meta.dirname, "reports");
await mkdir(reports, { recursive: true });
const output = await mkdtemp(join(reports, "mapping-"));
console.log(`Eval artifacts: ${output}`);

async function runCase(
  c: MappingCase,
  root: string,
  settings: ReturnType<typeof modelSettings>,
  interrupted: AbortSignal,
) {
  const scratch = await mkdtemp(join(root, "case-"));
  const checkout = join(scratch, "checkout");
  const catalogPath = join(scratch, "catalog.json");
  const snapshots: unknown[] = [];
  const catalogUsage: unknown[] = [];
  const controller = new AbortController();
  const signal = AbortSignal.any([
    controller.signal,
    interrupted,
    AbortSignal.timeout(180_000),
  ]);
  let graph: Awaited<ReturnType<typeof openDependencyGraph>> | undefined;
  let catalog: ReturnType<typeof createDependencyServiceCatalog> | undefined;
  let usage: unknown;
  let diagnostics = "";
  let error: string | undefined;
  const started = performance.now();
  try {
    for (const [path, content] of Object.entries(c.files)) {
      const file = join(checkout, path);
      await mkdir(dirname(file), { recursive: true });
      await writeFile(file, content);
    }
    const prompt = `Which configured applications in this checkout use the package ${JSON.stringify(c.package)}?
Find source references using trace_codex_security_code. Use the configured service catalog resolver for application identities. If there is a shared library, follow it to the consuming project before requesting its service mapping. When finished, query the graph by each matching source file path so the final tool results show its mappings.

${guidance}`;
    const servers = c.catalog && {
      [catalogServer]: {
        command: process.execPath,
        args: [
          "--experimental-strip-types",
          join(import.meta.dirname, "catalog.mts"),
          catalogPath,
        ],
        enabled_tools: [catalogTool],
      },
    };
    if (c.catalog)
      await writeFile(catalogPath, JSON.stringify(c.catalog), { mode: 0o600 });
    const catalogRuntime = {
      model: values.model,
      reasoningEffort: values.effort,
      selectedEnvironment: settings.env,
      onUsage(observed: unknown) {
        catalogUsage.push(observed);
      },
    };
    if (servers)
      catalog = createDependencyServiceCatalog({
        servers,
        repository: checkout,
        runtime: catalogRuntime,
        signal,
      });
    graph = await openDependencyGraph(
      plugin,
      checkout,
      catalog?.resolve,
      signal,
    );
    const session = graph;
    const config = [
      ...settings.configOverrides,
      ...untrustedProjectConfigOverrides(checkout),
      ...(values.model ? [`model=${JSON.stringify(values.model)}`] : []),
      "features.multi_agent_v2=false",
      "mcp_servers={}",
      "project_doc_max_bytes=0",
      `model_reasoning_effort=${JSON.stringify(values.effort)}`,
    ];
    const permissions = await preflightReadOnlyProfileCodex(
      { ...settings, configOverrides: config },
      {
        filesystem: { ":minimal": "read", [checkout]: { ".": "read" } },
        network: { enabled: false },
      },
      {},
      checkout,
      signal,
      [],
    );
    const child = spawn(
      settings.codexPathOverride,
      [
        "app-server",
        "--disable",
        "plugins",
        ...permissions.configOverrides.flatMap((override) => ["-c", override]),
      ],
      {
        cwd: checkout,
        env: settings.env,
        stdio: ["pipe", "pipe", "pipe"],
        signal,
      },
    );
    const closed = once(child, "close");
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
      diagnostics += chunk;
    });
    const [result, [code]] = await Promise.all([
      readSkillCommandOutput(
        child.stdout,
        {
          directory: checkout,
          input: child.stdin,
          prompt,
          sandbox: "read-only",
          permissionProfile: permissions.permissionProfileId,
          threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
          dependencyGraph: {
            ...session,
            async call(name, args) {
              const reply = await session.call(name, args);
              snapshots.push(reply);
              return reply;
            },
          },
        },
        (observed) => {
          usage = observed;
        },
      ),
      closed,
    ]);
    if (result.error) error = result.error;
    else if (code !== 0) error = `Codex exited with status ${code}.`;
    else if (!result.completed)
      error = "Codex did not complete the graph check.";
  } catch (cause) {
    error = cause instanceof Error ? cause.message : String(cause);
  } finally {
    controller.abort();
    try {
      await graph?.close();
    } finally {
      try {
        await catalog?.close();
      } finally {
        await rm(scratch, { recursive: true, force: true });
      }
    }
  }
  const grade = gradeMapping(c, snapshots);
  await writeFile(
    join(output, `${c.id}.json`),
    JSON.stringify(
      {
        grade,
        graph: snapshots,
        usage,
        catalogUsage,
        wallMs: Math.round(performance.now() - started),
        model: values.model,
        effort: values.effort,
        ...(error && { error, diagnostics }),
      },
      null,
      2,
    ) + "\n",
  );
  console.log(`${c.id} ${grade.pass && !error ? "PASS" : "FAIL"}`);
  for (const reason of [...(error ? [error] : []), ...grade.errors]) {
    console.log(`  ${reason}`);
  }
  return grade.pass && !error;
}

const ambientHome = (
  auth as unknown as typeof import("../../sdk/typescript/src/auth.js")
).configuredCodexHome(process.env);
await withEvalState(
  createIsolatedHome,
  ambientHome,
  async ({ root, home, signal }) => {
    const codex = await realpath(resolveCodexCommand({}).command);
    const settings = modelSettings(home, codex);
    const results = await Promise.all(
      selected.map((c) => runCase(c, root, settings, signal)),
    );
    const passed = results.filter(Boolean).length;
    console.log(`${passed}/${selected.length} passed`);
    if (passed !== selected.length) process.exitCode = 1;
  },
);
