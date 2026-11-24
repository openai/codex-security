import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { invokeCli, writeCliLogs } from "../dependency-reachability/cli.mjs";
import {
  commitFixture,
  jsonFile,
} from "../dependency-reachability/fixtures.mjs";
import { cases, catalogServer, catalogTool } from "./cases.mts";
import { gradeMapping, graphReplies } from "./grade.mts";

const usage =
  "Usage: node --experimental-strip-types evals/package-application-mapping/run.mjs --cli PATH [--case ID] [--model MODEL] [--out NEW_DIR]";
const { values } = parseArgs({
  options: {
    cli: { type: "string" },
    case: { type: "string" },
    model: { type: "string" },
    out: { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});
if (values.help) {
  console.log(usage);
  process.exit(0);
}
if (!values.cli) throw Error(usage);
const selected = cases.filter((c) => !values.case || values.case === c.id);
if (!selected.length) throw Error("Unknown case " + values.case);
const cli = await realpath(resolve(values.cli));
const output = values.out
  ? resolve(values.out)
  : await mkdtemp(join(tmpdir(), "application-mapping-"));
if (values.out) await mkdir(output, { mode: 0o700 });
const controller = new AbortController();
for (const name of ["SIGINT", "SIGTERM"])
  process.once(name, () => {
    process.exitCode = name === "SIGINT" ? 130 : 143;
    controller.abort();
  });
console.log("Results: " + output);

async function run(c) {
  const dest = join(output, c.id);
  await mkdir(dest, { mode: 0o700 });
  const scratch = await mkdtemp(join(tmpdir(), "mapping-case-"));
  const repo = join(scratch, "checkout");
  const start = performance.now();
  try {
    for (const [path, content] of Object.entries(c.files)) {
      const target = join(repo, path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, content);
    }
    const sha = commitFixture(repo);
    const catalog = join(scratch, "catalog.json"),
      config = join(scratch, "project.json");
    if (c.catalog) await jsonFile(catalog, c.catalog);
    await jsonFile(config, {
      exploitability: {
        scope: {
          instructions:
            "Identify the applications that launch the affected dependency's consuming code. Trace importers through shared libraries, distinguish CI and similarly named projects, and check actual launcher settings. When finished, query the graph by each matching source file path to record its mappings.",
        },
        ...(c.catalog && {
          evidence_sources: [
            {
              server: catalogServer,
              instructions:
                "Use this read-only service catalog to resolve the identity of applications by checkout-relative consumer, project, entrypoint or launch file. A service name requires a catalog record.",
            },
          ],
        }),
      },
      ...(c.catalog && {
        codex: {
          mcp_servers: {
            [catalogServer]: {
              command: process.execPath,
              args: [
                "--experimental-strip-types",
                join(import.meta.dirname, "catalog.mts"),
                catalog,
              ],
              enabled_tools: [catalogTool],
            },
          },
        },
      }),
    });
    const reportFile = join(scratch, "assessment.json");
    const args = [
      "check",
      "npm:" + c.package,
      "--vuln-description",
      "The label function in version 1.0.0 invokes conversion on its argument. Determine which configured applications invoke label and whether the caller controls its input.",
      "--config",
      config,
      "--report-file",
      reportFile,
      "--json",
    ];
    if (values.model) args.push("--model", values.model);
    const proc = await invokeCli(cli, repo, args, {
      signal: controller.signal,
    });
    await writeCliLogs(dest, proc);
    if (proc.code !== 0)
      throw Error("CLI exited " + proc.code + " (see retained command output)");
    const report = JSON.parse(await readFile(reportFile, "utf8"));
    await jsonFile(join(dest, "report.json"), report);
    const replies = graphReplies(report);
    const grade = gradeMapping(c, replies);
    return {
      id: c.id,
      sourceSha: sha,
      elapsedMs: Math.round(performance.now() - start),
      usage: report.checks?.[0]?.usage ?? null,
      grade,
    };
  } catch (error) {
    return {
      id: c.id,
      elapsedMs: Math.round(performance.now() - start),
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
const results = await Promise.all(selected.map(run));
await jsonFile(join(output, "results.json"), {
  model: values.model ?? null,
  results,
});
for (const result of results)
  console.log(
    result.id,
    result.grade?.pass ? "PASS" : "FAIL",
    result.error ?? result.grade?.errors.join(", "),
  );
if (results.some((r) => !r.grade?.pass)) process.exitCode ||= 1;
