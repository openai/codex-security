import type { InvestigationToolFactory } from "./dependency-investigation-session.js";
import type { ScanTokenUsage } from "./cost-model.js";
import { registerDependencyCheck } from "./dependency-check-command.js";
import type {
  DependencyEvidenceRecord,
  DependencyEvidenceFailure,
} from "./dependency-evidence-sources.js";
import { Cli, z } from "incur";
import { resolveConfigPath } from "./config-path.js";
import { CodexSecurityError } from "./errors.js";
import { executeStackRun, stackRunTools } from "./dependency-stack-run.js";

export interface DependencyAgentRequest {
  prompt: string;
  directory: string;
  signal: AbortSignal;
  model?: string;
  effort?: string;
  codex?: string[];
  config?: string;
  stackTarget?: string;
  readOnly?: boolean;
  coordinator?: boolean;
  onCoordinatorAnswer?: (answer: string) => Promise<string | undefined>;
  investigationTools?: InvestigationToolFactory;
  onAccessProgram?: (program: string | undefined) => void;
  onUsage?: (usage: ScanTokenUsage) => void;
  onEvidence?: (record: DependencyEvidenceRecord) => void;
  onEvidenceFailure?: (
    call: DependencyEvidenceFailure,
    result?: Record<string, unknown>,
  ) => void;
  onEvidenceStartup?: (
    server: string,
    status: import("./dependency-blocked-evidence.js").DependencyStartupStatus,
    required: boolean,
    error: unknown,
  ) => void;
  abortInvestigation?: (args: unknown, thread: string) => unknown;
  onEvidenceDiagnostic?: (message: string) => void;
}

export interface DependencyCliContext {
  environment: NodeJS.ProcessEnv;
  stderr: Pick<NodeJS.WritableStream, "write">;
  setExitCode(code: number): void;
  currentDirectory(): string;
  recordsInput: AsyncIterable<Buffer | string>;
  withSignal<T>(run: (signal: AbortSignal) => Promise<T>): Promise<T>;
  runAgent(request: DependencyAgentRequest): Promise<string>;
}

export function createExploitabilityCli(context: DependencyCliContext) {
  const flag = z.string().trim().min(1);
  const group = Cli.create("exploitability", {
    description: "Investigate dependency vulnerabilities in a repository.",
  });
  registerDependencyCheck(group, context);
  const run = Cli.create("run", {
    description:
      "Read and update a single investigation. Each operation returns JSON.",
  });
  const pathOptions = z.object({
    state: flag.describe("Path to the investigation SQLite file."),
  });
  for (const tool of stackRunTools) {
    const options =
      tool.name === "init"
        ? pathOptions.extend({
            inputs: flag.describe(
              "Directory containing the prepared input packet.",
            ),
            repo: flag.describe("Target Git checkout."),
          })
        : tool.inputSchema
          ? pathOptions.extend({
              jsonStdin: z
                .boolean()
                .describe("Read one JSON document from standard input."),
            })
          : pathOptions;
    run.command(tool.name, {
      description: tool.description,
      format: "json",
      options,
      mcp: false,
      async run({ options: opts }) {
        return context.withSignal(async (signal) => {
          const dir = context.currentDirectory();
          let input: unknown;
          if (tool.inputSchema) {
            if (!("jsonStdin" in opts && opts.jsonStdin))
              throw new CodexSecurityError(
                "Use --json-stdin to provide input for " + tool.name + ".",
              );
            const chunks: Buffer[] = [];
            for await (const data of context.recordsInput)
              chunks.push(Buffer.from(data));
            input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          }
          return executeStackRun(tool.name, {
            state: resolveConfigPath(dir, opts.state),
            signal,
            input,
            ...("inputs" in opts &&
              typeof opts.inputs === "string" && {
                inputs: resolveConfigPath(dir, opts.inputs),
              }),
            ...("repo" in opts &&
              typeof opts.repo === "string" && {
                repo: resolveConfigPath(dir, opts.repo),
              }),
          });
        });
      },
    });
  }
  return group.command(run);
}
