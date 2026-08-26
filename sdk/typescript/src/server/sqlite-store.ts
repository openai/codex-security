import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../runtime.js";
import { FindingsError } from "./errors.js";
import type {
  EmbeddedFinding,
  FindingsPage,
  FindingsStore,
} from "./storage.js";

export class SqliteFindingsStore implements FindingsStore {
  private options?: Promise<WorkbenchCommandOptions>;

  constructor(private readonly environment: NodeJS.ProcessEnv = process.env) {}

  async initialize(): Promise<void> {
    await this.run(["database-info"]);
  }

  async insert(entries: readonly EmbeddedFinding[]): Promise<string[]> {
    const result = await this.run(["store-findings"], JSON.stringify(entries));
    if (result["error"] === "finding_conflict") {
      throw new FindingsError(
        "finding_conflict",
        "A finding identity conflicts with stored data.",
      );
    }
    return result["findingIds"] as string[];
  }

  async list(page: { limit: number; offset: number }): Promise<FindingsPage> {
    return (await this.run([
      "list-stored-findings",
      "--limit",
      String(page.limit),
      "--offset",
      String(page.offset),
    ])) as unknown as FindingsPage;
  }

  private async run(args: string[], input?: string) {
    const options = await (this.options ??= this.resolveOptions());
    return await runWorkbench(options, args, input);
  }

  private async resolveOptions(): Promise<WorkbenchCommandOptions> {
    const environment = {
      ...this.environment,
      CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(this.environment),
    };
    const [python, pluginRoot] = await Promise.all([
      resolvePluginPython({ environment }),
      bundledPluginRoot(),
    ]);
    return {
      python,
      pluginRoot,
      environment,
      failureMessage: "Could not access the findings database",
    };
  }
}
