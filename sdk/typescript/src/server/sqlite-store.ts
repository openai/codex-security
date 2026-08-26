import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
} from "../runtime.js";
import type { FindingsStore } from "./storage.js";

export class SqliteFindingsStore implements FindingsStore {
  constructor(private readonly environment: NodeJS.ProcessEnv = process.env) {}

  async initialize(): Promise<void> {
    const environment = {
      ...this.environment,
      CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(this.environment),
    };
    const [python, pluginRoot] = await Promise.all([
      resolvePluginPython({ environment }),
      bundledPluginRoot(),
    ]);
    await runWorkbench(
      {
        python,
        pluginRoot,
        environment,
        failureMessage: "Could not initialize the findings database",
      },
      ["database-info"],
    );
  }
}
