import { delimiter, isAbsolute, resolve } from "node:path";
import {
  bundledPluginRoot,
  workbenchEnvironment,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../runtime.js";
import { FindingsError } from "./errors.js";
import type { FindingDedupeGroup } from "../finding-dedupe-groups.js";
import type {
  FindingNeighborhood,
  FindingSearchScope,
} from "../finding-retrieval.js";
import type {
  EmbeddedFinding,
  FindingsPage,
  FindingsStore,
} from "./storage.js";

export class SqliteFindingsStore implements FindingsStore {
  private options?: Promise<Omit<WorkbenchCommandOptions, "python">>;

  constructor(private readonly environment: NodeJS.ProcessEnv = process.env) {}

  async initialize(): Promise<void> {
    await this.run("database-info");
  }

  async insert(
    entries: readonly EmbeddedFinding[],
    repositoryId?: string,
  ): Promise<string[]> {
    const result = await this.run<{ findingIds: string[] }>("store-findings", {
      entries,
      repositoryId,
    });
    return result.findingIds;
  }

  list(page: { limit: number; offset: number }): Promise<FindingsPage> {
    return this.run("list-stored-findings", page);
  }

  findPotentialDuplicates(
    findingId: string,
    scope: FindingSearchScope,
  ): Promise<FindingNeighborhood> {
    return this.run("find-potential-duplicates", { findingId, scope });
  }

  async storeDedupeGroups(
    groups: readonly string[][],
  ): Promise<FindingDedupeGroup[]> {
    const result = await this.run<{ groups: FindingDedupeGroup[] }>(
      "store-dedupe-groups",
      { groups },
    );
    return result.groups;
  }

  async listDedupeGroups(findingId: string): Promise<FindingDedupeGroup[]> {
    const result = await this.run<{ groups: FindingDedupeGroup[] }>(
      "list-dedupe-groups",
      { findingId },
    );
    return result.groups;
  }

  private async run<T>(command: string, payload?: unknown): Promise<T> {
    const input = JSON.stringify(payload);
    const options = await (this.options ??= this.resolveOptions());
    const result = await runWorkbench(options, [command], input);
    const messages = {
      finding_conflict:
        command === "store-findings"
          ? "A finding identity conflicts with stored data."
          : "Every dedupe group member must already exist in the findings database.",
      finding_not_indexed:
        "The finding has no current embedding in the requested scope. Prepare its local embeddings or insert it with the matching repositoryId before requesting potential duplicates.",
      embedding_failed:
        "A stored embedding cannot be compared. Reimport the finding.",
    };
    const error = result["error"] as keyof typeof messages | undefined;
    if (error) throw new FindingsError(error, messages[error]);
    return result as T;
  }

  private async resolveOptions(): Promise<
    Omit<WorkbenchCommandOptions, "python">
  > {
    const protectedRoot = process.cwd();
    const environment: NodeJS.ProcessEnv = workbenchEnvironment(
      this.environment,
    );
    for (const [name, value] of Object.entries(environment)) {
      if (name.toUpperCase() !== "PATH" || value === undefined) continue;
      environment[name] = value
        .split(delimiter)
        .map((entry) => {
          const directory =
            process.platform === "win32"
              ? entry.replace(/^"(.*)"$/u, "$1")
              : entry;
          if (!directory) return directory;
          if (process.platform === "win32") return resolve(directory);
          // Keep POSIX symlink/.. traversal intact.
          return isAbsolute(directory)
            ? directory
            : `${protectedRoot}/${directory}`;
        })
        .join(delimiter);
    }
    return {
      protectedRoot,
      pluginRoot: await bundledPluginRoot(),
      environment,
      stateDirectory: environment["CODEX_SECURITY_STATE_DIR"],
      failureMessage: "Could not access the findings database",
    };
  }
}
