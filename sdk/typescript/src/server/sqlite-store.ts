import { delimiter, isAbsolute, resolve } from "node:path";
import {
  bundledPluginRoot,
  workbenchEnvironment,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../runtime.js";
import { FindingsError } from "./errors.js";
import type { DashboardQuery, DashboardSnapshot } from "./dashboard-types.js";
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
    await this.run(["database-info"]);
  }

  async dashboard(query: DashboardQuery): Promise<DashboardSnapshot> {
    return (await this.run(
      ["dashboard"],
      JSON.stringify(query),
    )) as unknown as DashboardSnapshot;
  }

  async insert(
    entries: readonly EmbeddedFinding[],
    repositoryId?: string,
  ): Promise<string[]> {
    const result = await this.run(
      ["store-findings"],
      JSON.stringify({ entries, repositoryId }),
    );
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

  async findPotentialDuplicates(
    findingId: string,
    scope: FindingSearchScope,
  ): Promise<FindingNeighborhood> {
    const result = await this.run([
      "find-potential-duplicates",
      `--finding-id=${findingId}`,
      ...(scope.allRepositories === true
        ? ["--all-repositories"]
        : [`--repository-id=${scope.repositoryId}`]),
    ]);
    if (result["error"] === "finding_not_indexed") {
      throw new FindingsError(
        "finding_not_indexed",
        "The finding has no current embedding in the requested scope. Import it with the matching repositoryId through POST /v1/bulk/findings before requesting potential duplicates.",
      );
    }
    if (result["error"] === "embedding_failed") {
      throw new FindingsError(
        "embedding_failed",
        "A stored embedding cannot be compared. Reimport the finding.",
      );
    }
    return result as unknown as FindingNeighborhood;
  }

  async storeDedupeGroups(
    groups: readonly string[][],
  ): Promise<FindingDedupeGroup[]> {
    const result = await this.run(
      ["store-dedupe-groups"],
      JSON.stringify({ groups }),
    );
    if (result["error"] === "finding_conflict") {
      throw new FindingsError(
        "finding_conflict",
        "Every dedupe group member must already exist in the findings database.",
      );
    }
    return result["groups"] as unknown as FindingDedupeGroup[];
  }

  async listDedupeGroups(findingId: string): Promise<FindingDedupeGroup[]> {
    return (
      await this.run(["list-dedupe-groups", `--finding-id=${findingId}`])
    )["groups"] as unknown as FindingDedupeGroup[];
  }

  private async run(args: string[], input?: string) {
    const options = await (this.options ??= this.resolveOptions());
    return await runWorkbench(options, args, input);
  }

  private async resolveOptions(): Promise<
    Omit<WorkbenchCommandOptions, "python">
  > {
    const protectedRoot = process.cwd();
    const environment: NodeJS.ProcessEnv = workbenchEnvironment(
      this.environment,
    );
    for (const [name, value] of Object.entries(environment)) {
      if (value === undefined) continue;
      if (name.toUpperCase() === "XDG_CACHE_HOME" && value.trim())
        environment[name] = resolve(value);
      if (name.toUpperCase() !== "PATH") continue;
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
