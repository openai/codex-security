export declare function buildDependencyCalculationPrompt(options: {
  targetPath: string;
  /** Validated repository-relative paths; omitted or empty means the root. */
  scopePaths?: readonly string[];
  setup: Record<string, unknown>;
  dependencyGraphPath?: string;
}): string;
