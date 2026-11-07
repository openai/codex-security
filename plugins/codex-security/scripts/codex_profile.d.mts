export function preflightProviderDefinitions(
  providers: Record<string, unknown>,
): Record<string, unknown>;

export function isPermissionProfileFallbackWarning(
  message: unknown,
  profileId: string,
): boolean;

export function profileConfigOverrides(
  config: Record<string, unknown>,
): string[];

export interface CodexProfileOptions {
  codexPathOverride: string;
  profileName: string;
  requestedPermissionProfile?: string;
  env?: Record<string, string>;
  apiKey?: string;
  baseUrl?: string;
  config?: Record<string, unknown>;
  configOverrides?: string[];
}

export interface ProfileThreadOptions {
  model?: string;
  threadSource?: string;
  sandboxMode?: string;
  workingDirectory?: string;
  skipGitRepoCheck?: boolean;
  modelReasoningEffort?: string;
  networkAccessEnabled?: boolean;
  webSearchMode?: string;
  webSearchEnabled?: boolean;
  approvalPolicy?: string;
  additionalDirectories?: string[];
}

export interface ProfileTurnOptions {
  cyberAccessProgram?: string;
  outputSchema?: unknown;
  signal?: AbortSignal;
}

type CompletedItem<Event> = Event extends {
  type: "item.completed";
  item: infer Item;
}
  ? Item
  : never;
type CompletedUsage<Event> = Event extends {
  type: "turn.completed";
  usage: infer Usage;
}
  ? Usage
  : never;

export interface ProfileThread<Event> {
  readonly id: string | null;
  runStreamed(
    input: string,
    options?: ProfileTurnOptions,
  ): Promise<{
    events: AsyncGenerator<Event>;
  }>;
  run(
    input: string,
    options?: ProfileTurnOptions,
  ): Promise<{
    items: CompletedItem<Event>[];
    finalResponse: string;
    usage: CompletedUsage<Event> | null;
  }>;
}

export function createCodexProfileClient<
  Event extends { type: string } = Record<string, unknown> & { type: string },
>(
  options: CodexProfileOptions,
): {
  startThread(options?: ProfileThreadOptions): ProfileThread<Event>;
  resumeThread(
    id: string,
    options?: ProfileThreadOptions,
  ): ProfileThread<Event>;
};
