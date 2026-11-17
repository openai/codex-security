export function retryWindowsRename(
  operation: () => Promise<void>,
  rollback?: () => Promise<void>,
  signal?: AbortSignal,
): Promise<void>;
