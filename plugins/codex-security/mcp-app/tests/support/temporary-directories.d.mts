export function createTemporaryDirectories(canonicalize?: boolean): {
  create(prefix: string): Promise<string>;
  cleanup(): Promise<void[]>;
};

export function temporaryDirectory(
  prefix: string,
  canonicalize?: boolean,
): Promise<string>;
