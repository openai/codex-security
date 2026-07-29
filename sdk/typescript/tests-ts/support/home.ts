const HOME_VARIABLES = ["HOME", "USERPROFILE"] as const;

/**
 * Runs `operation` with `os.homedir()` pointed at `home` so tests can exercise
 * `~` expansion without touching the real home directory.
 */
export async function withHome<T>(
  home: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = HOME_VARIABLES.map(
    (name) => [name, process.env[name]] as const,
  );
  for (const name of HOME_VARIABLES) process.env[name] = home;
  try {
    return await operation();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
