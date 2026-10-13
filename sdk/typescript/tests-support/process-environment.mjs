/** Restore only the environment keys a fixture changes, including missing values. */
export function captureEnvironment(keys) {
  const before = keys.map((key) => [key, process.env[key]]);
  return () => {
    for (const [key, value] of before) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}
