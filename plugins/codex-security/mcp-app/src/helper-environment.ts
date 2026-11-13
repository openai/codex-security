/** Keep the native model credential out of local helper processes. */
export function helperEnvironment(env = process.env): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(env).filter(
      ([name]) => name.toUpperCase() !== "MINIMAX_API_KEY",
    ),
  );
}
