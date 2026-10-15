export function resolving<T, Args extends unknown[] = []>(value: T) {
  return async (..._args: Args) => value;
}
