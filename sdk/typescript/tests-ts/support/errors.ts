export function fail(message: string): never {
  throw new Error(message);
}

export function throwing(message: string): () => never {
  return () => fail(message);
}

export function rejecting(message: string): () => Promise<never> {
  return async () => fail(message);
}
