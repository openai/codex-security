export function codexWithRun<Run>(run: Run) {
  return { startThread: () => ({ run }) };
}

export function jsonCodex(response: () => unknown) {
  return codexWithRun(async () => ({
    finalResponse: JSON.stringify(response()),
  }));
}
