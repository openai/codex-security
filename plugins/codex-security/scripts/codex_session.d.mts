export function readCodexSessionTurn<Event extends { type: string }>(options: {
  thread: { readonly id: string | null };
  events: AsyncGenerator<Event>;
  onEvent: (event: Event) => Promise<void> | void;
  stopOnCompletion?: boolean;
}): Promise<{
  threadId: string | null;
  status: "in_progress" | "completed";
  finalResponse: string;
  usage: unknown;
  lastStreamError: string | null;
}>;
