export interface TerminalStream {
  write(chunk: string, callback?: (error?: Error | null) => void): unknown;
  on?(event: "error", listener: (error: Error) => void): unknown;
  off?(event: "error", listener: (error: Error) => void): unknown;
}

export class TerminalErrorListener {
  readonly #ignore = (): void => {};
  #generation = 0;
  #active = false;

  constructor(private readonly stream: TerminalStream) {}

  start(): void {
    this.#generation++;
    if (!this.#active && this.stream.on !== undefined) {
      this.stream.on("error", this.#ignore);
      this.#active = true;
    }
  }

  stop(): void {
    if (!this.#active) return;
    // A later start needs the listener even if these earlier writes have drained.
    const generation = this.#generation;
    const remove = (): void => {
      if (generation === this.#generation && this.#active) {
        this.stream.off?.("error", this.#ignore);
        this.#active = false;
      }
    };
    try {
      this.stream.write("", () => queueMicrotask(remove));
    } catch {
      remove();
    }
  }
}
