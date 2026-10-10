import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";

export interface CodexSessionEvent {
  readonly type: string;
  readonly [key: string]: unknown;
}

export interface CodexSessionThread {
  readonly id: string | null;
  runStreamed(
    input: string,
    options: TurnOptions,
  ): Promise<{ events: AsyncGenerator<CodexSessionEvent> }>;
}

export interface CodexSessionClient {
  startThread(options: ThreadOptions): CodexSessionThread;
  resumeThread?(threadId: string, options: ThreadOptions): CodexSessionThread;
}

export const createCodexClient = (options: CodexOptions): CodexSessionClient =>
  new Codex(options);
