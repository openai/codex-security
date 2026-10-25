import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { Readable } from "node:stream";

export function consumeStreamLines(
  stream: Readable,
  consume: (line: string) => void,
) {
  let buffer = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop()!;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) consume(trimmed);
    }
  });
}

export function writeMessage(
  child: Pick<ChildProcessWithoutNullStreams, "stdin">,
  message: unknown,
) {
  child.stdin.write(JSON.stringify(message));
  child.stdin.write("\n");
}
