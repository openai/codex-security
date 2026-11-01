import { Writable } from "node:stream";
import { main } from "../../src/cli.js";
import { runHostProtocol } from "../../src/host-protocol.js";

const scenario = process.argv[2];
if (scenario === "cli") {
  await main(process.argv.slice(3));
} else {
  const output =
    scenario === "failed-terminal"
      ? new Writable({
          write(_chunk, _encoding, callback) {
            const fail = () =>
              callback(new Error("Synthetic terminal write failure"));
            if (process.argv[4] === "async") queueMicrotask(fail);
            else fail();
          },
        })
      : scenario === "close-after-flush"
        ? new Writable({
            write(_chunk, _encoding, callback) {
              this.end();
              callback();
            },
          })
        : scenario === "eof-before-flush"
          ? new Writable({
              write(_chunk, _encoding, callback) {
                process.stderr.write("writing\n");
                process.stdin.once("end", () => {
                  queueMicrotask(() => callback());
                });
              },
            })
          : process.stdout;
  // Windows stdout pipes write synchronously. Hold a native queued write
  // without blocking the event loop that must receive cancellation.
  if (scenario === "queued-execution") output.cork();
  const code = await runHostProtocol(process.stdin, output, {
    label: "Scan",
    requestMethod: "execution.run",
    awaitCancellationReceipt: true,
    async run(_params, execute) {
      if (scenario === "queued-execution") {
        const execution = execute("request-1", {
          payload: "synthetic request",
        });
        process.stderr.write(
          JSON.stringify({ queued: output.writableLength > 0 }) + "\n",
        );
        await execution;
      }
      return { status: process.argv[3] ?? "completed" };
    },
  });
  process.stderr.write(JSON.stringify({ code }) + "\n");
  // Match the CLI: native stdout can remain open after destroy().
  process.exit(code);
}
