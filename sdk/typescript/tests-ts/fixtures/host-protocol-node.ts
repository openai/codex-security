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
  const code = await runHostProtocol(process.stdin, output, {
    label: "Scan",
    requestMethod: "execution.run",
    awaitCancellationReceipt: true,
    async run(_params, execute) {
      if (scenario === "blocked-execution")
        await execute("request-1", { payload: "x".repeat(16 * 1024 * 1024) });
      return { status: process.argv[3] ?? "completed" };
    },
  });
  process.stderr.write(JSON.stringify({ code }) + "\n");
  // Match the CLI: native stdout can remain open after destroy().
  process.exit(code);
}
