import { join } from "node:path";
import { main } from "../../src/cli.ts";
import { publishScanInternal } from "../../src/publish.ts";
import { dependencies } from "../cli-fixtures.ts";

const deps = dependencies({
  currentDirectory: process.cwd(),
  environment: process.env,
});
deps.now = Date.now;
deps.addSignalListener = (signal, listener) => process.on(signal, listener);
deps.removeSignalListener = (signal, listener) => process.off(signal, listener);
deps.forceExit = (signal) => process.kill(process.pid, signal);
deps.publishScan = (directory, options) => {
  options.signal.addEventListener("abort", () =>
    process.stderr.write("cancelled\n"),
  );
  return publishScanInternal(directory, options, {
    environment: process.env,
    prepare: async () => ({
      scanId: "synthetic-scan",
      scanDirectory: directory,
      destination: { type: "linear", teamId: "synthetic-team" },
      issues: [
        {
          findingId: "synthetic-finding",
          occurrenceId: "synthetic-occurrence",
          title: "Synthetic finding",
          description: "Synthetic publication cleanup fixture.",
        },
      ],
    }),
    preparePublicationStore: async () => {},
    resolveCodex: () => ({ command: join(process.cwd(), "publisher.cjs") }),
  });
};

void main(process.argv.slice(2), process.stdout, process.stderr, deps).then(
  (code) => {
    process.exitCode = code;
  },
);
