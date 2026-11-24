import { main } from "../../src/cli.js";
import { dependencies } from "../cli-fixtures.js";

const port = process.argv[2]!;
process.exitCode = await main(
  process.argv.slice(3),
  process.stdout,
  process.stderr,
  {
    ...dependencies({ environment: process.env }),
    cloudFetch: (url, init) => {
      const { pathname, search } = new URL(url);
      return fetch(`http://127.0.0.1:${port}${pathname}${search}`, init);
    },
  },
);
