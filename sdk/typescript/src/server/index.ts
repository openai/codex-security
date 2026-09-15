import { serveFindings } from "./serve.js";

serveFindings().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
