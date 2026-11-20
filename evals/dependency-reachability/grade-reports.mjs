import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256 } from "./fixtures.mjs";
import { buildReportPacket } from "./report-packet.mjs";
import { rubricPrompt, rubricSchema, scoreRating } from "./report-rubric.mjs";

const rubricSha256 = sha256(
  await readFile(new URL("./report-rubric.mjs", import.meta.url)),
);

export async function rateReport({
  report,
  reference,
  repo,
  sha,
  model,
  signal,
  dest,
}) {
  signal?.throwIfAborted();
  const bytes =
    JSON.stringify(
      buildReportPacket({ report, reference, repo, sha }),
      null,
      2,
    ) + "\n";
  await writeFile(join(dest, "rating-input.json"), bytes, {
    flag: "wx",
    mode: 0o600,
  });

  // Load the built SDK only for a requested model grade.
  const { runReadOnlyCodex } =
    await import("../../sdk/typescript/dist/scan-comparison.js");
  const { CODEX_SECURITY_THREAD_SOURCES } =
    await import("../../sdk/typescript/dist/thread-source.js");
  // The output and checkout paths can identify the reviewer setting.
  const workingDirectory = await mkdtemp(join(tmpdir(), "report-rating-"));
  try {
    // Validate pointers against the persisted JSON, which omits undefined fields.
    const packet = JSON.parse(bytes);
    const prompt = rubricPrompt(packet);
    const validationErrors = [];
    // A schema-valid answer can cite a nonexistent array index. Give the
    // same packet to a fresh thread once when the first answer is invalid.
    for (let attempt = 0; attempt < 2; attempt++) {
      signal?.throwIfAborted();
      const response = await runReadOnlyCodex(
        prompt,
        rubricSchema,
        { model, signal, workingDirectory, cyberAccessProgram: "standard" },
        {
          surface: "sdk",
          command: "dependency-report-eval",
          threadSource: CODEX_SECURITY_THREAD_SOURCES.scanComparison,
        },
      );
      signal?.throwIfAborted();
      try {
        const rating = JSON.parse(response);
        return {
          ...scoreRating(rating, packet),
          model,
          packetSha256: sha256(bytes),
          rubricSha256,
          rating,
          ...(attempt > 0 && { retryReason: validationErrors[0] }),
        };
      } catch (error) {
        validationErrors.push(error.message);
      }
    }
    throw new Error("Invalid report ratings: " + validationErrors.join(", "));
  } finally {
    await rm(workingDirectory, { recursive: true, force: true });
  }
}
