import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { prepareKnowledgeBase } from "../src/knowledge-base.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function pdf(text: string): Uint8Array {
  const escaped = text.replace(/[\\()]/gu, "\\$&");
  const stream = `BT /F1 12 Tf 72 720 Td (${escaped}) Tj ET`;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`,
  ];
  let output = "%PDF-1.4\n";
  const offsets = [0];
  for (const [index, object] of objects.entries()) {
    offsets.push(Buffer.byteLength(output));
    output += `${index + 1} 0 obj\n${object}\nendobj\n`;
  }
  const xref = Buffer.byteLength(output);
  output += `xref\n0 ${offsets.length}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) {
    output += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }
  output += `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new TextEncoder().encode(output);
}

describe("knowledge-base PDF cancellation", () => {
  test("observes cancellation after PDF loading has started", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-pdf-cancel-")),
    );
    temporaryDirectories.push(root);
    const document = join(root, "architecture.pdf");
    await writeFile(document, pdf("Payment service boundary"));

    const controller = new AbortController();
    const reason = new Error("PDF extraction canceled.");
    let checks = 0;
    const signalSpy = spyOn(controller.signal, "throwIfAborted");
    signalSpy.mockImplementation(() => {
      if (++checks === 3) controller.abort(reason);
      if (controller.signal.aborted) throw controller.signal.reason;
    });

    try {
      await expect(
        prepareKnowledgeBase([document], controller.signal),
      ).rejects.toBe(reason);
      expect(checks).toBe(3);
    } finally {
      signalSpy.mockRestore();
    }
  });
});
