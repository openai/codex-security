import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  "load",
  "page",
  "text",
  "empty final page",
  "cleanup failure",
  "not canceled",
] as const)("PDF extraction cancellation boundary: %s", async (boundary) => {
  if (
    runTestInSubprocess(
      import.meta.path,
      `PDF extraction cancellation boundary: ${boundary}`,
    )
  )
    return;

  const root = await temporaryDirectory();
  const documentPath = join(root, "architecture.pdf");
  const staging = join(root, "staging");
  await mkdir(staging);
  await writeFile(documentPath, "%PDF-synthetic-loader-fixture");
  const reason = new Error("Synthetic PDF extraction cancellation");
  let controller = new AbortController();
  let pages: number[] = [];
  let textPages: number[] = [];
  let destroyed = 0;
  mock.module("pdfjs-dist/legacy/build/pdf.mjs", () => ({
    VerbosityLevel: { ERRORS: 0 },
    getDocument: () => ({
      promise: Promise.resolve().then(() => {
        if (boundary === "load") controller.abort(reason);
        return {
          numPages: boundary === "empty final page" ? 1 : 3,
          async getPage(number: number) {
            pages.push(number);
            if (boundary === "page") controller.abort(reason);
            return {
              async getTextContent() {
                textPages.push(number);
                if (
                  boundary === "text" ||
                  boundary === "empty final page" ||
                  boundary === "cleanup failure"
                )
                  controller.abort(reason);
                return {
                  items:
                    boundary === "empty final page"
                      ? []
                      : [{ str: `Synthetic page ${number}` }],
                };
              },
            };
          },
        };
      }),
      async destroy() {
        destroyed++;
        if (boundary === "cleanup failure")
          throw new Error("Synthetic PDF cleanup failure");
      },
    }),
  }));
  const { readKnowledgeBaseSnapshot, prepareKnowledgeBase } =
    await import("../src/knowledge-base.js");
  for (const entrypoint of ["snapshot", "prepared"] as const) {
    controller = new AbortController();
    pages = [];
    textPages = [];
    destroyed = 0;
    const read = async () => {
      if (entrypoint === "snapshot") {
        const snapshot = await readKnowledgeBaseSnapshot(
          [documentPath],
          controller.signal,
        );
        return Object.values(snapshot.documents);
      }
      const prepared = await prepareKnowledgeBase(
        [documentPath],
        controller.signal,
        staging,
      );
      try {
        return await Promise.all(
          (await readdir(prepared.path)).map((name) =>
            readFile(join(prepared.path, name), "utf8"),
          ),
        );
      } finally {
        await prepared.cleanup();
      }
    };
    if (boundary === "not canceled") {
      await expect(read()).resolves.toEqual([
        "Synthetic page 1\nSynthetic page 2\nSynthetic page 3",
      ]);
    } else {
      await expect(read()).rejects.toBe(reason);
    }
    expect(pages).toEqual(
      boundary === "not canceled" ? [1, 2, 3] : boundary === "load" ? [] : [1],
    );
    expect(textPages).toEqual(
      boundary === "not canceled"
        ? [1, 2, 3]
        : boundary === "load" || boundary === "page"
          ? []
          : [1],
    );
    expect(destroyed).toBe(1);
    expect(await readdir(staging)).toEqual([]);
  }
});
