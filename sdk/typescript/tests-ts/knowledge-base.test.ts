import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import * as os from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import { prepareKnowledgeBase } from "../src/knowledge-base.js";
import { expandHome } from "../src/runtime.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-knowledge-test-")),
  );
  temporaryDirectories.push(path);
  return path;
}

async function extractedDocuments(path: string): Promise<string[]> {
  return await Promise.all(
    (await readdir(path)).map((name) => readFile(join(path, name), "utf8")),
  );
}

function docx(text: string): Uint8Array {
  return zipSync({
    "word/document.xml": strToU8(
      `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:body></w:document>`,
    ),
  });
}

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

describe("scan knowledge bases", () => {
  test("prepares nested supported documents and retains requested source roots", async () => {
    const root = await temporaryDirectory();
    const nested = join(root, "architecture", "threats");
    const scope = join(root, "scope.md");
    await mkdir(nested, { recursive: true });
    await writeFile(scope, "Ignore local debug endpoints.");
    await writeFile(join(nested, "deployment.MARKDOWN"), "Public API gateway.");
    await writeFile(join(nested, "notes.txt"), "Prioritize SSRF.");
    await writeFile(join(root, "ignored.json"), "{}");

    const knowledgeBase = await prepareKnowledgeBase([root, scope, scope]);
    temporaryDirectories.push(knowledgeBase.path);

    expect(knowledgeBase.sources).toEqual([root, scope]);
    expect((await readdir(knowledgeBase.path)).length).toBe(3);
    const documents = await extractedDocuments(knowledgeBase.path);
    expect(documents).toContain("Ignore local debug endpoints.");
    expect(documents).toContain("Public API gateway.");
    expect(documents).toContain("Prioritize SSRF.");
    expect(knowledgeBase.path.startsWith(root)).toBe(false);
    if (process.platform !== "win32") {
      expect((await stat(knowledgeBase.path)).mode & 0o777).toBe(0o700);
      for (const name of await readdir(knowledgeBase.path)) {
        expect((await stat(join(knowledgeBase.path, name))).mode & 0o777).toBe(
          0o600,
        );
      }
    }
  });

  test("cancels recursive discovery before staging knowledge-base documents", async () => {
    const root = await temporaryDirectory();
    const nested = join(root, "nested", "deeper");
    await mkdir(nested, { recursive: true });
    await writeFile(join(nested, "scope.md"), "Review application boundaries.");

    const controller = new AbortController();
    const reason = new Error("Knowledge-base discovery canceled.");
    let checks = 0;
    const signalSpy = spyOn(controller.signal, "throwIfAborted");
    signalSpy.mockImplementation(() => {
      if (++checks === 8) controller.abort(reason);
      if (controller.signal.aborted) throw controller.signal.reason;
    });
    const temporarySpy = spyOn(os, "tmpdir");

    try {
      const prepared = prepareKnowledgeBase([root], controller.signal).then(
        (knowledgeBase) => {
          temporaryDirectories.push(knowledgeBase.path);
          return knowledgeBase;
        },
      );
      await expect(prepared).rejects.toBe(reason);
      expect(temporarySpy).not.toHaveBeenCalled();
    } finally {
      signalSpy.mockRestore();
      temporarySpy.mockRestore();
    }
  });

  test("handles large nested document listings without argument overflow", async () => {
    const root = await temporaryDirectory();
    const nested = join(root, "nested");
    await mkdir(nested);
    await writeFile(join(nested, "scope.md"), "Review application boundaries.");
    const originalReaddir = filesystem.readdir;
    const listingSpy = spyOn(filesystem, "readdir").mockImplementation(
      async (...args) => {
        const entries = await Reflect.apply(originalReaddir, filesystem, args);
        return args[0] === nested ? Array(700_000).fill(entries[0]) : entries;
      },
    );

    let knowledgeBase;
    try {
      knowledgeBase = await prepareKnowledgeBase([root]);
      temporaryDirectories.push(knowledgeBase.path);
    } finally {
      listingSpy.mockRestore();
    }

    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Review application boundaries.",
    ]);
  });

  test("removes staged documents when knowledge-base preparation is canceled", async () => {
    const root = await temporaryDirectory();
    const staging = join(root, "staging");
    await mkdir(staging);
    const first = join(root, "first.md");
    const second = join(root, "second.md");
    await writeFile(first, "First document.");
    await writeFile(second, "Second document.");

    const controller = new AbortController();
    const reason = new Error("Knowledge-base preparation canceled.");
    let checks = 0;
    const signalSpy = spyOn(controller.signal, "throwIfAborted");
    signalSpy.mockImplementation(() => {
      if (++checks === 4) controller.abort(reason);
      if (controller.signal.aborted) throw controller.signal.reason;
    });
    const temporarySpy = spyOn(os, "tmpdir").mockImplementation(() => staging);

    try {
      await expect(
        prepareKnowledgeBase([first, second], controller.signal),
      ).rejects.toBe(reason);
      expect(await readdir(staging)).toEqual([]);
    } finally {
      signalSpy.mockRestore();
      temporarySpy.mockRestore();
    }
  });

  test("expands ~ in requested paths and leaves absolute and ~user paths alone", async () => {
    const home = await temporaryDirectory();
    const documents = join(home, "docs");
    await mkdir(documents, { recursive: true });
    await writeFile(join(documents, "scope.md"), "Review the payment service.");
    const previousHome = process.env["HOME"];
    const previousUserProfile = process.env["USERPROFILE"];
    process.env["HOME"] = home;
    process.env["USERPROFILE"] = home;
    try {
      const expanded = await prepareKnowledgeBase(["~/docs"]);
      temporaryDirectories.push(expanded.path);
      expect(expanded.sources).toEqual([documents]);

      const bare = await prepareKnowledgeBase(["~"]);
      temporaryDirectories.push(bare.path);
      expect(bare.sources).toEqual([home]);

      const absolute = await prepareKnowledgeBase([documents]);
      temporaryDirectories.push(absolute.path);
      expect(absolute.sources).toEqual([documents]);

      expect(expandHome("~other/docs")).toBe("~other/docs");
    } finally {
      if (previousHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = previousHome;
      if (previousUserProfile === undefined) delete process.env["USERPROFILE"];
      else process.env["USERPROFILE"] = previousUserProfile;
    }
  });

  test("extracts searchable text from PDFs and DOCX documents", async () => {
    const root = await temporaryDirectory();
    await writeFile(
      join(root, "architecture.pdf"),
      pdf("Payment service boundary"),
    );
    await writeFile(join(root, "threat-model.docx"), docx("SSRF &amp; IDOR"));

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    const documents = await extractedDocuments(knowledgeBase.path);

    expect(documents).toContain("Payment service boundary");
    expect(documents).toContain("SSRF & IDOR\n");
  });

  test("cleans up documents and rediscovers directory contents on later runs", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "scope.md");
    await writeFile(source, "Initial scope");
    const first = await prepareKnowledgeBase([root]);
    await first.cleanup();
    await expect(stat(first.path)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(source, "utf8")).toBe("Initial scope");

    await writeFile(source, "Updated scope");
    await writeFile(join(root, "priorities.txt"), "New attack priorities");
    const second = await prepareKnowledgeBase(first.sources);
    temporaryDirectories.push(second.path);
    const documents = await extractedDocuments(second.path);

    expect(documents.sort()).toEqual([
      "New attack priorities",
      "Updated scope",
    ]);
  });

  test("rejects missing and unsupported paths", async () => {
    const root = await temporaryDirectory();
    const unsupported = join(root, "scope.doc");
    await writeFile(unsupported, "legacy document");

    await expect(prepareKnowledgeBase([""])).rejects.toThrow("cannot be empty");
    await expect(
      prepareKnowledgeBase([join(root, "missing.md")]),
    ).rejects.toThrow();
    await expect(prepareKnowledgeBase([unsupported])).rejects.toThrow(
      "Unsupported knowledge base document",
    );
    await expect(prepareKnowledgeBase([root])).rejects.toThrow(
      "contains no supported documents",
    );
  });

  test("rejects invalid UTF-8, malformed PDFs, and malformed DOCX files", async () => {
    const root = await temporaryDirectory();
    const invalidText = join(root, "invalid.md");
    const invalidPdf = join(root, "invalid.pdf");
    const invalidDocx = join(root, "invalid.docx");
    const invalidXml = join(root, "invalid-xml.docx");
    await writeFile(invalidText, new Uint8Array([0xc3, 0x28]));
    await writeFile(invalidPdf, "not a PDF");
    await writeFile(invalidDocx, zipSync({ "README.md": strToU8("not DOCX") }));
    await writeFile(
      invalidXml,
      zipSync({ "word/document.xml": strToU8("not XML") }),
    );

    await expect(prepareKnowledgeBase([invalidText])).rejects.toThrow(
      "not valid UTF-8",
    );
    await expect(prepareKnowledgeBase([invalidPdf])).rejects.toThrow(
      "Cannot extract text from knowledge base PDF",
    );
    await expect(prepareKnowledgeBase([invalidDocx])).rejects.toThrow(
      "Cannot extract text from knowledge base DOCX",
    );
    await expect(prepareKnowledgeBase([invalidXml])).rejects.toThrow(
      "Cannot extract text from knowledge base DOCX",
    );
  });

  testPosix("does not follow symbolic links", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "scope.md");
    const linked = join(root, "linked.md");
    await writeFile(source, "External APIs");
    await symlink(source, linked);

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "External APIs",
    ]);
    await expect(prepareKnowledgeBase([linked])).rejects.toThrow(
      "cannot be symbolic links",
    );
  });

  testPosix("rejects unreadable source documents", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "scope.md");
    await writeFile(source, "External APIs");
    await chmod(source, 0o000);

    try {
      await expect(prepareKnowledgeBase([source])).rejects.toThrow();
    } finally {
      await chmod(source, 0o600);
    }
  });
});
