import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { unzipSync } from "fflate";
import { expandHome } from "./runtime.js";

const SUPPORTED_EXTENSIONS = new Set([
  ".md",
  ".markdown",
  ".txt",
  ".pdf",
  ".docx",
]);

export interface PreparedKnowledgeBase {
  path: string;
  sources: string[];
  cleanup(): Promise<void>;
}

export async function prepareKnowledgeBase(
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<PreparedKnowledgeBase> {
  const sources = new Set<string>();
  const documents = new Set<string>();

  for (const requested of paths) {
    signal?.throwIfAborted();
    if (!requested.trim())
      throw new Error("Knowledge base paths cannot be empty.");
    const path = resolve(expandHome(requested));
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`Knowledge base paths cannot be symbolic links: ${path}`);
    }
    if (!metadata.isFile() && !metadata.isDirectory()) {
      throw new Error(
        `Knowledge base path is not a file or directory: ${path}`,
      );
    }

    const source = await realpath(path);
    const selected = metadata.isDirectory() ? await discover(source) : [source];
    if (selected.length === 0) {
      throw new Error(
        `Knowledge base directory contains no supported documents: ${path}`,
      );
    }
    for (const document of selected) {
      if (!SUPPORTED_EXTENSIONS.has(extname(document).toLowerCase())) {
        throw new Error(`Unsupported knowledge base document: ${document}`);
      }
      documents.add(document);
    }
    sources.add(source);
  }

  const path = await mkdtemp(join(tmpdir(), "codex-security-knowledge-"));
  try {
    let index = 0;
    for (const document of documents) {
      signal?.throwIfAborted();
      const metadata = await lstat(document);
      if (process.platform !== "win32" && (metadata.mode & 0o444) === 0) {
        throw new Error(`Knowledge base document is not readable: ${document}`);
      }
      const bytes = await readFile(document, {
        flag: constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
        signal,
      });
      const extension = extname(document).toLowerCase();
      const text =
        extension === ".pdf"
          ? await extractPdf(document, bytes)
          : extension === ".docx"
            ? extractDocx(document, bytes)
            : decodeText(document, bytes);
      if ((extension === ".pdf" || extension === ".docx") && !text.trim()) {
        throw new Error(
          `Knowledge base document contains no extractable text: ${document}`,
        );
      }
      await writeFile(
        join(path, `${index++}-${basename(document)}.txt`),
        text,
        {
          encoding: "utf8",
          mode: 0o600,
          signal,
        },
      );
    }
  } catch (error) {
    await rm(path, { recursive: true, force: true });
    throw error;
  }

  return {
    path,
    sources: [...sources],
    cleanup: () => rm(path, { recursive: true, force: true }),
  };
}

async function discover(directory: string): Promise<string[]> {
  const documents: string[] = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      documents.push(...(await discover(path)));
    } else if (
      entry.isFile() &&
      SUPPORTED_EXTENSIONS.has(extname(path).toLowerCase())
    ) {
      documents.push(path);
    }
  }
  return documents;
}

function decodeText(path: string, bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`Knowledge base document is not valid UTF-8: ${path}`, {
      cause: error,
    });
  }
}

async function extractPdf(path: string, bytes: Uint8Array): Promise<string> {
  try {
    const { getDocument, VerbosityLevel } = await import(
      "pdfjs-dist/legacy/build/pdf.mjs"
    );
    const loadingTask = getDocument({
      data: new Uint8Array(bytes),
      stopAtErrors: true,
      verbosity: VerbosityLevel.ERRORS,
    });
    try {
      const document = await loadingTask.promise;
      const pages: string[] = [];
      for (let number = 1; number <= document.numPages; number++) {
        const content = await (await document.getPage(number)).getTextContent();
        pages.push(
          content.items
            .map((item) => ("str" in item ? item.str : ""))
            .join(" "),
        );
      }
      return pages.join("\n");
    } finally {
      await loadingTask.destroy();
    }
  } catch (error) {
    throw new Error(`Cannot extract text from knowledge base PDF: ${path}`, {
      cause: error,
    });
  }
}

function extractDocx(path: string, bytes: Uint8Array): string {
  try {
    const files = unzipSync(bytes, {
      filter: (file) => {
        if (file.name !== "word/document.xml") return false;
        if (file.originalSize > 25 * 1024 * 1024) {
          throw new Error("DOCX document text exceeds 25 MB.");
        }
        return true;
      },
    });
    const document = files["word/document.xml"];
    if (document === undefined) throw new Error("Missing word/document.xml.");
    const xml = decodeText(path, document);
    if (
      !/<(?:\w+:)?document\b[^>]*>[\s\S]*<\/(?:\w+:)?document\s*>/u.test(xml)
    ) {
      throw new Error("Malformed word/document.xml.");
    }
    return decodeXml(
      xml
        .replace(/<\/(?:\w+:)?p\s*>/gu, "\n")
        .replace(/<(?:\w+:)?tab\b[^>]*\/>/gu, "\t")
        .replace(/<[^>]+>/gu, ""),
    );
  } catch (error) {
    throw new Error(`Cannot extract text from knowledge base DOCX: ${path}`, {
      cause: error,
    });
  }
}

function decodeXml(value: string): string {
  const entities: Record<string, string> = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
  };
  return value.replace(
    /&(amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);/giu,
    (entity, name: string) => {
      if (!name.startsWith("#")) return entities[name.toLowerCase()] ?? entity;
      const hexadecimal = name[1]?.toLowerCase() === "x";
      return String.fromCodePoint(
        Number.parseInt(name.slice(hexadecimal ? 2 : 1), hexadecimal ? 16 : 10),
      );
    },
  );
}
