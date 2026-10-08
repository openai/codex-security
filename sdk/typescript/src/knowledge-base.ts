import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { unzipSync } from "fflate";
import { expandHome } from "./runtime.js";
import {
  gitMarkerRoot,
  isGitMetadataDirectory,
  nullIfMissingFile,
} from "./targets.js";

const DOCUMENT_EXTENSIONS = new Set([
  ".md",
  ".markdown",
  ".txt",
  ".pdf",
  ".docx",
]);

export interface PreparedKnowledgeBase {
  path: string;
  sources: string[];
  protectedRoots: string[];
  cleanup(): Promise<void>;
}

export interface KnowledgeBaseSnapshot {
  readonly sources: readonly string[];
  readonly protectedRoots?: readonly string[];
  readonly documents: Readonly<Record<string, string>>;
}

/** @internal Extract once so campaign identity and workers use identical inputs. */
export async function readKnowledgeBaseSnapshot(
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<KnowledgeBaseSnapshot> {
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
    const selected = metadata.isDirectory()
      ? (await discover(source, signal)).sort()
      : [source];
    if (selected.length === 0) {
      throw new Error(
        `Knowledge base directory contains no supported documents: ${path}`,
      );
    }
    for (const document of selected) {
      documents.add(document);
    }
    sources.add(source);
  }

  const extracted: Record<string, string> = {};
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
    const name = `${index}-${basename(document)}.txt`;
    // The prefix and suffix can exceed the filesystem's 255-byte name limit.
    const filename = Buffer.byteLength(name) > 255 ? `${index}.txt` : name;
    extracted[filename] = text;
    index++;
  }
  return {
    sources: [...sources],
    protectedRoots: await Promise.all(
      [...sources].map(
        async (source) =>
          (await gitMarkerRoot(source, signal, "outermost")) ?? source,
      ),
    ),
    documents: extracted,
  };
}

export async function prepareKnowledgeBase(
  input: readonly string[] | KnowledgeBaseSnapshot,
  signal?: AbortSignal,
  directory?: string,
): Promise<PreparedKnowledgeBase> {
  const snapshot =
    "documents" in input
      ? input
      : await readKnowledgeBaseSnapshot(input, signal);
  const protectedRoots =
    snapshot.protectedRoots === undefined
      ? await Promise.all(
          snapshot.sources.map(
            async (source) =>
              (await gitMarkerRoot(source, signal, "outermost")) ?? source,
          ),
        )
      : [...snapshot.protectedRoots];
  const path = await mkdtemp(
    join(directory ?? tmpdir(), "codex-security-knowledge-"),
  );
  try {
    for (const [filename, text] of Object.entries(snapshot.documents)) {
      signal?.throwIfAborted();
      await writeFile(join(path, filename), text, {
        encoding: "utf8",
        mode: 0o600,
        signal,
      });
    }
  } catch (error) {
    await rm(path, { recursive: true, force: true });
    throw error;
  }
  return {
    path,
    sources: [...snapshot.sources],
    protectedRoots,
    cleanup: () => rm(path, { recursive: true, force: true }),
  };
}

/** @internal Read the same extracted document text used by scans. */
export async function readKnowledgeBaseDocuments(
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<string[]> {
  const { documents } = await readKnowledgeBaseSnapshot(paths, signal);
  return Object.keys(documents)
    .sort()
    .map((name) => documents[name]!);
}

async function discover(
  directory: string,
  signal?: AbortSignal,
): Promise<string[]> {
  signal?.throwIfAborted();
  const documents: string[] = [];
  const entries = await readdir(directory, { withFileTypes: true });
  signal?.throwIfAborted();
  for (const entry of entries) {
    signal?.throwIfAborted();
    if (
      (process.platform === "win32" ? entry.name.toLowerCase() : entry.name) ===
      ".git"
    )
      continue;
    const path = join(directory, entry.name);
    if (entry.name.toLowerCase() === ".git") {
      const marker = await stat(join(directory, ".git"), {
        bigint: true,
      }).catch(nullIfMissingFile);
      if (marker !== null) {
        const candidate = await lstat(path, { bigint: true });
        if (candidate.dev === marker.dev && candidate.ino === marker.ino) {
          continue;
        }
      }
      if (entry.isDirectory() && (await isGitMetadataDirectory(path, signal))) {
        continue;
      }
    }
    if (entry.isDirectory()) {
      for (const document of await discover(path, signal)) {
        documents.push(document);
      }
    } else if (entry.isFile()) {
      if (!DOCUMENT_EXTENSIONS.has(extname(path).toLowerCase())) {
        const bytes = await readFile(path, {
          flag: constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
          signal,
        });
        try {
          decodeText(path, bytes);
        } catch {
          continue;
        }
      }
      documents.push(path);
    }
  }
  return documents;
}

function decodeText(path: string, bytes: Uint8Array): string {
  if (bytes.includes(0)) {
    throw new Error(`Knowledge base document contains binary data: ${path}`);
  }
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
    const { getDocument, VerbosityLevel } =
      await import("pdfjs-dist/legacy/build/pdf.mjs");
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
