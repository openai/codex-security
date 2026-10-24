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
import { SaxesParser } from "saxes";
import { ConfigurationError, errorMessage } from "./errors.js";
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

export async function knowledgeBaseProtectedRoots(
  snapshot: KnowledgeBaseSnapshot,
  signal?: AbortSignal,
): Promise<string[]> {
  return snapshot.protectedRoots === undefined
    ? await Promise.all(
        snapshot.sources.map(
          async (source) =>
            (await gitMarkerRoot(source, signal, "outermost")) ?? source,
        ),
      )
    : [...snapshot.protectedRoots];
}

/** @internal Extract once so campaign identity and workers use identical inputs. */
export async function readKnowledgeBaseSnapshot(
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<KnowledgeBaseSnapshot> {
  try {
    const sources = new Set<string>();
    const documents = new Set<string>();

    for (const requested of paths) {
      signal?.throwIfAborted();
      if (!requested.trim())
        throw new Error("Knowledge base paths cannot be empty.");
      const path = resolve(expandHome(requested));
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) {
        throw new Error(
          `Knowledge base paths cannot be symbolic links: ${path}`,
        );
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
          ? await extractPdf(document, bytes, signal)
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
    const snapshot = {
      sources: [...sources],
      documents: extracted,
    };
    return {
      ...snapshot,
      protectedRoots: await knowledgeBaseProtectedRoots(snapshot, signal),
    };
  } catch (error) {
    if (signal?.aborted || error instanceof ConfigurationError) throw error;
    throw new ConfigurationError(errorMessage(error), { cause: error });
  }
}

export async function prepareKnowledgeBase(
  input: readonly string[] | KnowledgeBaseSnapshot,
  signal?: AbortSignal,
  directory?: string,
): Promise<PreparedKnowledgeBase> {
  try {
    const snapshot =
      "documents" in input
        ? input
        : await readKnowledgeBaseSnapshot(input, signal);
    const protectedRoots = await knowledgeBaseProtectedRoots(snapshot, signal);
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
  } catch (error) {
    if (signal?.aborted || error instanceof ConfigurationError) throw error;
    throw new ConfigurationError(errorMessage(error), { cause: error });
  }
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
      // Office keeps a "~$" owner file next to each open document.
      if (entry.name.startsWith("~$")) continue;
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

async function extractPdf(
  path: string,
  bytes: Uint8Array,
  signal?: AbortSignal,
): Promise<string> {
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
        signal?.throwIfAborted();
        const content = await (await document.getPage(number)).getTextContent();
        signal?.throwIfAborted();
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
    if (signal?.aborted) throw error;
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
    let text: string[] = [];
    let fields: {
      instructions: boolean;
      literal: string[];
      result: string[];
    }[] = [];
    const stories: { text: string[]; fields: typeof fields }[] = [];
    const parser = new SaxesParser();
    let documentElement = false;
    let deletedDepth = 0;
    let instructionText = false;
    const append = (value: string) => {
      if (deletedDepth > 0) return;
      const field = fields.at(-1);
      if (field === undefined) text.push(value);
      else if (!field.instructions) field.result.push(value);
      else if (!instructionText) field.literal.push(value);
    };
    const finishField = (closed: boolean) => {
      const field = fields.pop();
      if (field !== undefined) {
        // Unclosed fields retain ordinary runs; completed fields show only results.
        append((closed ? "" : field.literal.join("")) + field.result.join(""));
      }
    };
    parser.on("opentag", ({ name, attributes }) => {
      const localName = name.split(":").at(-1);
      if (
        localName === "del" ||
        localName === "delText" ||
        localName === "delInstrText"
      ) {
        deletedDepth++;
      }
      if (deletedDepth > 0) return;
      if (localName === "txbxContent") {
        // Text boxes have their own field boundaries.
        stories.push({ text, fields });
        text = [];
        fields = [];
      } else if (localName === "document") documentElement = true;
      else if (localName === "instrText") instructionText = true;
      else if (localName === "fldChar") {
        const type = decodeXml(
          Object.entries(attributes).find(
            ([name]) => name.split(":").at(-1) === "fldCharType",
          )?.[1] ?? "",
        );
        if (type === "begin")
          fields.push({ instructions: true, literal: [], result: [] });
        else if (type === "separate" && fields.length > 0)
          fields.at(-1)!.instructions = false;
        else if (type === "end") finishField(true);
      } else if (localName === "br" || localName === "cr") append("\n");
      else if (localName === "tab") append("\t");
    });
    parser.on("closetag", ({ name, isSelfClosing }) => {
      const localName = name.split(":").at(-1);
      if (deletedDepth === 0 && localName === "txbxContent") {
        while (fields.length > 0) finishField(false);
        const content = text.join("");
        ({ text, fields } = stories.pop()!);
        append(content);
      }
      if (localName === "instrText") instructionText = false;
      if (!isSelfClosing && localName === "p") append("\n");
      if (
        localName === "del" ||
        localName === "delText" ||
        localName === "delInstrText"
      ) {
        deletedDepth--;
      }
    });
    parser.on("text", (value) => append(decodeXml(value)));
    parser.on("cdata", (value) => append(value.replaceAll("&amp;", "&")));
    // Keep the existing entity decoder's handling of unusable references.
    // CDATA is literal text, so only undo this escaping in its handler.
    parser.write(xml.replaceAll("&", "&amp;")).close();
    if (!documentElement) throw new Error("Malformed word/document.xml.");
    while (fields.length > 0) finishField(false);
    return text.join("");
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
      const codePoint = Number.parseInt(
        name.slice(hexadecimal ? 2 : 1),
        hexadecimal ? 16 : 10,
      );
      if (
        codePoint > 0x10ffff ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      ) {
        return entity;
      }
      return String.fromCodePoint(codePoint);
    },
  );
}
