import { spawn } from "node:child_process";
import { createHash, hash } from "node:crypto";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import { portableRelativePath } from "./contract-values.js";
import {
  type DependencyAttemptStore,
  dependencyRecordHash,
} from "./dependency-attempt-store.js";
import {
  dependencyGitCommitSchema,
  readDependencyGitSource,
} from "./dependency-source-identity.js";
import { errorMessage } from "./errors.js";
import { resolvePluginPython } from "./runtime.js";

const github = z.strictObject({
  kind: z.literal("github"),
  owner: z.string().regex(/^[\w-]+$/u),
  repository: z.string().regex(/^[\w.-]+$/u),
  commit: z.string().regex(/^[0-9a-f]{40}$/u),
  path: z.string(),
});
const npm = z.strictObject({
  kind: z.literal("npm"),
  name: z.string().regex(/^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/u),
  version: z
    .string()
    .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u),
  path: z.string(),
});
const githubAdvisory = z.strictObject({
  kind: z.literal("github_advisory"),
  owner: github.shape.owner,
  repository: github.shape.repository,
  advisoryId: z.string().regex(/^GHSA-(?:[a-z0-9]{4}-){2}[a-z0-9]{4}$/u),
});
const localGit = z.strictObject({
  kind: z.literal("git"),
  commit: dependencyGitCommitSchema,
  path: z.string(),
});
const requestSchema = z.discriminatedUnion("kind", [
  localGit,
  github,
  githubAdvisory,
  npm,
]);
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const savedSchema = z.strictObject({
  request: requestSchema,
  url: z.url().optional(),
  git: z
    .strictObject({
      repositoryRoot: z.string(),
      blob: z.string(),
    })
    .optional(),
  archiveIntegrity: z.string().optional(),
  sha256: digest,
  capturedAt: z.iso.datetime(),
  source: z.string(),
});
const rangeSchema = z.strictObject({
  sourceId: digest,
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
});
const excerptSchema = z.union([
  rangeSchema,
  z.strictObject({
    sourceId: digest,
    search: z.string().min(1),
  }),
]);

// Bound remote transfers and decompression. A model can cite only the selected file.
const sourceBytes = 8 * 1024 * 1024;
const archiveBytes = 128 * 1024 * 1024;
type FetchSource = (url: string, init: RequestInit) => Promise<Response>;

async function download(
  fetcher: FetchSource,
  url: string,
  limit: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  let response: Response;
  try {
    response = await fetcher(url, {
      redirect: "error",
      credentials: "omit",
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    const detail =
      error instanceof Error && error.cause instanceof Error
        ? `${error.message}: ${error.cause.message}`
        : errorMessage(error);
    throw new Error(`Source lookup failed for ${url}: ${detail}`, {
      cause: error,
    });
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(
      `Source lookup failed with HTTP ${response.status}: ${url}`,
    );
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = response.body?.getReader();
  if (reader) {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > limit) {
          await reader.cancel();
          throw new Error(`Source download exceeds ${limit} bytes: ${url}`);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
  }
  return Buffer.concat(chunks, size);
}

// Read one regular entry. Never extract an archive or follow its links.
// Limit decompressed bytes including headers and metadata, not only member sizes.
const readArchive = `
import gzip, io, sys, tarfile
path, file_limit, total_limit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
class Bounded(io.RawIOBase):
    def __init__(self, stream):
        self.stream = stream
        self.remaining = total_limit
    def readable(self):
        return True
    def readinto(self, buffer):
        data = self.stream.read(min(len(buffer), self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("Uncompressed package exceeds the source archive budget")
        buffer[:len(data)] = data
        return len(data)
with gzip.GzipFile(fileobj=io.BytesIO(sys.stdin.buffer.read())) as source:
    with tarfile.open(fileobj=io.BufferedReader(Bounded(source)), mode="r|") as archive:
        result = None
        for entry in archive:
            if entry.name != path:
                continue
            if result is not None:
                raise ValueError("Package contains more than one entry for the requested file")
            if entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or entry.size > file_limit:
                raise ValueError("Requested package entry is not a bounded regular file")
            result = archive.extractfile(entry).read()
        if result is None:
            raise ValueError("Requested source file is absent from the release")
        sys.stdout.buffer.write(result)
`;

async function packageFile(
  python: string,
  bytes: Buffer,
  path: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      python,
      [
        "-I",
        "-B",
        "-c",
        readArchive,
        `package/${path}`,
        String(sourceBytes),
        String(archiveBytes),
      ],
      { signal, windowsHide: true },
    );
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(Buffer.concat(output));
      else
        reject(
          new Error(
            `Read package source failed: ${Buffer.concat(errors).toString("utf8").trim()}`,
          ),
        );
    });
    // A parser error can close stdin before the parent finishes writing.
    child.stdin.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EPIPE") reject(error);
    });
    child.stdin.end(bytes);
  });
}

const releaseSchema = z.object({
  name: z.string(),
  version: z.string(),
  dist: z.object({ tarball: z.url(), integrity: z.string() }),
});

interface SourceOptions {
  store: DependencyAttemptStore;
  repository: string;
  recordExcerpt(excerpt: JsonObject): string;
  /** Host transport for the explicitly authorized public-source tools. */
  fetcher: FetchSource;
  python?: string;
  signal?: AbortSignal;
}

export function createDependencySourceTools(options: SourceOptions) {
  const { fetcher, signal, store } = options;
  const pending = new Map<
    string,
    Promise<{
      sourceId: string;
      artifact: z.infer<typeof savedSchema>;
    }>
  >();

  function read(sourceId: string) {
    const saved = store.get("source-artifact", sourceId);
    if (saved === undefined) return;
    const artifact = savedSchema.parse(saved);
    if (
      dependencyRecordHash(artifact) !== sourceId ||
      hash("sha256", artifact.source) !== artifact.sha256
    )
      throw new Error(`Saved source evidence changed: ${sourceId}`);
    return artifact;
  }

  function cached(requestId: string) {
    const savedId = store.get("source-request", requestId);
    if (savedId === undefined) return;
    const sourceId = digest.parse(savedId);
    const artifact = read(sourceId);
    if (!artifact || dependencyRecordHash(artifact.request) !== requestId)
      throw new Error("Saved source reference does not match the request.");
    return { sourceId, artifact };
  }

  async function capture(
    request: z.infer<typeof requestSchema>,
    requestId: string,
  ) {
    const saved = cached(requestId);
    if (saved) return saved;
    let url: string | undefined;
    let git: z.infer<typeof savedSchema>["git"];
    let archiveIntegrity: string | undefined;
    let bytes: Buffer;
    if (request.kind === "git") {
      const captured = await readDependencyGitSource(
        options.repository,
        request.commit,
        request.path,
        signal,
      );
      bytes = captured.bytes;
      git = {
        repositoryRoot: captured.identity.repositoryRoot,
        blob: captured.identity.blob,
      };
    } else if (
      request.kind === "github" ||
      request.kind === "github_advisory"
    ) {
      if (request.repository === "." || request.repository === "..")
        throw new Error("Expected a GitHub repository name.");
      if (request.kind === "github") {
        const path = request.path.split("/").map(encodeURIComponent).join("/");
        url = `https://raw.githubusercontent.com/${request.owner}/${request.repository}/${request.commit}/${path}`;
      } else {
        url = `https://github.com/${request.owner}/${request.repository}/security/advisories/${request.advisoryId}`;
      }
      bytes = await download(fetcher, url, sourceBytes, signal);
    } else {
      const metadataUrl = `https://registry.npmjs.org/${encodeURIComponent(request.name)}/${encodeURIComponent(request.version)}`;
      const release = releaseSchema.parse(
        JSON.parse(
          (await download(fetcher, metadataUrl, sourceBytes, signal)).toString(
            "utf8",
          ),
        ),
      );
      if (release.name !== request.name || release.version !== request.version)
        throw new Error(
          "Registry response does not match the requested package and release.",
        );
      const tarball = new URL(release.dist.tarball);
      if (
        tarball.origin !== "https://registry.npmjs.org" ||
        tarball.username ||
        tarball.password
      )
        throw new Error("Package tarball must come from the npm registry.");
      url = tarball.href;
      archiveIntegrity = release.dist.integrity
        .split(/\s+/u)
        .find((digest) =>
          /^sha(?:512|384|256)-[A-Za-z0-9+/]+=*$/u.test(digest),
        );
      if (!archiveIntegrity)
        throw new Error(
          "Package release has no supported archive integrity digest.",
        );
      const archive = await download(fetcher, url, archiveBytes, signal);
      const [algorithm, expected] = archiveIntegrity.split("-", 2);
      if (createHash(algorithm!).update(archive).digest("base64") !== expected)
        throw new Error(
          "Package archive does not match its registry integrity digest.",
        );
      const python =
        options.python ??
        (await resolvePluginPython({
          protectedRoot: options.repository,
          currentDirectory: options.repository,
          signal,
        }));
      bytes = await packageFile(python, archive, request.path, signal);
    }
    // Keep the bytes exact, including a UTF-8 BOM, for the content digest.
    const source = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
    const artifact = {
      request,
      ...(url && { url }),
      ...(git && { git }),
      ...(archiveIntegrity && { archiveIntegrity }),
      sha256: hash("sha256", bytes),
      capturedAt: new Date().toISOString(),
      source,
    };
    const sourceId = dependencyRecordHash(artifact);
    signal?.throwIfAborted();
    return store.transaction(() => {
      const saved = cached(requestId);
      if (saved) return saved;
      store.set("source-artifact", sourceId, artifact);
      store.set("source-request", requestId, sourceId);
      return { sourceId, artifact };
    });
  }

  async function fetchSource(input: unknown): Promise<JsonObject> {
    signal?.throwIfAborted();
    const request = requestSchema.parse(input);
    if (request.kind !== "github_advisory")
      request.path = portableRelativePath(request.path, "Source path");
    const requestId = dependencyRecordHash(request);
    let task = pending.get(requestId);
    if (!task) {
      task = capture(request, requestId);
      pending.set(requestId, task);
    }
    try {
      const {
        sourceId,
        artifact: { source: _source, ...origin },
      } = await task;
      return { sourceId, ...origin };
    } finally {
      if (pending.get(requestId) === task) pending.delete(requestId);
    }
  }

  async function excerpt(input: unknown): Promise<JsonObject> {
    signal?.throwIfAborted();
    const request = excerptSchema.parse(input);
    const { sourceId } = request;
    const artifact = read(sourceId);
    if (!artifact) throw new Error(`Unknown source evidence: ${sourceId}`);
    const { source, ...origin } = artifact;
    const lines = source.match(/[^\n]*\n|[^\n]+$/gu) ?? [];
    if ("search" in request) {
      return {
        sourceId,
        matchingLines: lines.flatMap((line, index) =>
          line.includes(request.search) ? [index + 1] : [],
        ),
        totalLines: lines.length,
      };
    }
    const { startLine, endLine: requestedEndLine } = request;
    const lineCount = lines.length;
    const endLine = Math.min(requestedEndLine, lineCount);
    if (startLine > endLine)
      throw new Error(
        `Invalid source range ${startLine}–${requestedEndLine}; file has ${lineCount} lines.`,
      );
    const excerpt = {
      sourceId,
      ...origin,
      startLine,
      endLine,
      text: lines.slice(startLine - 1, endLine).join(""),
    };
    return {
      ...excerpt,
      requestedRange: { startLine, endLine: requestedEndLine },
      lineCount,
      receiptId: options.recordExcerpt(excerpt),
    };
  }

  return [
    {
      name: "fetch_dependency_source",
      description:
        "Capture one UTF-8 file from a local Git commit, a public GitHub commit or maintainer advisory, or an integrity-verified npm release. Returns provenance and a source ID.",
      inputSchema: {
        type: "object",
        ...(z.toJSONSchema(requestSchema) as JsonObject),
      },
      run: fetchSource,
    },
    {
      name: "read_dependency_source",
      description:
        "Search for literal text in a captured source, or read an inclusive line range to register a review receipt. Cite the returned startLine and endLine. Search only returns matching line numbers.",
      inputSchema: {
        type: "object",
        ...(z.toJSONSchema(excerptSchema) as JsonObject),
      },
      run: excerpt,
    },
  ];
}
