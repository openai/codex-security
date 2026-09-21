import { execFile as execFileCallback } from "node:child_process";
import { lstat, readFile, realpath } from "node:fs/promises";
import { devNull } from "node:os";
import { isAbsolute, join, relative, resolve, win32 } from "node:path";
import { promisify } from "node:util";
import { z } from "incur";
import { resolveTrustedExecutable } from "../trusted-executable.js";
import { windowsUnsafePathComponent } from "../windows-path.js";
import type { DeduplicationReviewFailureObservation } from "./review-failure.js";

const execFile = promisify(execFileCallback);
const revisionSchema = z
  .string()
  .trim()
  .regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/iu);
const readFileSchema = z
  .object({
    revision: revisionSchema,
    path: z.string().min(1).max(1024),
    startLine: z.number().int().positive().optional(),
    endLine: z.number().int().positive().optional(),
  })
  .strict();
const searchSchema = z
  .object({
    revision: revisionSchema,
    query: z.string().min(1).max(256),
    paths: z.array(z.string().min(1).max(1024)).max(20).optional(),
    limit: z.number().int().positive().max(100).optional(),
  })
  .strict();

const GIT_TIMEOUT_MS = 10_000;
const GIT_MAX_BUFFER_BYTES = 2 * 1024 * 1024;
const MAX_READ_LINES = 400;
const MAX_READ_BYTES = 64 * 1024;
const SEARCH_MAX_BUFFER_BYTES = 256 * 1024;

export const reviewSourceNamespace = {
  type: "namespace",
  name: "review_source",
  description:
    "Read or search the host-authorized Git checkout at an immutable revision. This namespace cannot access another repository, the network, or the working tree.",
  tools: [
    {
      type: "function",
      name: "read_file",
      description:
        "Read at most 400 lines from a repository-relative text file at a full immutable Git revision.",
      inputSchema: z.toJSONSchema(readFileSchema, { target: "openapi-3.0" }),
    },
    {
      type: "function",
      name: "search",
      description:
        "Search literal text in the host-authorized checkout at a full immutable Git revision, optionally below repository-relative path prefixes.",
      inputSchema: z.toJSONSchema(searchSchema, { target: "openapi-3.0" }),
    },
  ],
} as const;

export class ReviewSourceError extends Error {
  public constructor(
    message: string,
    public readonly observation: DeduplicationReviewFailureObservation,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ReviewSourceError";
  }
}

function sourceAccessError(
  message: string,
  cause?: unknown,
): ReviewSourceError {
  return new ReviewSourceError(
    message,
    { kind: "source", outcome: "access-unavailable" },
    cause === undefined ? undefined : { cause },
  );
}

function sourceRevisionError(
  message: string,
  cause?: unknown,
): ReviewSourceError {
  return new ReviewSourceError(
    message,
    { kind: "source", outcome: "revision-unavailable" },
    cause === undefined ? undefined : { cause },
  );
}

function validatedPath(value: string): string {
  if (
    value.includes("\0") ||
    value.includes("\\") ||
    isAbsolute(value) ||
    win32.isAbsolute(value) ||
    value.startsWith("-")
  ) {
    throw new Error("Source paths must be repository-relative Git paths.");
  }
  if (process.platform === "win32" && windowsUnsafePathComponent(value))
    throw new Error("Source paths must be unambiguous on Windows.");
  const parts = value.split("/");
  if (
    parts.some(
      (part) =>
        part.length === 0 ||
        part === "." ||
        part === ".." ||
        part.toLowerCase() === ".git",
    )
  ) {
    throw new Error("Source paths cannot traverse or access Git metadata.");
  }
  return value;
}

function validatedQuery(value: string): string {
  if (value.includes("\0") || value.startsWith("-"))
    throw new Error("Search queries cannot contain NULs or Git options.");
  return value;
}

function truncateUtf8(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value);
  if (bytes.length <= maxBytes) return value;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (let end = maxBytes; end > 0; end--) {
    try {
      return decoder.decode(bytes.subarray(0, end));
    } catch {
      continue;
    }
  }
  return "";
}

function isolatedGitEnvironment(
  environment: Readonly<NodeJS.ProcessEnv>,
): NodeJS.ProcessEnv {
  const isolated = { ...environment };
  for (const name of Object.keys(isolated)) {
    if (name.toUpperCase().startsWith("GIT_")) delete isolated[name];
  }
  return {
    ...isolated,
    GIT_ALLOW_PROTOCOL: "",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: devNull,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_GRAFT_FILE: devNull,
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
    PAGER: "cat",
  };
}

function exitCode(error: unknown): string | number | undefined {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { code?: string | number }).code
    : undefined;
}

interface GitBoundary {
  root: string;
  gitDirectory: string;
  commonDirectory: string;
  objectDirectory: string;
}

export class ReviewSource {
  private running = false;

  private constructor(
    private readonly checkout: string,
    private readonly checkoutRevision: string,
    private readonly git: string,
    private readonly environment: NodeJS.ProcessEnv,
    private readonly boundary: GitBoundary | undefined,
    private readonly signal?: AbortSignal,
  ) {}

  public static async open(
    checkout: string,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
    signal?: AbortSignal,
  ): Promise<ReviewSource> {
    let canonical: string;
    try {
      canonical = await realpath(checkout);
    } catch (error) {
      throw sourceAccessError(
        "The approved source checkout is unavailable.",
        error,
      );
    }
    const command = await resolveTrustedExecutable(
      "git",
      isolatedGitEnvironment(environment),
      canonical,
    );
    if (command === null)
      throw sourceAccessError("Git is unavailable on a trusted PATH.");
    const source = new ReviewSource(
      canonical,
      "",
      command.executable,
      isolatedGitEnvironment(command.environment),
      undefined,
      signal,
    );
    let revision: string;
    let boundary: GitBoundary;
    try {
      boundary = await source.inspectBoundary();
      revision = await source.rawGitOutput(
        ["rev-parse", "--verify", "HEAD^{commit}"],
        GIT_MAX_BUFFER_BYTES,
      );
    } catch (error) {
      if (error instanceof ReviewSourceError) throw error;
      throw sourceAccessError(
        "The approved source checkout could not be inspected.",
        error,
      );
    }
    return new ReviewSource(
      canonical,
      revision.toLowerCase(),
      command.executable,
      isolatedGitEnvironment(command.environment),
      boundary,
      signal,
    );
  }

  public async call(tool: string, input: unknown): Promise<unknown> {
    if (this.running)
      throw sourceAccessError("Another source operation is already running.");
    this.running = true;
    try {
      await this.assertBoundary();
      let result: unknown;
      try {
        if (tool === "read_file") result = await this.readFile(input);
        else if (tool === "search") result = await this.search(input);
        else throw new Error("Unknown review source tool.");
      } catch (error) {
        await this.assertBoundary();
        throw error;
      }
      await this.assertBoundary();
      return result;
    } finally {
      this.running = false;
    }
  }

  private async readFile(input: unknown): Promise<unknown> {
    const request = readFileSchema.parse(input);
    const revision = await this.requireRevision(request.revision);
    const path = validatedPath(request.path);
    const startLine = request.startLine ?? 1;
    const endLine = request.endLine ?? startLine + MAX_READ_LINES - 1;
    if (endLine < startLine || endLine - startLine + 1 > MAX_READ_LINES)
      throw new Error(`read_file accepts at most ${MAX_READ_LINES} lines.`);
    let source: string;
    try {
      source = await this.sourceGitOutput(
        ["cat-file", "blob", `${revision}:${path}`],
        GIT_MAX_BUFFER_BYTES,
        [],
        false,
      );
    } catch (error) {
      throw sourceAccessError(
        "The requested source file could not be read from the approved revision.",
        error,
      );
    }
    if (source.includes("\0"))
      throw sourceAccessError("The requested source file is not text.");
    const lines = source.split(/\r?\n/u);
    const content = lines.slice(startLine - 1, endLine).join("\n");
    const bytes = Buffer.from(content);
    const truncated = bytes.length > MAX_READ_BYTES;
    return {
      revision,
      path,
      startLine,
      endLine: Math.min(endLine, lines.length),
      content: truncated ? truncateUtf8(content, MAX_READ_BYTES) : content,
      truncated,
    };
  }

  private async search(input: unknown): Promise<unknown> {
    const request = searchSchema.parse(input);
    const revision = await this.requireRevision(request.revision);
    const query = validatedQuery(request.query);
    const paths = (request.paths ?? []).map(validatedPath);
    const limit = request.limit ?? 50;
    let output: string;
    try {
      output = await this.sourceGitOutput(
        [
          "grep",
          "-z",
          "--no-recurse-submodules",
          "--no-textconv",
          "--full-name",
          "-n",
          "-I",
          "-F",
          "-e",
          query,
          revision,
          "--",
          ...paths,
        ],
        SEARCH_MAX_BUFFER_BYTES,
        [1],
        false,
      );
    } catch (error) {
      throw sourceAccessError(
        "The approved source revision could not be searched.",
        error,
      );
    }
    const matches: { path: string; line: number; text: string }[] = [];
    const prefix = `${revision}:`;
    let offset = 0;
    while (offset < output.length && matches.length < limit) {
      const pathEnd = output.indexOf("\0", offset);
      const lineEnd = output.indexOf("\0", pathEnd + 1);
      const textEnd = output.indexOf("\n", lineEnd + 1);
      if (pathEnd < offset || lineEnd < pathEnd || textEnd < lineEnd)
        throw sourceAccessError("Git returned an invalid search result.");
      const framedPath = output.slice(offset, pathEnd);
      const line = output.slice(pathEnd + 1, lineEnd);
      if (!framedPath.startsWith(prefix) || !/^[1-9]\d*$/u.test(line))
        throw sourceAccessError("Git returned an invalid search result.");
      const text = output.slice(lineEnd + 1, textEnd).replace(/\r$/u, "");
      matches.push({
        path: framedPath.slice(prefix.length),
        line: Number(line),
        text,
      });
      offset = textEnd + 1;
    }
    return { revision, query, matches, truncated: matches.length === limit };
  }

  private async requireRevision(requested: string): Promise<string> {
    const revision = requested.toLowerCase();
    let current: string;
    let resolved: string;
    try {
      current = await this.rawGitOutput(
        ["rev-parse", "--verify", "HEAD^{commit}"],
        GIT_MAX_BUFFER_BYTES,
      );
      resolved = await this.rawGitOutput(
        ["rev-parse", "--verify", "--end-of-options", `${revision}^{commit}`],
        GIT_MAX_BUFFER_BYTES,
      );
    } catch (error) {
      if (exitCode(error) !== 128)
        throw sourceAccessError(
          "Git could not inspect the approved source checkout.",
          error,
        );
      throw sourceRevisionError(
        "The requested source revision is unavailable in the approved checkout.",
        error,
      );
    }
    if (
      current.toLowerCase() !== this.checkoutRevision ||
      resolved.toLowerCase() !== revision
    ) {
      throw sourceRevisionError(
        "The approved checkout or requested source revision changed.",
      );
    }
    return revision;
  }

  private async sourceGitOutput(
    args: readonly string[],
    maxBuffer: number,
    acceptedExitCodes: readonly number[] = [],
    trimFinalNewline = true,
  ): Promise<string> {
    await this.assertBoundary();
    try {
      const output = await this.rawGitOutput(
        args,
        maxBuffer,
        acceptedExitCodes,
        trimFinalNewline,
      );
      await this.assertBoundary();
      return output;
    } catch (error) {
      await this.assertBoundary();
      throw error;
    }
  }

  private async inspectBoundary(): Promise<GitBoundary> {
    let root: string;
    let gitDirectory: string;
    let commonDirectory: string;
    let objectDirectory: string;
    try {
      root = await this.rawGitOutput(
        ["rev-parse", "--show-toplevel"],
        GIT_MAX_BUFFER_BYTES,
      );
      gitDirectory = await this.rawGitOutput(
        ["rev-parse", "--absolute-git-dir"],
        GIT_MAX_BUFFER_BYTES,
      );
      commonDirectory = await this.rawGitOutput(
        ["rev-parse", "--git-common-dir"],
        GIT_MAX_BUFFER_BYTES,
      );
      objectDirectory = await this.rawGitOutput(
        ["rev-parse", "--git-path", "objects"],
        GIT_MAX_BUFFER_BYTES,
      );
    } catch (error) {
      throw sourceAccessError(
        "The approved source checkout's Git boundary could not be inspected.",
        error,
      );
    }
    const canonicalize = async (path: string): Promise<string> =>
      await realpath(resolve(this.checkout, path)).catch((error) => {
        throw sourceAccessError(
          "The approved source checkout's Git boundary is unavailable.",
          error,
        );
      });
    const boundary = {
      root: await canonicalize(root),
      gitDirectory: await canonicalize(gitDirectory),
      commonDirectory: await canonicalize(commonDirectory),
      objectDirectory: await canonicalize(objectDirectory),
    };
    if (relative(this.checkout, boundary.root) !== "")
      throw sourceAccessError(
        "The approved source checkout is not the canonical Git worktree root.",
      );
    if (
      relative(boundary.commonDirectory, boundary.objectDirectory) !== "objects"
    ) {
      throw sourceAccessError(
        "The approved checkout uses an external Git object store.",
      );
    }
    await this.assertNoAlternates(boundary.objectDirectory);
    return boundary;
  }

  private async assertBoundary(): Promise<void> {
    if (this.boundary === undefined) return;
    const current = await this.inspectBoundary();
    if (
      current.root !== this.boundary.root ||
      current.gitDirectory !== this.boundary.gitDirectory ||
      current.commonDirectory !== this.boundary.commonDirectory ||
      current.objectDirectory !== this.boundary.objectDirectory
    ) {
      throw sourceAccessError(
        "The approved source checkout's Git boundary changed.",
      );
    }
  }

  private async assertNoAlternates(objectDirectory: string): Promise<void> {
    const informationDirectory = join(objectDirectory, "info");
    const information = await lstat(informationDirectory).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined;
        throw sourceAccessError(
          "The approved checkout's Git object store could not be inspected.",
          error,
        );
      },
    );
    if (information === undefined) return;
    if (information.isSymbolicLink() || !information.isDirectory())
      throw sourceAccessError(
        "The approved checkout's Git object metadata is not a directory.",
      );
    for (const name of ["alternates", "http-alternates"]) {
      const path = join(informationDirectory, name);
      const metadata = await lstat(path).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return undefined;
          throw sourceAccessError(
            "The approved checkout's Git object store could not be inspected.",
            error,
          );
        },
      );
      if (metadata === undefined) continue;
      if (metadata.isSymbolicLink() || !metadata.isFile())
        throw sourceAccessError(
          "The approved checkout's Git object metadata is not a regular file.",
        );
      const contents = await readFile(path, "utf8").catch((error) => {
        throw sourceAccessError(
          "The approved checkout's Git object store could not be inspected.",
          error,
        );
      });
      if (contents.trim() !== "")
        throw sourceAccessError(
          "The approved checkout uses an external Git object store.",
        );
    }
  }

  private async rawGitOutput(
    args: readonly string[],
    maxBuffer: number,
    acceptedExitCodes: readonly number[] = [],
    trimFinalNewline = true,
  ): Promise<string> {
    this.signal?.throwIfAborted();
    try {
      const result = await execFile(
        this.git,
        [
          "--no-pager",
          "-c",
          `core.attributesFile=${devNull}`,
          "-c",
          "core.fsmonitor=false",
          "-c",
          "core.hooksPath=",
          "-c",
          "diff.external=",
          "-c",
          "diff.trustExitCode=false",
          "-C",
          this.checkout,
          ...args,
        ],
        {
          encoding: "utf8",
          env: this.environment,
          maxBuffer,
          signal: this.signal,
          timeout: GIT_TIMEOUT_MS,
          windowsHide: true,
        },
      );
      return trimFinalNewline
        ? result.stdout.replace(/\r?\n$/u, "")
        : result.stdout;
    } catch (error) {
      const code = exitCode(error);
      if (typeof code === "number" && acceptedExitCodes.includes(code)) {
        const stdout =
          error !== null && typeof error === "object" && "stdout" in error
            ? String((error as { stdout?: unknown }).stdout ?? "")
            : "";
        return trimFinalNewline ? stdout.replace(/\r?\n$/u, "") : stdout;
      }
      throw error;
    }
  }
}
