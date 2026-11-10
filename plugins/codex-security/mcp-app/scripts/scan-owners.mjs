// Generated from the SDK owner verifier. Run pnpm build in sdk/typescript.
// scripts/plugin-scan-owners.mts
import { readFileSync } from "node:fs";
import { once } from "node:events";

// src/owner-evidence.ts
import { execFile as execFileCallback2 } from "node:child_process";
import {
  lstat as lstat2,
  readdir,
  realpath as realpath3,
} from "node:fs/promises";
import { join as join3, relative as relative3, sep as sep3 } from "node:path";
import { promisify as promisify2 } from "node:util";

// src/bedrock-oss-pricing.ts
function models(base20b, base120b, safeguard20b, safeguard120b) {
  return {
    "openai.gpt-oss-20b": base20b,
    "openai.gpt-oss-120b": base120b,
    "openai.gpt-oss-20b-1:0": base20b,
    "openai.gpt-oss-120b-1:0": base120b,
    "openai.gpt-oss-safeguard-20b": safeguard20b,
    "openai.gpt-oss-safeguard-120b": safeguard120b,
  };
}
var us = models([0.07, 0.3], [0.15, 0.6], [0.07, 0.2], [0.15, 0.6]);
var gov = models([0.084, 0.36], [0.18, 0.72]);
var tokyo = models([0.08, 0.36], [0.18, 0.73], [0.08, 0.24], [0.18, 0.73]);
var regions = {
  "us-east-1": us,
  "us-east-2": us,
  "us-west-2": us,
  "us-gov-east-1": gov,
  "us-gov-west-1": gov,
  "ap-northeast-1": tokyo,
  "ap-south-1": models([0.08, 0.35], [0.18, 0.71], [0.08, 0.24], [0.18, 0.71]),
  // The Standard table on AWS's pricing page explicitly lists Sydney, where
  // the bulk catalog only has Mantle SKUs.
  "ap-southeast-2": models(
    [0.0721, 0.309],
    [0.1545, 0.618],
    [0.0721, 0.206],
    [0.1545, 0.618],
  ),
  "ap-southeast-3": models(
    [0.07, 0.31],
    [0.16, 0.62],
    [0.084, 0.24],
    [0.18, 0.72],
  ),
  "eu-central-1": models([0.09, 0.4], [0.2, 0.79], [0.084, 0.24], [0.18, 0.72]),
  "eu-north-1": models([0.07, 0.3], [0.15, 0.6], [0.084, 0.24], [0.18, 0.72]),
  "eu-south-1": models([0.09, 0.4], [0.2, 0.79], [0.08, 0.23], [0.18, 0.7]),
  "eu-west-1": models([0.08, 0.35], [0.18, 0.7], [0.08, 0.23], [0.18, 0.7]),
  "eu-west-2": models([0.11, 0.47], [0.23, 0.93], [0.11, 0.31], [0.23, 0.93]),
  "sa-east-1": tokyo,
};

// src/bedrock-pricing.ts
var usEast = ["us-east-1", "us-east-2"];
var usMantle = [...usEast, "us-west-2"];
var usGeo = [...usMantle, "us-west-1", "ca-central-1", "ca-west-1"];
var gov2 = ["us-gov-east-1", "us-gov-west-1"];
var india = ["ap-south-1", "ap-south-2"];
var astraGlobal = [
  ...usGeo,
  "eu-central-1",
  "eu-north-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "sa-east-1",
];
var commonGlobal = [
  ...astraGlobal,
  "eu-central-2",
  "eu-south-1",
  "eu-south-2",
  "ap-east-2",
  "ap-south-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-6",
  "ap-southeast-7",
  "il-central-1",
  "af-south-1",
];
var gpt56Global = [...commonGlobal, "me-central-1", "me-south-1"];
var gpt6Global = [...commonGlobal, "mx-central-1"];
function offer(origins, short, long, source) {
  return { origins, short, long, source };
}
function card(slug, ...offers) {
  return {
    source: `https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-${slug}.html`,
    offers,
  };
}
var cards = {
  "openai.gpt-5.4": card(
    "54",
    offer(
      { regional: usMantle, us: usGeo },
      [2.75, 0.275, 2.75, 16.5],
      [5.5, 0.55, 5.5, 24.75],
    ),
    offer({ regional: ["us-gov-west-1"] }, [3.375, 0.3375, 3.375, 20.25]),
    offer(
      { regional: ["us-gov-east-1"] },
      [3.3, 0.33, 3.3, 19.8],
      void 0,
      "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/20261102165015/us-gov-east-1/index.json",
    ),
  ),
  "openai.gpt-5.5": card(
    "55",
    offer(
      { regional: usEast, us: usGeo },
      [5.5, 0.55, 5.5, 33],
      [11, 1.1, 11, 49.5],
    ),
  ),
  "openai.gpt-daybreak-blue-5.6-sol": card(
    "daybreak-blue-56-sol",
    offer(
      { regional: ["us-east-2"] },
      [4.4, 0.44, 5.5, 22],
      [8.8, 0.88, 11, 33],
    ),
  ),
  "openai.gpt-5.6-cyber": card(
    "56-cyber",
    offer({ regional: ["us-east-2"] }, [13.75, 1.375, 17.1875, 82.5]),
    offer({ regional: ["us-gov-east-1"] }, [16.875, 1.6875, 21.09375, 101.25]),
  ),
  "openai.gpt-5.6-luna": card(
    "56-luna",
    offer(
      { regional: usMantle, us: usGeo, in: india },
      [0.22, 0.022, 0.275, 1.32],
      [0.44, 0.044, 0.55, 1.98],
    ),
    offer(
      { global: gpt56Global },
      [0.2, 0.02, 0.25, 1.2],
      [0.4, 0.04, 0.5, 1.8],
    ),
    offer(
      { regional: gov2, "us-gov": gov2 },
      [0.27, 0.027, 0.3375, 1.62],
      [0.54, 0.054, 0.675, 2.43],
    ),
  ),
  "openai.gpt-5.6-terra": card(
    "56-terra",
    offer(
      { regional: usMantle, us: usGeo, in: india },
      [2.2, 0.22, 2.75, 13.2],
      [4.4, 0.44, 5.5, 19.8],
    ),
    offer({ global: gpt56Global }, [2, 0.2, 2.5, 12], [4, 0.4, 5, 18]),
    offer(
      { regional: gov2, "us-gov": gov2 },
      [2.7, 0.27, 3.375, 16.2],
      [5.4, 0.54, 6.75, 24.3],
    ),
  ),
  "openai.gpt-5.6-sol": card(
    "56-sol",
    offer(
      { regional: usEast, us: usGeo },
      [4.4, 0.44, 5.5, 22],
      [8.8, 0.88, 11, 33],
    ),
    offer({ global: gpt56Global }, [4, 0.4, 5, 20], [8, 0.8, 10, 30]),
  ),
  "openai.gpt-6-astra": card(
    "6-astra",
    offer(
      { regional: ["us-east-1", "us-west-2"], us: usGeo },
      [11, 1.1, 13.75, 55],
      [22, 2.2, 27.5, 82.5],
    ),
    offer({ global: astraGlobal }, [10, 1, 12.5, 50], [20, 2, 25, 75]),
  ),
  "openai.gpt-6-luna": card(
    "6-luna",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [0.11, 0.011, 0.1375, 0.55],
      [0.22, 0.022, 0.275, 0.825],
    ),
    offer(
      { global: gpt6Global },
      [0.1, 0.01, 0.125, 0.5],
      [0.2, 0.02, 0.25, 0.75],
    ),
  ),
  "openai.gpt-6-sol": card(
    "6-sol",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [2.2, 0.22, 2.75, 11],
      [4.4, 0.44, 5.5, 16.5],
    ),
    offer({ global: gpt6Global }, [2, 0.2, 2.5, 10], [4, 0.4, 5, 15]),
  ),
  "openai.gpt-6.1-sol": card(
    "6-1-sol",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [2.2, 0.11, 2.75, 11],
      [4.4, 0.22, 5.5, 16.5],
    ),
    offer({ global: gpt6Global }, [2, 0.1, 2.5, 10], [4, 0.2, 5, 15]),
  ),
  "openai.gpt-6.1-terra": card(
    "6-1-terra",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [1.1, 0.055, 1.375, 5.5],
      [2.2, 0.11, 2.75, 8.25],
    ),
    offer({ global: gpt6Global }, [1, 0.05, 1.25, 5], [2, 0.1, 2.5, 7.5]),
  ),
};

// src/cost-model.ts
function directRate(
  asOf,
  short,
  long,
  source = "https://developers.openai.com/api/docs/pricing",
) {
  return { short, long, unitsPerUsd: 1e9, source, asOf };
}
var gpt55 = directRate(
  "2026-09-14",
  [5e3, 500, 5e3, 3e4],
  [1e4, 1e3, 1e4, 45e3],
  "https://developers.openai.com/api/docs/models/gpt-5.5",
);
var gpt56Sol = directRate(
  "2026-09-14",
  [4e3, 400, 5e3, 2e4],
  [8e3, 800, 1e4, 3e4],
);
var directPricing = {
  "gpt-5.5": gpt55,
  "gpt-5.5-2026-04-23": gpt55,
  "gpt-6-sol": directRate(
    "2026-10-10",
    [2e3, 200, 2500, 1e4],
    [4e3, 400, 5e3, 15e3],
    "https://developers.openai.com/api/docs/models/gpt-6-sol",
  ),
  "gpt-6.1-sol": directRate(
    "2026-09-30",
    [2e3, 100, 2500, 1e4],
    [4e3, 200, 5e3, 15e3],
  ),
  "gpt-6-astra": directRate(
    "2026-09-14",
    [1e4, 1e3, 12500, 5e4],
    [2e4, 2e3, 25e3, 75e3],
  ),
  "gpt-6-luna": directRate(
    "2026-09-30",
    [100, 10, 125, 500],
    [200, 20, 250, 750],
  ),
  "gpt-5.6": gpt56Sol,
  "gpt-5.6-sol": gpt56Sol,
  "gpt-5.6-terra": directRate(
    "2026-09-14",
    [2e3, 200, 2500, 12e3],
    [4e3, 400, 5e3, 18e3],
  ),
  "gpt-5.6-luna": directRate(
    "2026-09-14",
    [200, 20, 250, 1200],
    [400, 40, 500, 1800],
  ),
  "gpt-5.6-cyber": directRate("2026-10-06", [12500, 1250, 15625, 75e3]),
  "gpt-6-cyber": directRate("2026-11-05", [2e4, 2e3, 25e3, 1e5]),
};

// src/errors.ts
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
function abortReason(signal2) {
  return (
    signal2.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}
var CodexSecurityError = class extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
};
var InvalidTargetError = class extends CodexSecurityError {};

// src/targets.ts
import { isUtf8 } from "node:buffer";
import { execFile as execFileCallback } from "node:child_process";
import { realpathSync } from "node:fs";
import {
  copyFile,
  lstat,
  mkdtemp,
  readFile,
  realpath as realpath2,
  rm,
  stat as stat2,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
  basename as basename2,
  dirname as dirname2,
  isAbsolute as isAbsolute2,
  join as join2,
  relative as relative2,
  resolve as resolve2,
  sep as sep2,
} from "node:path";
import { promisify } from "node:util";

// src/trusted-executable.ts
import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import {
  basename,
  delimiter,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
async function resolveTrustedExecutable(candidate, environment, protectedRoot) {
  const inspected = await inspectTrustedExecutable(
    candidate,
    environment,
    protectedRoot,
  );
  return inspected.executable === null
    ? null
    : { executable: inspected.executable, environment: inspected.environment };
}
async function inspectTrustedExecutable(candidate, environment, protectedRoot) {
  const roots = await Promise.all(
    (typeof protectedRoot === "string" ? [protectedRoot] : protectedRoot).map(
      (root) => realpath(root).catch(() => resolve(root)),
    ),
  );
  const isProtected = (path2) => roots.some((root) => isWithin(root, path2));
  const path =
    environment["PATH"] ??
    Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH",
    )?.[1];
  const entries = [];
  for (let entry of path?.split(delimiter) ?? []) {
    if (
      process.platform === "win32" &&
      entry.startsWith('"') &&
      entry.endsWith('"')
    ) {
      entry = entry.slice(1, -1);
    }
    if (entry.length === 0) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isProtected(canonical)) continue;
    if (!entries.includes(canonical)) entries.push(canonical);
  }
  const pathLike = candidate.includes("/") || candidate.includes("\\");
  const extensions =
    process.platform === "win32"
      ? /\.(?:exe|com)$/iu.test(candidate)
        ? [{ suffix: "", runnable: true }]
        : pathLike
          ? extname(candidate) === ""
            ? [{ suffix: ".exe", runnable: true }]
            : [{ suffix: "", runnable: false }]
          : [
              { suffix: ".exe", runnable: true },
              { suffix: ".com", runnable: true },
              { suffix: ".bat", runnable: false },
              { suffix: ".cmd", runnable: false },
              { suffix: "", runnable: false },
            ]
      : [{ suffix: "", runnable: true }];
  const candidates = pathLike
    ? extensions.map((extension) => ({
        entry: null,
        path:
          process.platform === "win32"
            ? resolve(`${candidate}${extension.suffix}`)
            : candidate,
        runnable: extension.runnable,
      }))
    : entries.flatMap((entry) =>
        extensions.map((extension) => ({
          entry,
          path: join(entry, `${candidate}${extension.suffix}`),
          runnable: extension.runnable,
        })),
      );
  const unsafeEntries = /* @__PURE__ */ new Set();
  let executable = null;
  for (const current of candidates) {
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) continue;
    if (isProtected(canonical)) {
      if (current.entry !== null) unsafeEntries.add(current.entry);
      continue;
    }
    if (process.platform === "win32" && /\.(?:bat|cmd)$/iu.test(canonical)) {
      continue;
    }
    if (!current.runnable) continue;
    try {
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      if (!(await stat(canonical)).isFile()) continue;
      const invocationPath = pathLike
        ? join(await realpath(dirname(current.path)), basename(current.path))
        : current.path;
      executable ??=
        pathLike && (isProtected(current.path) || isProtected(invocationPath))
          ? canonical
          : invocationPath;
    } catch {
      continue;
    }
  }
  const sanitizedEnvironment = { ...environment };
  for (const name of Object.keys(sanitizedEnvironment)) {
    if (name.toUpperCase() === "PATH") delete sanitizedEnvironment[name];
  }
  sanitizedEnvironment["PATH"] = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
  return { executable, environment: sanitizedEnvironment };
}
function isWithin(root, candidate) {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}

// src/windows-path.ts
import { parse, toNamespacedPath } from "node:path";
var SQLITE_WINDOWS_MAX_FILENAME_BYTES = 260 * 4 - 8;
var UNSAFE_COMPONENT = /[<>:"|?*\u0000-\u001f]|[ .]$/u;
var RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/iu;
function isWindowsUnsafePathComponent(value) {
  return (
    value !== "" &&
    value !== "." &&
    (UNSAFE_COMPONENT.test(value) || RESERVED_COMPONENT.test(value))
  );
}
function windowsUnsafePathComponent(path) {
  return path
    .slice(parse(path).root.length)
    .split(/[\\/]/u)
    .find(isWindowsUnsafePathComponent);
}

// src/targets.ts
var execFile = promisify(execFileCallback);
var UNSUPPORTED_GIT_ENVIRONMENT = /* @__PURE__ */ new Set([
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_REPLACE_REF_BASE",
]);
var GIT_REPOSITORY_ENVIRONMENT = /* @__PURE__ */ new Set([
  ...UNSUPPORTED_GIT_ENVIRONMENT,
  "GIT_CEILING_DIRECTORIES",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_GRAFT_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_NAMESPACE",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_PREFIX",
  "GIT_SHALLOW_FILE",
]);
async function normalizeRepository(repository2, signal2) {
  const candidate = resolveRepositoryPath(repository2);
  requirePortableWindowsRepositoryPath(candidate);
  let resolved;
  try {
    resolved = await abortable(
      () => realpath2(candidate, { encoding: "buffer" }),
      signal2,
    );
    if (!(await abortable(() => lstat(resolved), signal2)).isDirectory()) {
      throw new Error("not a directory");
    }
  } catch (error) {
    throwIfAborted(signal2);
    throw new InvalidTargetError(
      `Repository is not a directory: ${candidate}`,
      {
        cause: error,
      },
    );
  }
  requireUtf8Path("Repository path", candidate, resolved);
  const canonical = resolved.toString();
  requirePortableWindowsRepositoryPath(canonical);
  return canonical;
}
function resolveRepositoryPath(repository2) {
  requireUtf8Path("Repository path", repository2);
  return resolve2(expandHome(repository2));
}
function requireUtf8Path(label, value, resolved) {
  if (resolved === void 0 ? !value.isWellFormed() : !isUtf8(resolved)) {
    throw new InvalidTargetError(
      `${label} cannot be represented as UTF-8: ${value}`,
    );
  }
}
function requirePortableWindowsRepositoryPath(path) {
  if (process.platform !== "win32") return;
  const ambiguous = windowsUnsafePathComponent(path);
  if (ambiguous !== void 0) {
    throw new InvalidTargetError(
      `Repository paths must not contain Windows-ambiguous components: ${ambiguous}`,
    );
  }
}
async function enclosingGitWorktreeRoot(repository2, signal2, options = {}) {
  const strict = options.requireIfPresent === true;
  const readGit = options.readGit ?? gitOutput;
  const markerRoot = strict
    ? await gitMarkerRoot(repository2, signal2, "nearest")
    : null;
  let canonicalRoot;
  try {
    if (strict) {
      if (
        (await readGit(
          repository2,
          ["rev-parse", "--is-inside-git-dir"],
          signal2,
        )) === "true"
      ) {
        throw new InvalidTargetError(
          "The selected path is inside Git metadata. Select a worktree directory instead.",
        );
      }
      if (markerRoot === null) return null;
    }
    const root = await readGit(
      repository2,
      ["rev-parse", "--show-toplevel"],
      signal2,
    );
    canonicalRoot = await abortable(() => realpath2(root), signal2);
  } catch (error) {
    throwIfAborted(signal2);
    if (strict && error instanceof InvalidTargetError) throw error;
    if (markerRoot !== null) {
      throw new InvalidTargetError(
        `Could not determine the Git worktree root. Check that Git is installed and the checkout is accessible. ${errorMessage(error)}`,
        { cause: error },
      );
    }
    return null;
  }
  if (
    markerRoot !== null &&
    relative2(
      await abortable(() => realpath2(markerRoot), signal2),
      canonicalRoot,
    ) !== ""
  ) {
    throw new InvalidTargetError(
      "Git's worktree root does not match the selected checkout's .git marker. Select the intended checkout explicitly or fix its Git configuration.",
    );
  }
  if (markerRoot !== null)
    await requireGitWorktreeBinding(canonicalRoot, signal2, readGit);
  return canonicalRoot;
}
async function gitMetadataDirectories(repository2, signal2, options = {}) {
  const readGit = options.readGit ?? gitOutput;
  const [directory, commonDirectory] = await Promise.all([
    readGit(repository2, ["rev-parse", "--absolute-git-dir"], signal2),
    readGit(repository2, ["rev-parse", "--git-common-dir"], signal2),
  ]);
  const roots = await Promise.all([
    abortable(() => realpath2(resolve2(repository2, directory)), signal2),
    abortable(() => realpath2(resolve2(repository2, commonDirectory)), signal2),
  ]);
  return [...roots, ...(await gitObjectDirectories(roots, signal2, options))];
}
function gitAlternatePaths(contents) {
  const text2 = contents.toString("latin1").split("\0", 1)[0];
  const paths = [];
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  for (let offset = 0; offset < text2.length;) {
    const newline = text2.indexOf("\n", offset);
    let end = newline === -1 ? text2.length : newline;
    let path = text2.slice(offset, end);
    if (path.startsWith("#")) path = "";
    const quoted = /^"(?:[^"\\]|\\[\s\S])*"/u.exec(text2.slice(offset))?.[0];
    if (quoted !== void 0) {
      try {
        path = JSON.parse(
          quoted.replace(
            /\\(?:[0-3][0-7]{2}|[\s\S])|[\u0000-\u001f]/gu,
            (escape) => {
              if (/^\\[btnfr\\"]$/u.test(escape)) return escape;
              const byte =
                escape[0] !== "\\"
                  ? escape.charCodeAt(0)
                  : escape === "\\a"
                    ? 7
                    : escape === "\\v"
                      ? 11
                      : /^\\[0-3][0-7]{2}$/u.test(escape)
                        ? Number.parseInt(escape.slice(1), 8)
                        : void 0;
              if (byte === void 0)
                throw new SyntaxError("Invalid Git path escape.");
              return `\\u${byte.toString(16).padStart(4, "0")}`;
            },
          ),
        );
        end = offset + quoted.length;
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
      }
    }
    if (path !== "") {
      try {
        paths.push(utf8.decode(Buffer.from(path, "latin1")));
      } catch (error) {
        throw new InvalidTargetError("Git object-store paths must use UTF-8.", {
          cause: error,
        });
      }
    }
    offset = end + 1;
  }
  return paths;
}
async function gitObjectDirectories(
  metadataDirectories,
  signal2,
  options = {},
) {
  const pending = metadataDirectories.map((path) => join2(path, "objects"));
  const visited = /* @__PURE__ */ new Set();
  const canonical = (path) => {
    try {
      return realpathSync.native(path);
    } catch (error) {
      if (["ENOENT", "ENOTDIR"].includes(error.code ?? "")) return null;
      throw error;
    }
  };
  while (pending.length > 0) {
    throwIfAborted(signal2);
    const directory = canonical(pending.pop());
    if (directory === null || visited.has(directory)) continue;
    if (!(await stat2(directory)).isDirectory()) continue;
    visited.add(directory);
    const contents = await readFile(join2(directory, "info", "alternates"), {
      signal: signal2,
    }).catch(nullIfMissingPath);
    if (contents === null) continue;
    for (const path of gitAlternatePaths(contents)) {
      throwIfAborted(signal2);
      pending.push(resolve2(directory, path));
    }
  }
  return [...visited].filter(
    (path) =>
      options.includeLocalObjects ||
      metadataDirectories.every((root) =>
        relativePathIsOutside(relative2(root, path)),
      ),
  );
}
async function requireGitWorktreeBinding(repository2, signal2, readGit) {
  let cause;
  try {
    const [directory, commonDirectory] = await gitMetadataDirectories(
      repository2,
      signal2,
      { readGit },
    );
    if (
      [directory, commonDirectory].every(
        (path) => !relativePathIsOutside(relative2(repository2, path)),
      )
    )
      return;
    if (relative2(directory, commonDirectory) === "") {
      if (
        await readGit(
          repository2,
          ["config", "--get", "core.worktree"],
          signal2,
        )
      )
        return;
    } else {
      const worktreesDirectory = await abortable(
        () => realpath2(join2(commonDirectory, "worktrees")),
        signal2,
      );
      if (relative2(worktreesDirectory, dirname2(directory)) === "") {
        const contents = await abortable(
          () => readFile(join2(directory, "gitdir"), "utf8"),
          signal2,
        );
        const backlink = resolve2(directory, contents.trimEnd());
        if (
          basename2(backlink) === ".git" &&
          relative2(
            repository2,
            await abortable(() => realpath2(dirname2(backlink)), signal2),
          ) === ""
        )
          return;
      }
    }
  } catch (error) {
    throwIfAborted(signal2);
    cause = error;
  }
  throw new InvalidTargetError(
    "Git metadata is not bound to the selected checkout. Select the intended checkout, repair a moved worktree with git worktree repair, or set core.worktree for a separate Git directory you own.",
    { cause },
  );
}
function relativePathIsOutside(path) {
  return path === ".." || path.startsWith(`..${sep2}`) || isAbsolute2(path);
}
function validatedGitEnvironment(environment = process.env) {
  const unsupported = Object.entries(environment).find(
    ([name, value]) =>
      UNSUPPORTED_GIT_ENVIRONMENT.has(name.toUpperCase()) &&
      value !== void 0 &&
      value.trim() !== "",
  );
  if (unsupported !== void 0) {
    throw new InvalidTargetError(
      `${unsupported[0]} is not supported for Codex Security scans.`,
    );
  }
}
async function repositoryRevision(repository2, signal2) {
  try {
    return await gitOutput(
      repository2,
      ["rev-parse", "--verify", "HEAD^{commit}"],
      signal2,
    );
  } catch {
    throwIfAborted(signal2);
    return null;
  }
}
async function trustedGitCommand(
  repository2,
  preserveConfiguration,
  sourceEnvironment,
  protectedRoots,
  signal2,
) {
  const command = await resolveTrustedExecutable(
    "git",
    isolatedGitEnvironment(preserveConfiguration, sourceEnvironment),
    [
      (await gitMarkerRoot(repository2, signal2, "outermost")) ?? repository2,
      ...(typeof protectedRoots === "string"
        ? [protectedRoots]
        : protectedRoots),
    ],
  );
  if (!command) throw new Error("Git is not available on a trusted PATH.");
  return command;
}
async function gitOutput(
  repository2,
  args,
  signal2,
  environment = {},
  workingDirectory = repository2,
  encoding = "utf8",
  protectedRoots = [],
  sourceEnvironment = process.env,
) {
  throwIfAborted(signal2);
  const command = await trustedGitCommand(
    repository2,
    args[0] === "rev-parse" ||
      (args[0] === "symbolic-ref" &&
        args[1] === "--quiet" &&
        args[2] === "HEAD" &&
        args.length === 3) ||
      (args[0] === "--exec-path" && args.length === 1) ||
      args[0] === "config" ||
      (args[0] === "fetch-pack" &&
        args[1] === "--diag-url" &&
        args.length === 3) ||
      (args[0] === "ls-remote" &&
        args[1] === "--get-url" &&
        (args.length === 2 || (args[2] === "--" && args.length === 4))) ||
      args[0] === "ls-files" ||
      (args[0] === "remote" &&
        (args.length === 1 ||
          (args[1] === "get-url" &&
            (args[2] === "--all" || args[2] === "--")))),
    sourceEnvironment,
    protectedRoots,
    signal2,
  );
  throwIfAborted(signal2);
  const { stdout } = await execFile(
    command.executable,
    ["-c", "core.fsmonitor=false", "-C", workingDirectory, ...args],
    {
      encoding,
      signal: signal2,
      env: { ...command.environment, ...environment },
      maxBuffer: Infinity,
    },
  );
  if (typeof stdout !== "string") return stdout;
  const remoteUrl = args[0] === "remote" && args[1] === "get-url";
  return stdout.replace(
    process.platform === "win32" && !remoteUrl ? /\r?\n$/u : /\n$/u,
    "",
  );
}
async function gitMarkerRoot(repository2, signal2, search) {
  let candidate = resolve2(repository2);
  let current;
  while (true) {
    try {
      const canonical = await abortable(() => realpath2(candidate), signal2);
      current = (await lstat(canonical)).isDirectory()
        ? canonical
        : dirname2(canonical);
      break;
    } catch (error) {
      throwIfAborted(signal2);
      const code = error.code;
      if (
        search !== "outermost" ||
        !["ENOENT", "ENOTDIR", "EACCES", "EPERM"].includes(code ?? "")
      )
        throw error;
      const parent = dirname2(candidate);
      if (parent === candidate) throw error;
      candidate = parent;
    }
  }
  return await walkGitMarkers(current, signal2, search);
}
async function walkGitMarkers(current, signal2, search) {
  let root = null;
  while (true) {
    throwIfAborted(signal2);
    try {
      await lstat(join2(current, ".git"));
      if (search === "nearest") return current;
      root = current;
    } catch (error) {
      throwIfAborted(signal2);
      const code = error.code;
      if (
        code !== "ENOENT" &&
        code !== "ENOTDIR" &&
        (search !== "outermost" || (code !== "EACCES" && code !== "EPERM"))
      )
        throw error;
    }
    const parent = dirname2(current);
    if (parent === current) return root;
    current = parent;
  }
}
function isolatedGitEnvironment(
  preserveGitConfiguration,
  source = process.env,
) {
  const environment = { ...source };
  for (const name of Object.keys(environment)) {
    const normalized = name.toUpperCase();
    if (
      GIT_REPOSITORY_ENVIRONMENT.has(normalized) ||
      normalized === "GIT_ALLOW_PROTOCOL" ||
      (!preserveGitConfiguration && normalized.startsWith("GIT_"))
    ) {
      delete environment[name];
    }
  }
  environment["GIT_ALLOW_PROTOCOL"] = "";
  return environment;
}
async function abortable(operation, signal2) {
  if (signal2 === void 0) return await operation();
  throwIfAborted(signal2);
  return await new Promise((resolvePromise, reject) => {
    const onAbort = () => reject(abortReason(signal2));
    signal2.addEventListener("abort", onAbort, { once: true });
    const finish = (settle) => (value) => {
      signal2.removeEventListener("abort", onAbort);
      settle(value);
    };
    void Promise.resolve()
      .then(() => {
        throwIfAborted(signal2);
        return operation();
      })
      .then(finish(resolvePromise), finish(reject));
  });
}
function throwIfAborted(signal2) {
  if (signal2?.aborted === true) throw abortReason(signal2);
}
function expandHome(value) {
  if (value === "~") {
    return homedir();
  }
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    const separators =
      sep2 === "/" && value.startsWith("~/") ? /^\/+/ : /^[/\\]+/;
    return resolve2(homedir(), value.slice(2).replace(separators, ""));
  }
  return value;
}
function nullIfMissingFile(error) {
  if (error.code === "ENOENT") return null;
  throw error;
}
function nullIfMissingPath(error) {
  if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
  throw error;
}

// src/codeowners.ts
function parseCodeowners(source) {
  const rules = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    const value = line.trimStart();
    if (!value || value.startsWith("#")) continue;
    const token = /^(?:\\.|[^\s])+/u.exec(value)[0];
    const matches = codeownersPattern(token);
    if (matches === null) continue;
    const handles = value
      .slice(token.length)
      .split("#", 1)[0]
      .trim()
      .split(/\s+/u)
      .filter(Boolean);
    const owners = [];
    let valid = true;
    for (const handle of handles) {
      if (/^@[a-z\d](?:[a-z\d_-]*[a-z\d])?(?:\/[a-z\d_.-]+)?$/i.test(handle)) {
        owners.push(
          handle.includes("/")
            ? { kind: "group", provider: "github", handle: handle.slice(1) }
            : { kind: "person", provider: "github", handle: handle.slice(1) },
        );
      } else if (/^[^@\s]+@[^@\s]+$/u.test(handle)) {
        owners.push({ kind: "person", email: handle });
      } else {
        valid = false;
        break;
      }
    }
    if (valid)
      rules.push({
        pattern: token,
        line: index + 1,
        rule: line,
        owners,
        matches,
      });
  }
  return rules;
}
function codeownersPattern(pattern) {
  if (pattern.startsWith("!") || pattern.startsWith("\\#")) return null;
  const anchored = pattern.startsWith("/");
  if (anchored) pattern = pattern.slice(1);
  const directory = pattern.endsWith("/");
  if (directory) pattern = pattern.slice(0, -1);
  const rooted = anchored || pattern.includes("/");
  const immediate = /(?:^|\/)[*?]$/u.test(pattern);
  const characters = Array.from(pattern);
  const tokens = [];
  for (let index = 0; index < characters.length; index++) {
    const character = characters[index];
    if (character === "\\" && index + 1 < characters.length) {
      tokens.push({ literal: characters[++index] });
    } else if (
      character === "[" ||
      character === "]" ||
      (character === "*" &&
        characters[index + 1] === "*" &&
        characters[index + 2] === "*")
    ) {
      return null;
    } else if (
      character === "*" &&
      characters[index + 1] === "*" &&
      (index === 0 || characters[index - 1] === "/") &&
      (index + 2 === characters.length || characters[index + 2] === "/")
    ) {
      if (characters[index + 2] === "/") {
        tokens.push("**/");
        index += 2;
      } else {
        tokens.push("**");
        index++;
      }
    } else if (character === "*" || character === "?") tokens.push(character);
    else tokens.push({ literal: character });
  }
  return (path) => {
    let active = /* @__PURE__ */ new Set([0]);
    let next = /* @__PURE__ */ new Set();
    for (let offset = 0; ;) {
      const boundary = offset === 0 || path[offset - 1] === "/";
      if (!rooted && boundary) active.add(0);
      for (const index of active) {
        const token = tokens[index];
        if (token === "*" || token === "**" || (token === "**/" && boundary))
          active.add(index + 1);
      }
      const end = offset === path.length;
      if (
        active.has(tokens.length) &&
        (directory
          ? path[offset] === "/"
          : end || (!immediate && path[offset] === "/"))
      )
        return true;
      if (end) return false;
      const character = String.fromCodePoint(path.codePointAt(offset));
      next.clear();
      for (const index of active) {
        const token = tokens[index];
        if (token === void 0) continue;
        if (typeof token === "object") {
          if (token.literal === character) next.add(index + 1);
        } else if (token === "?") {
          if (character !== "/") next.add(index + 1);
        } else if (token !== "*" || character !== "/") next.add(index);
      }
      if (rooted && next.size === 0) return false;
      [active, next] = [next, active];
      offset += character.length;
    }
  };
}
function codeownersForPath(rules, path) {
  return rules.findLast(({ matches }) => matches(path));
}

// src/owner-evidence.ts
var execFile2 = promisify2(execFileCallback2);
async function findingsAtScanRevision(
  repository2,
  revision2,
  findings2,
  signal2,
) {
  if ((await repositoryRevision(repository2, signal2)) !== revision2)
    throw new Error(
      "Owner checkout does not match the completed scan revision.",
    );
  const scanRoot = await normalizeRepository(repository2, signal2);
  const gitRoot =
    (await enclosingGitWorktreeRoot(scanRoot, signal2, {
      requireIfPresent: true,
    })) ?? scanRoot;
  const prefix = relative3(gitRoot, scanRoot).split(sep3).join("/");
  return findings2.map((finding) => ({
    ...finding,
    sourceRevision: revision2,
    locations: finding.locations.map((location) => ({
      ...location,
      path: prefix ? `${prefix}/${location.path}` : location.path,
    })),
  }));
}
async function ownerRepository(repository2, environment, signal2) {
  repository2 = await normalizeRepository(repository2, signal2);
  validatedGitEnvironment(environment);
  repository2 =
    (await enclosingGitWorktreeRoot(repository2, signal2, {
      requireIfPresent: true,
    })) ?? repository2;
  const executable = await resolveTrustedExecutable(
    "git",
    environment,
    repository2,
  );
  if (executable === null)
    throw new CodexSecurityError("Git is required to suggest owners.");
  const run = async (cwd, args, encoding) => {
    signal2?.throwIfAborted();
    const { stdout } = await execFile2(executable.executable, args, {
      cwd,
      env: { ...executable.environment, GIT_NO_LAZY_FETCH: "1" },
      signal: signal2,
      maxBuffer: Infinity,
      encoding: "buffer",
    });
    return stdout.toString(encoding);
  };
  const [gitDirectory, commonDirectory, ...objectDirectories] =
    await gitMetadataDirectories(repository2, signal2, {
      includeLocalObjects: true,
    });
  const metadataDirectories = [
    .../* @__PURE__ */ new Set([gitDirectory, commonDirectory]),
  ];
  if (
    objectDirectories.some((path) =>
      metadataDirectories.every((root) =>
        relativePathIsOutside(relative3(root, path)),
      ),
    )
  ) {
    throw new InvalidTargetError(
      "Git objects are not bound to the selected checkout. Use a checkout that does not borrow external object stores.",
    );
  }
  await requireBoundMetadata(metadataDirectories, objectDirectories, signal2);
  const gitOutput2 = (encoding, ...args) =>
    run(
      gitDirectory,
      [
        `--git-dir=${gitDirectory}`,
        "--literal-pathspecs",
        "-c",
        "core.bare=true",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        ...args,
      ],
      encoding,
    );
  const git2 = (...args) => gitOutput2("utf8", ...args);
  const revision2 = (
    await git2("rev-parse", "--verify", "HEAD^{commit}")
  ).trim();
  const files = new Set(
    (
      await gitOutput2(
        "latin1",
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        revision2,
      )
    )
      .split("\0")
      .filter((record) => /^100(?:644|755) blob /u.test(record))
      .map((record) => record.slice(record.indexOf("	") + 1)),
  );
  const shallow =
    (await git2("rev-parse", "--is-shallow-repository")).trim() === "true";
  const hasFile = (path) =>
    path.isWellFormed() && files.has(Buffer.from(path).toString("latin1"));
  const loadCodeowners = async () => {
    const path = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"].find(
      hasFile,
    );
    if (path === void 0) return null;
    const source = await git2("cat-file", "blob", `${revision2}:${path}`);
    return {
      path,
      rules: Buffer.byteLength(source) >= 3e6 ? null : parseCodeowners(source),
    };
  };
  let codeowners;
  const fileHistories = /* @__PURE__ */ new Map();
  async function recentFileHistory(path) {
    let history = fileHistories.get(path);
    if (!history) {
      history = (
        await git2(
          "log",
          "-100",
          "--no-merges",
          "--no-use-mailmap",
          "--no-show-signature",
          "--no-notes",
          "-z",
          "--format=%H%x00%an%x00%ae%x00%ct",
          revision2,
          "--",
          path,
        )
      ).split("\0");
      fileHistories.set(path, history);
    }
    return history;
  }
  return {
    git: git2,
    revision: revision2,
    hasFile,
    recentFileHistory,
    shallow,
    // Keep the load lazy so failures remain inside per-finding error handling.
    codeowners: () => (codeowners ??= loadCodeowners()),
  };
}
async function requireBoundMetadata(
  metadataDirectories,
  objectDirectories,
  signal2,
) {
  const pending = [
    ...objectDirectories,
    ...metadataDirectories.flatMap((directory) =>
      ["HEAD", "refs", "packed-refs", "reftable"].map((name) =>
        join3(directory, name),
      ),
    ),
  ];
  const visited = /* @__PURE__ */ new Set();
  while (pending.length > 0) {
    signal2?.throwIfAborted();
    const path = pending.pop();
    if (visited.has(path)) continue;
    visited.add(path);
    const entry = await lstat2(path).catch(nullIfMissingFile);
    if (entry?.isSymbolicLink()) {
      const destination = await realpath3(path);
      if (
        metadataDirectories.every((root) =>
          relativePathIsOutside(relative3(root, destination)),
        )
      ) {
        throw new InvalidTargetError(
          "Git metadata is not bound to the selected checkout. Select the intended checkout or repair its Git metadata.",
        );
      }
      pending.push(destination);
    } else if (entry?.isDirectory()) {
      for (const name of await readdir(path)) pending.push(join3(path, name));
    }
  }
}
async function collectOwnerEvidence(finding, repository2, policy) {
  const { revision: revision2, hasFile, shallow } = repository2;
  const context = {
    identities: [],
    evidence: [],
    declaredOwners: [],
    limitations: [
      "Git authors are not verified tracker accounts or proof of current employment.",
    ],
  };
  if (shallow)
    context.limitations.push(
      "This checkout has shallow history; earlier contributors may be missing.",
    );
  const stale =
    finding.sourceRevision !== void 0 && finding.sourceRevision !== revision2;
  if (stale)
    context.limitations.push(
      "The finding revision differs from HEAD; its line ranges were not used.",
    );
  if (finding.locations.length === 0)
    context.limitations.push("No source locations were supplied.");
  const codeowners = await repository2.codeowners();
  if (codeowners !== null) {
    if (codeowners.rules === null) {
      context.limitations.push(
        "CODEOWNERS meets or exceeds GitHub's 3 MB file-size limit and was ignored.",
      );
    } else {
      for (const path of new Set(
        finding.locations.map(({ path: path2 }) => path2),
      )) {
        if (!hasFile(path)) continue;
        const rule = codeownersForPath(codeowners.rules, path);
        if (rule === void 0) continue;
        if (rule.owners.length === 0) continue;
        const citation = addOwnerEvidence(context, {
          kind: "codeowners",
          path: codeowners.path,
          commit: revision2,
          startLine: rule.line,
          endLine: rule.line,
          rule: rule.rule,
          matchedPath: path,
          content: rule.rule,
          identityIndex: null,
        });
        for (const owner of rule.owners)
          context.declaredOwners.push({ owner, evidenceIds: [citation.id] });
      }
    }
  }
  if (context.declaredOwners.length > 0)
    context.limitations.push(
      "CODEOWNERS identities are declarations; their existence and repository access are not verified.",
    );
  if (policy === "standalone" && !context.declaredOwners.length)
    await collectGitOwnerEvidence(finding, repository2, context, stale, policy);
  return context;
}
function addOwnerEvidence(context, item) {
  const evidence = { id: `e${context.evidence.length + 1}`, ...item };
  context.evidence.push(evidence);
  return evidence;
}
async function collectGitOwnerEvidence(
  finding,
  repository2,
  context,
  stale,
  policy,
) {
  const { git: git2, revision: revision2, hasFile } = repository2;
  const identityIndex = (name, email) => {
    const index = context.identities.findIndex(
      (identity) => identity.email === email,
    );
    if (index !== -1) return index;
    return context.identities.push({ name, email }) - 1;
  };
  const add = (item) => addOwnerEvidence(context, item);
  for (const path of new Set(
    finding.locations.map(({ path: path2 }) => path2),
  )) {
    if (!hasFile(path)) {
      context.limitations.push(`Not a regular file at HEAD: ${path}`);
      continue;
    }
    const locations = stale
      ? [{ path }]
      : finding.locations.filter((location) => location.path === path);
    const lineLocations = locations.filter(
      (location) => location.startLine !== void 0,
    );
    if (policy === "scan" && !lineLocations.length) {
      const history2 = await repository2.recentFileHistory(path);
      for (let i = 0; i + 3 < history2.length; i += 4) {
        const [commit, name, email, timestamp] = history2.slice(i, i + 4);
        if (name && email.trim())
          add({
            kind: "history",
            path,
            commit,
            commitTime: Number(timestamp),
            content: "",
            identityIndex: identityIndex(name, email),
          });
      }
      continue;
    }
    const source = await git2("cat-file", "blob", `${revision2}:${path}`);
    if (!source || source.includes("\0")) {
      context.limitations.push(`Source is empty or binary: ${path}`);
      continue;
    }
    const lines = source.replace(/\n$/u, "").split("\n");
    for (const location of policy === "scan" ? lineLocations : locations) {
      const start = location.startLine ?? 1;
      if (policy === "scan" && (location.endLine ?? start) > lines.length)
        throw new CodexSecurityError(
          `Finding lines are outside the committed file: ${path}`,
        );
      if (start > lines.length) {
        context.limitations.push(
          `Finding line is outside the committed file: ${path}:${start}`,
        );
        continue;
      }
      const end = Math.min(
        location.endLine ?? location.startLine ?? lines.length,
        lines.length,
      );
      const excerptStart = Math.max(1, start - 10);
      const excerptEnd = Math.min(lines.length, end + 10);
      if (policy === "standalone")
        add({
          kind: "source",
          path,
          commit: revision2,
          startLine: excerptStart,
          endLine: excerptEnd,
          content: lines
            .slice(excerptStart - 1, excerptEnd)
            .map((line2, index) => `${excerptStart + index}: ${line2}`)
            .join("\n"),
          identityIndex: null,
        });
      const blame = await git2(
        "blame",
        "--line-porcelain",
        "--no-textconv",
        "--ignore-revs-file=",
        "-L",
        `${start},${end}`,
        revision2,
        "--",
        path,
      );
      let commit = "",
        name = "",
        email = "",
        line = 0,
        commitTime = 0;
      for (const value of blame.split("\n")) {
        const header = /^([a-f0-9]{40,64}) \d+ (\d+)(?: \d+)?$/u.exec(value);
        if (header) {
          commit = header[1];
          line = Number(header[2]);
        } else if (value.startsWith("author ")) name = value.slice(7);
        else if (value.startsWith("author-mail <")) email = value.slice(13, -1);
        else if (value.startsWith("committer-time "))
          commitTime = Number(value.slice(15));
        else if (value.startsWith("	") && email.trim()) {
          const index = identityIndex(name, email);
          const previous = context.evidence.at(-1);
          if (
            previous?.kind === "blame" &&
            previous.path === path &&
            previous.blameCommit === commit &&
            previous.identityIndex === index &&
            previous.endLine === line - 1
          ) {
            previous.endLine = line;
          } else {
            add({
              kind: "blame",
              path,
              commit: revision2,
              blameCommit: commit,
              ...(policy === "scan" && { commitTime }),
              startLine: line,
              endLine: line,
              content: `Authored in ${commit}.`,
              identityIndex: index,
            });
          }
        }
      }
    }
    if (policy === "scan") continue;
    const history = (
      await git2(
        "log",
        "--no-use-mailmap",
        "--no-show-signature",
        "--no-notes",
        "--no-decorate",
        "--format=%H%x00%an%x00%ae%x00%aI%x00%s",
        "-z",
        revision2,
        "--",
        path,
      )
    ).split("\0");
    for (let index = 0; index + 4 < history.length; index += 5) {
      const [commit, name, email, date, subject] = history.slice(
        index,
        index + 5,
      );
      if (email.trim())
        add({
          kind: "history",
          path,
          commit,
          content: `${date}: ${subject}`,
          identityIndex: identityIndex(name, email),
        });
    }
  }
}

// src/owner-report.ts
import { z } from "zod";
var text = z.string().refine((value) => value.trim().length > 0);
var locationSchema = z
  .object({
    path: text,
    startLine: z.number().int().positive().optional(),
    endLine: z.number().int().positive().optional(),
  })
  .refine(
    ({ startLine, endLine }) =>
      endLine === void 0 || (startLine !== void 0 && endLine >= startLine),
  );
var findingSchema = z.object({
  findingId: text,
  occurrenceId: text.optional(),
  title: text,
  summary: z.string(),
  remediation: z.string().optional(),
  sourceRevision: text.optional(),
  locations: z.array(locationSchema),
  extensions: z.record(z.string(), z.unknown()).optional(),
});
var decisionSchema = z.strictObject({
  suggestions: z.array(
    z.strictObject({
      identityIndex: z.number().int().nonnegative(),
      reason: text,
      evidenceIds: z.array(text),
    }),
  ),
  reason: text,
});
async function ownerResult(repository2, finding, signal2, policy) {
  signal2?.throwIfAborted();
  const result = {
    findingId: finding.findingId,
    occurrenceId: finding.occurrenceId ?? null,
    status: "abstained",
    suggestions: [],
    limitations: [],
    reason: "No source with observed contributors was available.",
  };
  try {
    const context = await collectOwnerEvidence(
      finding,
      repository2,
      policy.kind,
    );
    signal2?.throwIfAborted();
    result.limitations = context.limitations;
    if (context.declaredOwners.length) {
      for (const declared of context.declaredOwners)
        addSuggestion(result.suggestions, {
          owner: declared.owner,
          reason: "Declared owner of an affected file in CODEOWNERS.",
          evidence: publicEvidence(
            context.evidence.filter(({ id }) =>
              declared.evidenceIds.includes(id),
            ),
          ),
        });
    }
    if (policy.kind === "scan") {
      const stale =
        finding.sourceRevision !== void 0 &&
        finding.sourceRevision !== repository2.revision;
      await collectGitOwnerEvidence(
        finding,
        repository2,
        context,
        stale,
        "scan",
      );
      const latest = /* @__PURE__ */ new Map();
      const citedPaths = /* @__PURE__ */ new Set();
      for (const evidence of context.evidence) {
        if (evidence.identityIndex === null || evidence.commitTime === void 0)
          continue;
        const owner = context.identities[evidence.identityIndex];
        const email = owner.email.toLowerCase();
        const previous = latest.get(email);
        citedPaths.add(evidence.path);
        if (!previous || evidence.commitTime > previous.time)
          latest.set(email, { owner, evidence, time: evidence.commitTime });
      }
      if (finding.locations.every(({ path }) => citedPaths.has(path))) {
        const ranked = [...latest.entries()].sort(
          ([emailA, a], [emailB, b]) =>
            b.time - a.time || (emailA < emailB ? -1 : emailA > emailB ? 1 : 0),
        );
        for (const [, candidate] of ranked.slice(0, 3))
          addSuggestion(result.suggestions, {
            owner: candidate.owner,
            reason: "Recent author of the affected source in Git.",
            evidence: publicEvidence([candidate.evidence]),
          });
      } else {
        result.reason = "Git evidence was unavailable for an affected path.";
      }
    } else if (
      !result.suggestions.length &&
      context.identities.length &&
      context.evidence.some(({ kind }) => kind === "source")
    ) {
      const decision = decisionSchema.parse(
        await policy.decide(finding, context),
      );
      signal2?.throwIfAborted();
      const candidates = decision.suggestions.map((suggestion) => {
        const owner = context.identities[suggestion.identityIndex];
        const cited = [...new Set(suggestion.evidenceIds)].map((id) =>
          context.evidence.find((item) => item.id === id),
        );
        if (
          !owner ||
          !cited.every((item) => item !== void 0) ||
          !cited.some((item) => item.identityIndex === suggestion.identityIndex)
        )
          throw new CodexSecurityError(
            "The recommendation contains an unknown owner or unsupported citation.",
          );
        return {
          owner,
          reason: suggestion.reason,
          evidence: publicEvidence(cited),
        };
      });
      for (const candidate of candidates)
        addSuggestion(result.suggestions, candidate);
      result.reason = decision.reason;
    }
    if (result.suggestions.length) {
      result.status = "identified";
      result.reason = result.suggestions[0].reason;
    }
  } catch (error) {
    if (result.suggestions.length) {
      result.status = "identified";
      result.reason = result.suggestions[0].reason;
      const warning = `Git owner lookup failed: ${errorMessage(error)}`;
      result.limitations.push(warning);
      if (policy.kind === "scan") policy.onWarning?.(warning);
    } else {
      signal2?.throwIfAborted();
      result.status = "error";
      result.reason = errorMessage(error);
    }
  }
  return result;
}
function publicEvidence(evidence) {
  return evidence.map(
    ({
      content: _content,
      blameCommit: _blameCommit,
      commitTime: _commitTime,
      identityIndex: _index,
      ...citation
    }) => citation,
  );
}
function ownerKey(owner) {
  return "email" in owner
    ? `email:${owner.email.toLowerCase()}`
    : `github:${owner.handle.toLowerCase()}`;
}
function addSuggestion(suggestions, candidate) {
  const existing = suggestions.find(
    ({ owner }) => ownerKey(owner) === ownerKey(candidate.owner),
  );
  if (existing) {
    for (const citation of candidate.evidence)
      if (!existing.evidence.some(({ id }) => id === citation.id))
        existing.evidence.push(citation);
  } else suggestions.push(candidate);
}

// scripts/plugin-scan-owners.mts
var [, , repository, revision] = process.argv;
if (!repository || !revision)
  throw new Error("Expected a checkout and scan revision.");
var signal = AbortSignal.timeout(8e3);
var inputs = findingSchema.array().parse(JSON.parse(readFileSync(0, "utf8")));
var findings = await findingsAtScanRevision(
  repository,
  revision,
  inputs,
  signal,
);
var git = await ownerRepository(repository, process.env, signal);
if (git.revision !== revision)
  throw new Error("Owner checkout differs from the scan revision.");
for (const finding of findings) {
  let warning;
  const { findingId, occurrenceId, status, reason, suggestions } =
    await ownerResult(git, finding, signal, {
      kind: "scan",
      onWarning: (message) => {
        warning = message;
      },
    });
  if (
    !process.stdout.write(
      JSON.stringify({
        findingId,
        occurrenceId,
        status,
        reason,
        suggestions,
        warning,
      }) + "\n",
    )
  )
    await once(process.stdout, "drain", { signal });
}
