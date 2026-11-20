import { readdir } from "node:fs/promises";
import { userInfo } from "node:os";
import { basename, dirname, isAbsolute } from "node:path";
import { splitCommand } from "./command-words.js";
import { CodexSecurityError } from "./errors.js";

export function unsupportedSshInclude() {
  return new CodexSecurityError(
    "Cannot bind the SSH configuration Include for patch publication. Use a self-contained SSH config outside the checkout, or static include paths outside every writable root.",
  );
}

export function* sshConfigEntries(contents: string, strict = true) {
  for (const raw of contents.split("\n")) {
    const line = raw.split("\0", 1)[0]!.replace(/[ \t\r\f]+$/u, "");
    // OpenSSH's keyword reader accepts double quotes and an optional '='.
    // Detect unusual spellings too, then require unambiguous static syntax.
    const keyword =
      /^[\s=]*(identityfile2?|include|match|proxycommand|localcommand|knownhostscommand|pkcs11provider|smartcarddevice|securitykeyprovider|xauthlocation)/iu
        .exec(line.replaceAll('"', ""))?.[1]
        ?.toLowerCase();
    if (!keyword) continue;
    const directive =
      /^[ \t\r]*([a-z\d]+)(?:[ \t\r]*=[ \t\r]*|[ \t\r]+)(.*)$/isu.exec(
        strict
          ? line
          : line
              .replace(/^[ \t\r=]+/u, "")
              .replace(/^["a-z\d]+/iu, (word) => word.replaceAll('"', "")),
      );
    yield {
      keyword: keyword === "identityfile2" ? "identityfile" : keyword,
      args:
        directive?.[1]?.toLowerCase() === keyword ? directive[2] : undefined,
    };
  }
}

export function sshIncludeWords(args: string) {
  // Transport binding requires common static syntax across OpenSSH versions.
  if (
    process.platform === "win32" ||
    /['%$\\?[\]{}=\r\f#\ufffd]/u.test(args) ||
    !/^(?:"[^"]+"|[^"\t ]+)(?:[ \t]+(?:"[^"]+"|[^"\t ]+))*$/u.test(args)
  )
    throw unsupportedSshInclude();
  return splitCommand(args, "ssh") ?? [];
}

export function sshIdentityFile(args: string | undefined) {
  const file = args && splitCommand(args, "ssh")?.[0];
  if (file && file.toLowerCase() !== "none") return file;
}

interface SshConfigReader {
  strict: boolean;
  inspect: (path: string) => Promise<string[]>;
  listMatches: (
    pattern: string,
    parent: string,
    matches: (name: string) => boolean,
    list: () => Promise<string[]>,
  ) => Promise<string[]>;
}

export async function walkSshConfiguration(
  config: string,
  environment: NodeJS.ProcessEnv,
  system: string | undefined,
  { inspect, listMatches, strict }: SshConfigReader,
) {
  const unsupported = (): string[] => {
    if (strict) throw unsupportedSshInclude();
    return [];
  };
  const visited = new Set<string>();
  const expand = (pattern: string) => {
    if (isAbsolute(pattern)) return [pattern];
    if (pattern.startsWith("~") && !pattern.startsWith("~/"))
      return unsupported();
    if (system) return [system + "/" + pattern];
    const suffix = pattern.startsWith("~/")
      ? pattern.slice(1)
      : "/.ssh/" + pattern;
    // glob(GLOB_TILDE) can use HOME, while OpenSSH's own expansion uses pw_dir.
    let account: string | undefined;
    try {
      account = userInfo().homedir;
    } catch (error) {
      if (strict) throw error;
    }
    const home = environment["HOME"] ?? account;
    return [...new Set([home, account])].flatMap((base) => {
      if (base === undefined || (strict && /[*?[\]\\]/u.test(base)))
        return unsupported();
      return (isAbsolute(base) ? base : "/" + base) + suffix;
    });
  };
  const select = async (pattern: string) => {
    if (!pattern.includes("*")) return [pattern];
    const parent = dirname(pattern);
    const [prefix, suffix, more] = basename(pattern).split("*");
    if (parent.includes("*") || suffix === undefined || more !== undefined)
      return unsupported();
    const matches = (name: string) =>
      name.length >= prefix!.length + suffix.length &&
      name.startsWith(prefix!) &&
      name.endsWith(suffix) &&
      (!name.startsWith(".") || prefix!.startsWith("."));
    const list = async () => {
      const entries = await readdir(parent).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return [];
          throw error;
        },
      );
      return entries.filter(matches).sort();
    };
    const names = await listMatches(pattern, parent, matches, list);
    return names.flatMap((name) => {
      if (name.includes("\ufffd")) return unsupported();
      return parent + "/" + name;
    });
  };
  const visit = async (path: string, depth: number): Promise<void> => {
    if (visited.has(path)) return;
    visited.add(path);
    if (depth > 16) {
      unsupported();
      return;
    }
    for (const include of await inspect(path))
      for (const pattern of expand(include))
        for (const child of await select(pattern))
          await visit(child, depth + 1);
  };
  await visit(config, 0);
}
