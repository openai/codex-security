import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import * as os from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import { prepareKnowledgeBase } from "../src/knowledge-base.js";
import { expandHome } from "../src/runtime.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup, temporaryDirectories } =
  createApiTestFixtures("codex-security-knowledge-test-");
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(cleanup);

async function extractedDocuments(path: string): Promise<string[]> {
  return await Promise.all(
    (await readdir(path)).map((name) => readFile(join(path, name), "utf8")),
  );
}

function docx(
  text: string,
  secondLine?: string,
  breakElement = "<w:br/>",
): Uint8Array {
  return zipSync({
    "word/document.xml": strToU8(
      `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r>${secondLine === undefined ? "" : `${breakElement}<w:r><w:t>${secondLine}</w:t></w:r>`}</w:p></w:body></w:document>`,
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
  test.each(["win32", "darwin", "linux"])(
    "matches case-variant Git metadata using %s platform and filesystem rules",
    async (platform) => {
      const root = await temporaryDirectory();
      await mkdir(join(root, ".GIT"));
      await writeFile(join(root, ".GIT", "config"), "Synthetic metadata");
      await writeFile(join(root, "guide.md"), "Synthetic guide");
      const aliasesGit = await filesystem.lstat(join(root, ".git")).then(
        () => true,
        () => false,
      );
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          `
      Object.defineProperty(process, "platform", { value: process.argv[1] });
      const { prepareKnowledgeBase } = await import(process.argv[2]);
      const { readdir, readFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const prepared = await prepareKnowledgeBase([process.argv[3]]);
      try {
        console.log(JSON.stringify(await Promise.all((await readdir(prepared.path)).map(name => readFile(join(prepared.path, name), "utf8")))));
      } finally { await prepared.cleanup(); }
    `,
          platform,
          fileURLToPath(new URL("../src/knowledge-base.ts", import.meta.url)),
          root,
        ],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout).sort()).toEqual(
        platform === "win32" || aliasesGit
          ? ["Synthetic guide"]
          : ["Synthetic guide", "Synthetic metadata"],
      );
    },
  );

  test.each([
    [".git", "directory"],
    [".GIT", "directory"],
    [".GIT", "directory link"],
    [".GIT", "Git file"],
  ] as const)(
    "directory knowledge bases handle %s metadata with %s while direct files remain explicit",
    async (metadataName, metadataKind) => {
      const linked = metadataKind === "directory link";
      const gitFile = metadataKind === "Git file";
      const root = await temporaryDirectory();
      if (gitFile) {
        const template = await temporaryDirectory();
        const initialized = spawnSync(
          "git",
          [
            "init",
            "--quiet",
            `--template=${template}`,
            "--initial-branch=synthetic",
            root,
          ],
          { encoding: "utf8" },
        );
        expect(initialized.status, initialized.stderr).toBe(0);
        await filesystem.rename(join(root, ".git"), join(root, ".GIT"));
        const aliasesGit = await filesystem.lstat(join(root, ".git")).then(
          () => true,
          () => false,
        );
        // Case-insensitive filesystems cannot represent this separate Git file.
        if (!aliasesGit) await writeFile(join(root, ".git"), "gitdir: .GIT\n");
        const recognized = spawnSync(
          "git",
          ["-C", root, "rev-parse", "--absolute-git-dir"],
          { encoding: "utf8" },
        );
        expect(recognized.status, recognized.stderr).toBe(0);
        expect(await filesystem.realpath(recognized.stdout.trim())).toBe(
          await filesystem.realpath(join(root, ".GIT")),
        );
      } else {
        await mkdir(join(root, metadataName));
      }
      const metadata = join(root, metadataName, "config");
      await writeFile(
        metadata,
        (gitFile ? await readFile(metadata, "utf8") : "") +
          "[http]\nextraheader = synthetic-authorization\n",
      );
      await writeFile(
        join(root, "guide.md"),
        "Documented application behavior.",
      );
      const aliasesGit = await filesystem.lstat(join(root, ".git")).then(
        () => true,
        () => false,
      );
      if (metadataName !== ".git" && !aliasesGit) {
        if (linked) {
          await symlink(
            join(root, metadataName),
            join(root, ".git"),
            process.platform === "win32" ? "junction" : "dir",
          );
        } else {
          await mkdir(join(root, ".git"));
          await writeFile(
            join(root, ".git", "config"),
            "Separate Git metadata.",
          );
        }
      }
      const directory = await prepareKnowledgeBase([root]);
      temporaryDirectories.track(directory.path);
      expect((await extractedDocuments(directory.path)).sort()).toEqual(
        [
          "Documented application behavior.",
          ...(process.platform !== "win32" && !aliasesGit && !linked
            ? [await readFile(metadata, "utf8")]
            : []),
        ].sort(),
      );
      const explicit = await prepareKnowledgeBase([metadata]);
      temporaryDirectories.track(explicit.path);
      expect(await extractedDocuments(explicit.path)).toEqual([
        await readFile(metadata, "utf8"),
      ]);
    },
  );

  testPosix(
    "omits case-variant metadata aliases on a case-insensitive filesystem",
    async () => {
      const root = await temporaryDirectory();
      const preservedGit = join(root, ".GIT");
      await mkdir(preservedGit);
      const metadata = join(preservedGit, "config");
      await writeFile(
        metadata,
        "[http]\nextraheader = synthetic-authorization\n",
      );
      await writeFile(
        join(root, "guide.md"),
        "Documented application behavior.",
      );
      const originalStat = filesystem.stat;
      const aliasSpy = spyOn(filesystem, "stat").mockImplementation(
        async (path, options?) =>
          Reflect.apply(originalStat, filesystem, [
            path === join(root, ".git") ? preservedGit : path,
            options,
          ]),
      );
      try {
        const directory = await prepareKnowledgeBase([root]);
        temporaryDirectories.track(directory.path);
        expect(await extractedDocuments(directory.path)).toEqual([
          "Documented application behavior.",
        ]);
        const explicit = await prepareKnowledgeBase([metadata]);
        temporaryDirectories.track(explicit.path);
        expect(await extractedDocuments(explicit.path)).toEqual([
          await readFile(metadata, "utf8"),
        ]);
      } finally {
        aliasSpy.mockRestore();
      }
    },
  );

  test("prepares nested supported documents and retains requested source roots", async () => {
    const root = await temporaryDirectory();
    const nested = join(root, "architecture", "threats");
    const scope = join(root, "scope.md");
    await mkdir(nested, { recursive: true });
    await writeFile(scope, "Ignore local debug endpoints.");
    await writeFile(join(nested, "deployment.MARKDOWN"), "Public API gateway.");
    await writeFile(join(nested, "notes.txt"), "Prioritize SSRF.");
    await mkdir(join(root, ".git"));
    await writeFile(join(root, ".git", "config"), "Repository metadata.");
    await writeFile(join(nested, ".git"), "gitdir: /synthetic/metadata");
    await writeFile(join(root, "ignored.bin"), new Uint8Array([0, 1, 2]));
    await writeFile(join(root, "invalid-utf8.bin"), new Uint8Array([0xff]));

    const knowledgeBase = await prepareKnowledgeBase([scope, root, scope]);
    temporaryDirectories.track(knowledgeBase.path);

    expect(knowledgeBase.sources).toEqual([scope, root]);
    expect((await readdir(knowledgeBase.path)).sort()).toEqual([
      "0-scope.md.txt",
      "1-deployment.MARKDOWN.txt",
      "2-notes.txt.txt",
    ]);
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

  test.each([
    ["context.json", '{"service":"Public API"}'],
    ["results.sarif", '{"version":"2.1.0","runs":[]}'],
    ["deployment.yaml", "service: public-api\n"],
    ["context.custom", "Boundary: café → gateway\n"],
    ["CONTEXT", "Public API gateway.\n"],
  ])("accepts %s directly and in nested directories", async (name, text) => {
    const root = await temporaryDirectory();
    const nested = join(root, "nested");
    await mkdir(nested);
    const source = join(nested, name);
    await writeFile(source, text);

    for (const paths of [[source], [root], [root, source]]) {
      const knowledgeBase = await prepareKnowledgeBase(paths);
      temporaryDirectories.track(knowledgeBase.path);
      expect(await extractedDocuments(knowledgeBase.path)).toEqual([text]);
      expect(knowledgeBase.sources).toEqual(paths);
    }
  });

  test.each([
    ["ASCII at the staging boundary", `${"a".repeat(246)}.md`],
    ["ASCII beyond the staging boundary", `${"a".repeat(247)}.md`],
    ["ASCII at the source boundary", `${"a".repeat(252)}.md`],
    ["multibyte UTF-8", `${"文".repeat(83)}.md`],
  ])("stages long filenames: %s", async (_description, name) => {
    const root = await temporaryDirectory();
    const paths: string[] = [];
    const contents: string[] = [];
    for (let index = 0; index < 11; index++) {
      const directory = join(root, String(index));
      await mkdir(directory);
      const source = join(directory, name);
      const text = `Document ${index}.`;
      await writeFile(source, text);
      paths.push(source);
      contents.push(text);
    }
    const scope = join(root, "scope.md");
    await writeFile(scope, "Review application boundaries.");
    paths.push(scope);
    contents.push("Review application boundaries.");

    const knowledgeBase = await prepareKnowledgeBase(paths);
    temporaryDirectories.track(knowledgeBase.path);

    expect(knowledgeBase.sources).toEqual(paths);
    expect((await extractedDocuments(knowledgeBase.path)).sort()).toEqual(
      [...contents].sort(),
    );
    expect(
      await readFile(join(knowledgeBase.path, "11-scope.md.txt"), "utf8"),
    ).toBe("Review application boundaries.");
    await knowledgeBase.cleanup();
    await expect(stat(knowledgeBase.path)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(
      await Promise.all(paths.map((path) => readFile(path, "utf8"))),
    ).toEqual(contents);
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
          temporaryDirectories.track(knowledgeBase.path);
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
      temporaryDirectories.track(knowledgeBase.path);
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
    const originalWriteFile = filesystem.writeFile;
    let staged = false;
    const writeSpy = spyOn(filesystem, "writeFile").mockImplementation(
      async (...args) => {
        await Reflect.apply(originalWriteFile, filesystem, args);
        staged = true;
        controller.abort(reason);
      },
    );

    try {
      await expect(
        prepareKnowledgeBase([first, second], controller.signal, staging),
      ).rejects.toBe(reason);
      expect(staged).toBe(true);
      expect(await readdir(staging)).toEqual([]);
    } finally {
      writeSpy.mockRestore();
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
      temporaryDirectories.track(expanded.path);
      expect(expanded.sources).toEqual([documents]);

      const bare = await prepareKnowledgeBase(["~"]);
      temporaryDirectories.track(bare.path);
      expect(bare.sources).toEqual([home]);

      const absolute = await prepareKnowledgeBase([documents]);
      temporaryDirectories.track(absolute.path);
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
    await writeFile(
      join(root, "threat-model.docx"),
      docx("SSRF &amp; IDOR", "Review authentication"),
    );
    await writeFile(
      join(root, "paired-break.docx"),
      docx("Authorization", "Review permissions", "<w:br></w:br>"),
    );
    await writeFile(
      join(root, "carriage-return.docx"),
      docx("Authentication", "Review sessions", "<w:cr/>"),
    );

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.track(knowledgeBase.path);
    const documents = await extractedDocuments(knowledgeBase.path);

    expect(documents).toContain("Payment service boundary");
    expect(documents).toContain("SSRF & IDOR\nReview authentication\n");
    expect(documents).toContain("Authorization\nReview permissions\n");
    expect(documents).toContain("Authentication\nReview sessions\n");
  });

  test.each([
    ["&#x110000;", "&#x110000;"],
    ["&#1114112;", "&#1114112;"],
    ["&#99999999999999;", "&#99999999999999;"],
    ["&#xD800;", "&#xD800;"],
    ["&#xDFFF;", "&#xDFFF;"],
    ["&#55296;", "&#55296;"],
    ["&#xD7FF;", "\uD7FF"],
    ["&#xE000;", "\uE000"],
    ["&#65;", "A"],
    ["&#128512;", "\u{1F600}"],
    ["&#x10FFFF;", "\u{10FFFF}"],
    ["&#0;", "\0"],
    ["&#x1;", "\x01"],
  ])(
    "decodes DOCX Unicode scalar references and preserves unusable ones: %s",
    async (reference, expected) => {
      const root = await temporaryDirectory();
      await writeFile(join(root, "reference.docx"), docx(`Text ${reference}.`));
      const knowledgeBase = await prepareKnowledgeBase([root]);
      temporaryDirectories.track(knowledgeBase.path);
      const documents = await extractedDocuments(knowledgeBase.path);
      expect(documents).toEqual([`Text ${expected}.\n`]);
    },
  );

  test("keeps one unusable reference from failing the other knowledge-base documents", async () => {
    const root = await temporaryDirectory();
    await writeFile(join(root, "notes.md"), "Authentication boundary notes");
    await writeFile(
      join(root, "threat-model.docx"),
      docx("Boundary &#x110000; case."),
    );

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.track(knowledgeBase.path);
    const documents = await extractedDocuments(knowledgeBase.path);

    expect(documents).toHaveLength(2);
    expect(documents).toContain("Authentication boundary notes");
    expect(documents).toContain("Boundary &#x110000; case.\n");
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
    temporaryDirectories.track(second.path);
    const documents = await extractedDocuments(second.path);

    expect(documents.sort()).toEqual([
      "New attack priorities",
      "Updated scope",
    ]);
  });

  test("rejects missing paths, explicit binary files, and binary-only directories", async () => {
    const root = await temporaryDirectory();
    const unsupported = join(root, "scope.doc");
    await writeFile(unsupported, new Uint8Array([0, 1, 2]));

    await expect(prepareKnowledgeBase([""])).rejects.toThrow("cannot be empty");
    await expect(
      prepareKnowledgeBase([join(root, "missing.md")]),
    ).rejects.toThrow();
    await expect(prepareKnowledgeBase([unsupported])).rejects.toThrow(
      "contains binary data",
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
    temporaryDirectories.track(knowledgeBase.path);
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
