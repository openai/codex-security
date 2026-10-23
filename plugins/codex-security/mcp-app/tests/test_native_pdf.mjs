import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const pluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : fileURLToPath(
      new URL("../../../../sdk/typescript/_bundled_plugin/", import.meta.url),
    );

test(
  "shipped native entrypoint extracts a PDF before Codex authentication",
  { timeout: 30000 },
  async () => {
    const root = await realpath(
      await mkdtemp(path.join(tmpdir(), "codex-security-native-pdf-")),
    );
    const repository = path.join(root, "repository");
    const temporary = path.join(root, "tmp");
    const codexHome = path.join(root, "codex");
    const document = path.join(root, "architecture.pdf");
    const receipt = path.join(root, "codex-boundary.json");
    const preload = path.join(root, "fake-codex.mjs");
    const server = path.join(pluginRoot, "mcp", "server.mjs");
    const text = "Payment service boundary";
    const client = new Client({
      name: "codex-security-native-pdf-test",
      version: "1.0.0",
    });
    try {
      await Promise.all(
        [repository, temporary, codexHome].map((directory) => mkdir(directory)),
      );
      await writeFile(
        path.join(repository, "app.py"),
        "print('synthetic fixture')\n",
      );
      await writeFile(document, pdf(text));
      // Node is the fake Codex executable on every platform. Only login status is allowed.
      await writeFile(
        preload,
        `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
if (resolve(process.argv[1] ?? "") === ${JSON.stringify(server)}) {
  const spawn = childProcess.spawn;
  childProcess.spawn = (command, args, options) => {
    if (command !== process.execPath) return spawn(command, args, options);
    if (options?.env?.CODEX_HOME !== ${JSON.stringify(codexHome)}
      || args?.at(-2) !== "login" || args?.at(-1) !== "status")
      throw new Error("Unexpected fake Codex command; model execution is forbidden.");
    return spawn(command, [${JSON.stringify(preload)}, ...args], options);
  };
  syncBuiltinESMExports();
} else {
  const args = process.argv.slice(2);
  const config = args.slice(0, -2);
  if (config.length % 2 || config.some((value, index) =>
    index % 2 === 0 ? value !== "--config" : !value.includes("=")))
    throw new Error("Unexpected fake Codex authentication flags.");
  const documents = readdirSync(${JSON.stringify(temporary)})
    .filter(name => name.startsWith("codex-security-knowledge-"))
    .flatMap(name => readdirSync(join(${JSON.stringify(temporary)}, name))
      .map(file => readFileSync(join(${JSON.stringify(temporary)}, name, file), "utf8")));
  writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({ args, documents }));
  if (JSON.stringify(args.slice(-2)) !== JSON.stringify(["login", "status"]))
    throw new Error("Unexpected fake Codex command; model execution is forbidden.");
  console.error("Not logged in (synthetic fixture).");
  process.exit(1);
}
`,
      );
      const environment = Object.fromEntries(
        ["PATH", "SystemRoot", "WINDIR", "PYTHON"]
          .filter((name) => process.env[name] !== undefined)
          .map((name) => [name, process.env[name]]),
      );
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [server, "--stdio"],
        cwd: root,
        env: {
          ...environment,
          HOME: root,
          USERPROFILE: root,
          TMPDIR: temporary,
          TMP: temporary,
          TEMP: temporary,
          CODEX_HOME: codexHome,
          CODEX_CLI_PATH: process.execPath,
          NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
          CODEX_SECURITY_KNOWLEDGE_BASE: document,
          CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
          CODEX_SECURITY_SCAN_ROOT: path.join(root, "scans"),
        },
      });
      await client.connect(transport);
      const result = await client.callTool({
        name: "start_codex_security_deep_scan",
        arguments: { targetPath: repository },
        _meta: {
          "openai/threadId": "synthetic-pdf-owner",
          "codex/sandbox-state-meta": {
            permissionProfile: {
              type: "managed",
              file_system: { type: "unrestricted" },
              network: "restricted",
            },
          },
        },
      });
      assert.equal(result.isError, true);
      assert.match(result.content[0].text, /No credentials were found/);
      const boundary = JSON.parse(await readFile(receipt, "utf8"));
      assert.deepEqual(boundary.args.slice(-2), ["login", "status"]);
      assert.deepEqual(boundary.documents, [text]);
    } finally {
      await client.close();
      await rm(root, { recursive: true, force: true });
    }
  },
);

function pdf(text) {
  const stream = `BT /F1 12 Tf 72 720 Td (${text}) Tj ET`;
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
  for (const offset of offsets.slice(1))
    output += `${String(offset).padStart(10, "0")} 00000 n \n`;
  output += `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(output);
}
