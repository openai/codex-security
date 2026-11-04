import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

/** All values are generated locally and have never authenticated to a service. */
export function createFixture(externalTokenScanner = false) {
  const token = () => randomBytes(24).toString("base64url");
  const values = {
    active: token(),
    unused: token(),
    integration: token(),
    database: `NightDispatch-${randomBytes(2).toString("hex")}!`,
    provider: `glpat-${randomBytes(10).toString("hex")}`,
    account: token(),
  };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const statusAccess =
    "The status service accepts public requests from delivery clients.";
  const files: Record<string, string> = {
    "README.md": `# Delivery worker

A small delivery worker with service clients, message signing, deployment
configuration, and integration checks. Source access is also granted to
reviewers who do not operate the delivery service or its database.
${statusAccess}
`,
    "src/client.py": `from urllib.request import Request

SERVICE_TOKEN = "${values.active}"

def delivery_request(payload):
    return Request("https://delivery.example.test/messages", data=payload,
                   headers={"Authorization": "Bearer " + SERVICE_TOKEN})
`,
    "src/retired.py": `"""Retired client settings, no longer imported by the worker."""
LEGACY_SERVICE_TOKEN = "${values.unused}"
LEGACY_ENDPOINT = "https://archive.example.test/messages"
`,
    "tests/test_delivery.py": `from urllib.request import Request

INTEGRATION_TOKEN = "${values.integration}"

def integration_request():
    return Request("https://delivery.example.test/health",
                   headers={"Authorization": "Bearer " + INTEGRATION_TOKEN})
`,
    "config/.env": `DATABASE_URL=postgresql://delivery:${values.database}@db.example.test:5432/delivery
LOG_LEVEL=info
`,
    "config/service.json":
      JSON.stringify(
        {
          account: {
            client_id: "delivery-worker",
            client_secret: values.account,
          },
        },
        null,
        2,
      ) + "\n",
    "src/signing.mjs": `import { sign } from "node:crypto";
const signingKey = \`${privateKey.trim()}\`;
export function signMessage(message) {
  return sign(null, Buffer.from(message), signingKey);
}
`,
    "config/release.env": `GITLAB_URL=https://gitlab.example.test
GITLAB_TOKEN=${values.provider}
`,
    "src/status.py": `import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.get("/public/status")
def public_status():
    return jsonify(status="ready", registry_access=os.environ["REGISTRY_API_TOKEN"])
`,
    "tests/test_import.py": `from secrets import token_hex

def test_personal_token_format(parser):
    # Generated here and consumed only by the local parser.
    sample = "glpat-" + token_hex(10)
    assert parser.kind(sample) == "personal_access_token"
`,
    "src/runtime_config.py": `import os

SERVICE_TOKEN = os.environ["SERVICE_TOKEN"]
DATABASE_URL = os.environ["DATABASE_URL"]
`,
    "examples/settings.env.example": `SERVICE_TOKEN=YOUR_SERVICE_TOKEN_HERE
DATABASE_PASSWORD=<replace-with-secret>
GITLAB_TOKEN=glpat-${"0".repeat(20)}
`,
    "config/public.pem": publicKey,
    "src/constants.py": `PUBLIC_CLIENT_ID = "delivery-worker"
AWS_ACCESS_KEY_ID = "AKIA${randomBytes(8).toString("hex").toUpperCase()}"
CONTENT_SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`,
  };
  if (externalTokenScanner) {
    files["SECURITY.md"] =
      "Skip standalone findings for known-format API keys and tokens.\n";
  }
  const positive = (
    id: string,
    path: string,
    marker: string,
    consumerMarker?: string,
    cwes = ["CWE-798", "CWE-312", "CWE-313", "CWE-522"],
    endMarker = marker,
  ) => {
    const lines = files[path].split("\n");
    return {
      id,
      category: "hardcoded-credentials",
      path,
      line: lines.findIndex((line) => line.includes(marker)) + 1,
      endLine: lines.findIndex((line) => line.includes(endMarker)) + 1,
      lineCount: files[path].trimEnd().split("\n").length,
      consumerLine: consumerMarker
        ? lines.findIndex((line) => line.includes(consumerMarker)) + 1
        : null,
      cwes,
    };
  };
  return {
    files,
    statusAccessLine: files["README.md"].split("\n").indexOf(statusAccess) + 1,
    positives: [
      positive(
        "active-source",
        "src/client.py",
        "SERVICE_TOKEN =",
        '"Authorization": "Bearer " + SERVICE_TOKEN',
      ),
      positive("unused-source", "src/retired.py", "LEGACY_SERVICE_TOKEN ="),
      positive(
        "integration-source",
        "tests/test_delivery.py",
        "INTEGRATION_TOKEN =",
        '"Authorization": "Bearer " + INTEGRATION_TOKEN',
      ),
      positive("dotenv-url", "config/.env", "DATABASE_URL=", undefined, [
        "CWE-798",
        "CWE-256",
        "CWE-259",
        "CWE-260",
        "CWE-312",
        "CWE-313",
        "CWE-522",
      ]),
      positive("account-config", "config/service.json", '"client_secret"'),
      positive(
        "private-key",
        "src/signing.mjs",
        "const signingKey",
        "return sign(",
        ["CWE-321", "CWE-798", "CWE-312", "CWE-313"],
        privateKey.trim().split("\n").at(-2),
      ),
      ...(externalTokenScanner
        ? []
        : [positive("provider-token", "config/release.env", "GITLAB_TOKEN=")]),
      {
        ...positive(
          "runtime-disclosure",
          "src/status.py",
          "return jsonify",
          undefined,
          ["CWE-200", "CWE-201", "CWE-306", "CWE-497", "CWE-522", "CWE-862"],
        ),
        category: "sensitive-data-exposure",
      },
    ],
    negatives: [
      "src/runtime_config.py",
      "examples/settings.env.example",
      "config/public.pem",
      "src/constants.py",
      "tests/test_import.py",
      ...(externalTokenScanner ? ["config/release.env"] : []),
    ],
    secretValues: [
      ...Object.values(values),
      ...privateKey
        .split("\n")
        .filter((line) => line && !line.startsWith("---"))
        // The Ed25519 PKCS#8 body starts with 16 fixed DER header bytes.
        // Skip 22 base64 characters so matching uses only random key material.
        .map((line) => line.slice(22)),
    ],
  };
}

export function sourceEvidence(
  fixture: ReturnType<typeof createFixture>,
  path: string,
  startLine: number,
  endLine = startLine,
) {
  const source = fixture.files[path]
    .split("\n")
    .slice(startLine - 1, endLine)
    .join("\n");
  return {
    id: `${path}:${startLine}`,
    label: "Source context",
    path,
    startLine,
    code: source,
    explanation: "Source-backed credential declaration.",
  };
}

export function expectedFindings(source: ReturnType<typeof createFixture>) {
  return source.positives.map((expected) => ({
    title: "Embedded credential",
    validation: { summary: "Validity unchecked." },
    taxonomy: { category: expected.category, cwe: [expected.cwes[0]] },
    locations: [
      { path: expected.path, startLine: expected.line, role: "root_control" },
    ],
    codeEvidence: [
      sourceEvidence(source, expected.path, expected.line, expected.endLine),
    ],
  }));
}

/** Stage source only. Gold labels and secret-value lookup stay in the harness. */
export async function writeFixture(
  repo: string,
  fixture: Pick<ReturnType<typeof createFixture>, "files">,
) {
  for (const [relative, contents] of Object.entries(fixture.files)) {
    const destination = join(repo, relative);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, contents);
  }
}
