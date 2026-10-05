import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

/** All values are generated locally and have never authenticated to a service. */
export function createFixture() {
  const token = () => randomBytes(24).toString("base64url");
  const values = {
    active: token(),
    unused: token(),
    integration: token(),
    database: token(),
    account: token(),
  };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const files: Record<string, string> = {
    "README.md": `# Delivery worker

A small delivery worker with service clients, message signing, deployment
configuration, and integration checks. Source access is also granted to
reviewers who do not operate the delivery service or its database.
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
    "src/runtime_config.py": `import os

SERVICE_TOKEN = os.environ["SERVICE_TOKEN"]
DATABASE_URL = os.environ["DATABASE_URL"]
`,
    "examples/settings.env.example": `SERVICE_TOKEN=YOUR_SERVICE_TOKEN_HERE
DATABASE_PASSWORD=<replace-with-secret>
`,
    "config/public.pem": publicKey,
    "src/constants.py": `PUBLIC_CLIENT_ID = "delivery-worker"
CONTENT_SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`,
  };
  const positive = (
    id: string,
    path: string,
    marker: string,
    cwes: string[],
    consumerMarker?: string,
    endMarker = marker,
  ) => {
    const lines = files[path].split("\n");
    return {
      id,
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
    positives: [
      positive(
        "active-source",
        "src/client.py",
        "SERVICE_TOKEN =",
        ["CWE-798", "CWE-312", "CWE-313", "CWE-522"],
        '"Authorization": "Bearer " + SERVICE_TOKEN',
      ),
      positive("unused-source", "src/retired.py", "LEGACY_SERVICE_TOKEN =", [
        "CWE-798",
        "CWE-312",
        "CWE-313",
        "CWE-522",
      ]),
      positive(
        "integration-source",
        "tests/test_delivery.py",
        "INTEGRATION_TOKEN =",
        ["CWE-798", "CWE-312", "CWE-313", "CWE-522"],
        '"Authorization": "Bearer " + INTEGRATION_TOKEN',
      ),
      positive("dotenv-url", "config/.env", "DATABASE_URL=", [
        "CWE-798",
        "CWE-256",
        "CWE-259",
        "CWE-260",
        "CWE-312",
        "CWE-313",
        "CWE-522",
      ]),
      positive("account-config", "config/service.json", '"client_secret"', [
        "CWE-798",
        "CWE-312",
        "CWE-313",
        "CWE-522",
      ]),
      positive(
        "private-key",
        "src/signing.mjs",
        "const signingKey",
        ["CWE-321", "CWE-798", "CWE-312", "CWE-313"],
        "return sign(",
        privateKey.trim().split("\n").at(-2),
      ),
    ],
    negatives: [
      "src/runtime_config.py",
      "examples/settings.env.example",
      "config/public.pem",
      "src/constants.py",
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

/** Stage source only. Gold labels and secret-value lookup stay in the harness. */
export async function writeFixture(
  repo: string,
  fixture: ReturnType<typeof createFixture>,
) {
  for (const [relative, contents] of Object.entries(fixture.files)) {
    const destination = join(repo, relative);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, contents);
  }
}
