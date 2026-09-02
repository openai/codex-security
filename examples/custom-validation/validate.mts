// Exercise the fixture over real HTTP and save the observed evidence.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import { createServer } from "./app.mjs";

type HttpResult = {
  status: number;
  body: { id?: string; owner?: string; amount?: number; error?: string };
};

async function main(): Promise<number> {
  let output: string;
  try {
    const { values } = parseArgs({
      options: {
        output: { type: "string" },
        help: { type: "boolean", short: "h" },
      },
    });
    if (values.help) {
      console.log("Usage: node validate.mjs --output PATH");
      return 0;
    }
    if (values.output === undefined) throw new Error("--output is required");
    output = values.output;
  } catch (error) {
    console.error((error as Error).message);
    return 2;
  }

  const server = await createServer();
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  async function get(invoice: string, token?: string): Promise<HttpResult> {
    const response = await fetch(`${baseUrl}/invoices/${invoice}`, {
      headers: token === undefined ? {} : { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5_000),
    });
    return {
      status: response.status,
      body: (await response.json()) as HttpResult["body"],
    };
  }

  let evidence: {
    anonymous: HttpResult;
    own_invoice: HttpResult;
    other_invoice: HttpResult;
    cross_account_read: boolean;
  };
  try {
    const anonymous = await get("1002");
    const own_invoice = await get("1001", "demo-alice");
    const other_invoice = await get("1002", "demo-alice");
    assert.equal(anonymous.status, 401, "Authentication control failed");
    assert.equal(own_invoice.status, 200, "Own-account control failed");
    evidence = {
      anonymous,
      own_invoice,
      other_invoice,
      cross_account_read:
        other_invoice.status === 200 && other_invoice.body.owner === "bob",
    };
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  const proof = { ...evidence, server_stopped: true };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(proof));
  return 0;
}

process.exitCode = await main();
