import { once } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { connect } from "node:net";
import { dirname, join } from "node:path";

export async function loopbackTls(
  config: string,
  git: (...args: string[]) => string,
  usage: "server" | "client" = "server",
) {
  const directory = dirname(config);
  const settings = join(directory, `${usage}-openssl.cnf`);
  const key = join(directory, `${usage}-key.pem`);
  const cert = join(directory, `${usage}-cert.pem`);
  await writeFile(
    settings,
    "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n" +
      `[dn]\nCN=Loopback test ${usage}\n` +
      `[extensions]\nbasicConstraints=critical,CA:TRUE\nextendedKeyUsage=${usage}Auth\n` +
      "subjectAltName=IP:127.0.0.1,IP:127.0.0.2\n",
  );
  // Git for Windows supplies OpenSSL on its shell PATH.
  git(
    "-C",
    directory,
    "-c",
    "alias.test-openssl=!openssl",
    "test-openssl",
    "req",
    "-newkey",
    "rsa:2048",
    "-x509",
    "-nodes",
    "-days",
    "1",
    "-config",
    settings,
    "-keyout",
    key,
    "-out",
    cert,
  );
  if (usage === "client") {
    git("config", "--file", config, "http.sslCert", cert);
    git("config", "--file", config, "http.sslKey", key);
    // Git for Windows also offers Schannel, which uses a certificate store.
    if (process.platform === "win32")
      git("config", "--file", config, "http.sslBackend", "openssl");
  } else {
    git("config", "--file", config, "http.sslCAInfo", cert);
    git("config", "--file", config, "http.schannelUseSSLCAInfo", "true");
  }
  return { key: await readFile(key), cert: await readFile(cert) };
}

export async function loopbackProxy(originPort: number) {
  const proxy = createServer();
  // Only this tunnel maps the destination address to the loopback Git server.
  proxy.on("connect", (request, client, head) => {
    if (request.url !== `127.0.0.2:${originPort}`) {
      client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const upstream = connect(originPort, "127.0.0.1", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      client.pipe(upstream).pipe(client);
    });
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
  });
  proxy.listen(0, "127.0.0.1");
  await once(proxy, "listening");
  const address = proxy.address();
  if (!address || typeof address === "string")
    throw new Error("Missing loopback proxy address");
  return {
    url: `http://127.0.0.1:${address.port}`,
    [Symbol.dispose]() {
      proxy.close();
    },
  };
}
