import { excerpts } from "./case-data.mts";
import type { ReachabilityCase, StageFile } from "./cases.mts";
import type { Verdict } from "./grade.mts";

const before = "985238ce5b8f999edccd3c4ba83fba636db51272";
const after = "29a91ff19585ca3eebd4bf53d275f600a093a73d";
const root = "image/ports/";
const patch = root + "1.3.1-r1/CVE-2023-4863.patch";
const workers = "incident/workers.txt";
const packages = "incident/packages.tsv";

function port(
  revision: string,
  source: string,
  destination: string,
): StageFile {
  return {
    kind: "git",
    repository: "alpinelinux/aports",
    revision,
    source,
    destination,
  };
}

const stage: StageFile[] = [
  port(before, "main/libwebp/APKBUILD", root + "1.3.1-r0/APKBUILD"),
  port(after, "main/libwebp/APKBUILD", root + "1.3.1-r1/APKBUILD"),
  port(after, "main/libwebp/CVE-2023-4863.patch", patch),
  port(after, "community/py3-pillow/APKBUILD", root + "py3-pillow/APKBUILD"),
  {
    kind: "fixture",
    source: "fixtures/rollout/app.py",
    destination: "app/thumbnail.py",
  },
  {
    kind: "fixture",
    source: "fixtures/rollout/workers.txt",
    destination: workers,
  },
];

function rolloutCase(
  id: string,
  portNumber: number,
  verdict: Verdict,
): ReachabilityCase {
  const prior = portNumber === 9100;
  const missing = verdict === "unknown";
  const receipts = missing ? "packages-current.tsv" : "packages.tsv";
  const dial = `127.0.0.1:${portNumber}`;
  const revision = prior ? "1.3.1-r1" : "1.3.1-r0";
  const inode = prior ? "3741" : "8930";
  const endpoint = "edge/caddy.json";
  const question =
    "Assess CVE-2023-4863 for the next anonymous POST /thumbnail in the captured deployment. " +
    "The requester supplies the image bytes. The flaw is a heap overwrite while building Huffman tables for a crafted lossless WebP. " +
    "The application uses Alpine's py3-pillow built from this checkout. Assume the captured deployment stays in effect. " +
    "Can this request trigger the advisory? Report the upstream libwebp version used for the request.";
  return {
    id,
    suite: "pillow",
    repository: "python-pillow/Pillow",
    revision: "6e28ed1f36d0eb74053af54e1eddc9c29db698cd",
    question,
    version: "1.3.1",
    verdict,
    stage: [
      ...stage,
      {
        kind: "fixture",
        source: "fixtures/rollout/" + receipts,
        destination: packages,
      },
      {
        kind: "json",
        destination: endpoint,
        value: {
          apps: {
            http: {
              servers: {
                api: {
                  listen: [":80"],
                  routes: [
                    {
                      match: [{ path: ["/thumbnail"] }],
                      handle: [
                        { handler: "reverse_proxy", upstreams: [{ dial }] },
                      ],
                    },
                  ],
                },
              },
            },
          },
        },
      },
    ],
    evidenceGroups: [
      excerpts(endpoint, dial),
      excerpts(workers, dial),
      excerpts(workers, `08:01 ${inode} /usr/lib/libwebp.so`),
      excerpts(packages, `libwebp-${missing ? "1.3.1-r0" : revision}`),
      excerpts(
        root + revision + "/APKBUILD",
        prior ? "CVE-2023-4863.patch" : "libwebp-$pkgver.tar.gz",
      ),
      ...(verdict === "ruled_out"
        ? [
            excerpts(
              patch,
              "+  if (root_table->curr_segment->curr_table + total_size >=",
              "+    next->size = total_size > segment_size",
              "BuildHuffmanTable is called to check if the data is valid.\nIf it is and the table is not big enough, more memory is allocated.",
            ),
          ]
        : []),
    ],
  };
}

export const rolloutCases = [
  rolloutCase("thumbnail-blue", 9100, "ruled_out"),
  rolloutCase("thumbnail-green", 9101, "exploitable"),
  rolloutCase("thumbnail-receipt-window", 9100, "unknown"),
];
