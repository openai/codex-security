// Historical attack-path prompts; the investigator receives only the question.
export const questions = new Map([
  ...["affected-decode", "fixed-decode"].map((id) => [
    id,
    "Assess CVE-2023-4863 in libwebp for this Pillow checkout. The flaw is a heap overflow when decoding Huffman tables in a crafted lossless WebP. Upstream fixed it in 1.3.2. Assume the official Linux CPython 3.12 x86_64 manylinux_2_28 wheel built for this release. An attacker supplies the bytes in request_body to Image.open(BytesIO(request_body)).load(). Can this caller trigger the advisory? Report the bundled libwebp version.",
  ]),
  ...["affected-encode-only"].map((id) => [
    id,
    "Assess CVE-2023-4863 in libwebp for this Pillow checkout. The flaw is a heap overflow when decoding Huffman tables in a crafted lossless WebP. Upstream fixed it in 1.3.2. Assume the official Linux CPython 3.12 x86_64 manylinux_2_28 wheel built for this release. An attacker controls raw RGB pixel values in a validated, fixed-length 64x64 buffer. The only image operation is Image.frombytes('RGB', (64, 64), pixels).save(output, format='WEBP', lossless=True). Can this caller trigger the advisory? Report the bundled libwebp version.",
  ]),
  ...[
    "direct-links",
    "disabled-links",
    "queued-links",
    "unmounted-route",
    "external-worker",
  ].map((id) => [
    id,
    "An unauthenticated caller controls the raw email submitted to POST /inbox. Can this caller trigger the advisory through that endpoint as deployed? Report the dependency version in the supplied image. The finding is CVE-2026-48801 in linkify-it. In versions through 5.0.0, match() takes quadratic time on text containing many fuzzy links or email addresses.",
  ]),
  ...["address-groups", "address-backport", "stripped-headers"].map((id) => [
    id,
    "An unauthenticated caller controls the raw email submitted to POST /inbox. Can this caller trigger the advisory through that endpoint as deployed? Report the dependency version in the supplied image. The finding is CVE-2025-14874 in Nodemailer 3.0.0 through 7.0.10. Its address parser can exhaust the stack by recursing without a depth limit on nested address groups in a mail header. Upstream added a depth limit in 7.0.11.",
  ]),
  ...["native-charset"].map((id) => [
    id,
    "An unauthenticated caller controls the raw email submitted to POST /inbox. Can this caller trigger the advisory through that endpoint as deployed? Report the dependency version in the supplied image. The finding is CVE-2024-2961 in glibc iconv. In unpatched glibc versions through 2.39, certain conversions to ISO-2022-CN-EXT can overflow the output buffer.",
  ]),
  ...["task-parameter"].map((id) => [
    id,
    "Assess CVE-2023-37466 in vm2 for the starter app's example-nodejs-template. Assume the backend and its dependencies are built from this checkout and its lockfile. An authenticated user may submit a normal POST /v2/tasks request and controls the name parameter. The repository destination is fixed. The user cannot edit the registered template or its skeleton. Scope this to server-side task execution. The advisory describes a sandbox escape in vm2 through 3.9.19 that requires attacker-controlled JavaScript execution inside the VM. Can this requester meet that precondition? Report the resolved vm2 version.",
  ]),
  ...["archive-east", "archive-west"].map((id) => [
    id,
    "Assess CVE-2025-14874 in Nodemailer. An unauthenticated caller controls the bytes of an uploaded file in POST /archive. The finding concerns unbounded recursion on nested groups in an address header in Nodemailer 3.0.0 through 7.0.10. Determine whether this caller can reach the vulnerable operation through the service as deployed, and report the installed Nodemailer version.",
  ]),
  ...[
    "archive-worker-pinned-original",
    "archive-worker-pinned-normalized",
    "archive-worker-mime-parts",
  ].map((id) => [
    id,
    "An unauthenticated sender can submit an RFC 5322 message to POST /messages and has no other access. Can that sender trigger CVE-2025-14874 in this deployment? The advisory concerns unbounded recursion on nested address groups in a message header in Nodemailer through 7.0.10. Report the installed Nodemailer version.",
  ]),
  ...["thumbnail-blue", "thumbnail-green", "thumbnail-receipt-window"].map(
    (id) => [
      id,
      "Assess CVE-2023-4863 for the next anonymous POST /thumbnail in the captured deployment. The requester supplies the image bytes. The flaw is a heap overwrite while building Huffman tables for a crafted lossless WebP. The application uses Alpine's py3-pillow built from this checkout. Assume the captured deployment stays in effect. Can this request trigger the advisory? Report the upstream libwebp version used for the request.",
    ],
  ),
  ...["zip-import-alpha", "zip-import-beta"].map((id) => [
    id,
    "An external caller can submit a ZIP mail bundle and controls only its contents. CVE-2025-14874 in Nodemailer requires a sender-controlled address header to reach the parser. Can an arbitrary To address chosen by this caller reach the installed address parser through this feature? Assess this input prerequisite and report the installed Nodemailer version.",
  ]),
]);
