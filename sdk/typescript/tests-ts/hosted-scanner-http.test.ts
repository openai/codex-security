import { setImmediate } from "node:timers/promises";
import { afterEach, expect, jest, mock, test } from "bun:test";
import {
  hostedScannerHttp,
  type HostedScannerHttpOptions,
} from "../src/hosted-scanner-http.js";

const url = new URL(
  "https://semgrep.dev/api/v1/deployments/example/findings?page=1",
);
function get(options: HostedScannerHttpOptions) {
  return hostedScannerHttp(options).getJson(url, "Bearer synthetic");
}

const now = Date.UTC(2026, 10, 6, 8, 49, 20, 250);
afterEach(() => jest.useRealTimers());

function limited(hint: string, cancel: () => void) {
  return new Response(new ReadableStream({ cancel }), {
    status: 429,
    headers: { "Retry-After": hint },
  });
}

test.each([
  ["010", 10_000, null],
  ["Fri, 06 Nov 2026 08:48:05 GMT", 5_000, "Fri, 06 Nov 2026 08:48:00 GMT"],
  ["Fri, 06 Nov 2026 08:49:30 GMT", 9_750, null],
  ["Friday, 06-Nov-26 08:49:30 GMT", 9_750, "unusable date"],
  ["Fri Nov  6 08:49:30 2026", 9_750, null],
  ["Sun, 06 Nov 1994 08:49:37 GMT", 0, null],
  ["Sunday, 06-Nov-94 08:49:37 GMT", 0, null],
  ["Sat, 31 Dec 2016 23:59:60 GMT", 0, null],
] as const)(
  "releases the 429 body and waits for Retry-After %s",
  async (hint, delay, serverDate) => {
    jest.useFakeTimers({ now });
    const released = Promise.withResolvers<void>();
    const fetch = mock(async () => Response.json({ complete: true }));
    const response = limited(hint, released.resolve);
    if (serverDate) response.headers.set("Date", serverDate);
    fetch.mockResolvedValueOnce(response);
    const result = get({ fetch });
    await released.promise;
    if (delay > 0) {
      jest.advanceTimersByTime(delay - 1);
      await setImmediate();
      expect(fetch).toHaveBeenCalledTimes(1);
      jest.advanceTimersByTime(1);
    }
    expect(await result).toEqual({ complete: true });
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

test("retries the same URL when a transport rewrites its request path", async () => {
  const paths: string[] = [];
  await get({
    fetch: async (requestUrl) => {
      requestUrl.pathname = `/proxy${requestUrl.pathname}`;
      paths.push(requestUrl.pathname);
      return paths.length === 1
        ? new Response(null, { status: 429, headers: { "Retry-After": "0" } })
        : Response.json({});
    },
  });
  expect(paths).toEqual([`/proxy${url.pathname}`, `/proxy${url.pathname}`]);
});

test.each(["cancel", "timeout"])(
  "a %s during Retry-After prevents the second GET",
  async (mode) => {
    jest.useFakeTimers({ now });
    const controller = new AbortController();
    const signal =
      mode === "timeout" ? AbortSignal.timeout(500) : controller.signal;
    const released = Promise.withResolvers<void>();
    const fetch = mock(async () => limited("10", released.resolve));
    const result = get({
      fetch,
      signal,
    }).catch((error: unknown) => error);
    await released.promise;
    if (mode === "timeout") jest.advanceTimersByTime(500);
    else controller.abort(new Error("collection stopped"));
    expect(await result).toBe(signal.reason);
    jest.advanceTimersByTime(10_000);
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);

test("unusable or long hints and other HTTP errors fail on the first response with raw details", async () => {
  jest.useFakeTimers({ now });
  const detail = "vendor detail: synthetic-token\n\u001b[31mretry later";
  for (const [status, hint] of [
    [429, null],
    [429, ""],
    [429, "-1"],
    [429, "1.5"],
    [429, "1e0"],
    [429, "0, 1"],
    [429, "11"],
    [429, "9".repeat(400)],
    [429, "Fri, 06 Nov 2026 08:49:31 GMT"],
    [429, "Tuesday, 06-Nov-74 08:49:30 GMT"],
    [429, "2026-11-06"],
    [429, "Fri, 31 Feb 2023 08:49:30 GMT"],
    [429, "Fri, 30 Dec 2016 23:59:60 GMT"],
    [401, "0"],
    [403, "0"],
    [503, "0"],
    [307, "0"],
  ] as const) {
    const fetch = mock(
      async () =>
        new Response(detail, {
          status,
          headers: hint === null ? {} : { "Retry-After": hint },
        }),
    );
    await expect(get({ fetch })).rejects.toThrow(
      `GET ${url.origin}${url.pathname} failed (HTTP ${status})${hint ? `; Retry-After: ${hint}` : ""}: ${detail}`,
    );
    expect(fetch).toHaveBeenCalledTimes(1);
  }
});

test("does not retry a fetch rejection", async () => {
  const error = new TypeError("connection reset");
  const fetch = mock(async () => {
    throw error;
  });
  await expect(get({ fetch })).rejects.toBe(error);
  expect(fetch).toHaveBeenCalledTimes(1);
});
