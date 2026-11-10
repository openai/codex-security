import { expect, test } from "bun:test";
import { isGitHubCloudHost, parseGitRemote } from "../src/git-remote.js";

test.each([
  [
    "https://example.test/team/project.git",
    false,
    "https:",
    "",
    "",
    "team/project.git",
  ],
  [
    "ssh://git@example.test:2222/team/project.git",
    false,
    "ssh:",
    "git",
    "2222",
    "team/project.git",
  ],
  [
    "git@example.test:team/project.git",
    true,
    "ssh:",
    "git",
    "",
    "team/project.git",
  ],
  ["example.test:team/project.git", true, "ssh:", "", "", "team/project.git"],
] as const)(
  "parses the transport of %s",
  (input, scpStyle, protocol, username, port, path) => {
    const remote = parseGitRemote(input)!;
    expect(remote).toMatchObject({ scpStyle, path });
    expect(remote.url.hostname).toBe("example.test");
    expect(remote.url.protocol).toBe(protocol);
    expect(remote.url.username).toBe(username);
    expect(remote.url.port).toBe(port);
  },
);

test("keeps literal SCP paths separate from URL queries and fragments", () => {
  const remote = parseGitRemote(
    "git@example.test:team/../project.git?ref#part",
  )!;
  expect(remote.path).toBe("team/../project.git?ref#part");
  expect(remote.url.search).toBe("");
  expect(remote.url.hash).toBe("");
});

test("uses URL path semantics while preserving repository casing", () => {
  const remote = parseGitRemote("https://example.test/Team/../Project.git/")!;
  expect(remote.path).toBe("Project.git/");
  expect(remote.url.pathname).toBe("/Project.git/");
});

test("leaves transport and credential eligibility to callers", () => {
  const remote = parseGitRemote(
    "http://synthetic:password@example.test/team/project?ref#part",
  )!;
  expect(remote.url.protocol).toBe("http:");
  expect(remote.url.username).toBe("synthetic");
  expect(remote.url.password).toBe("password");
  expect(remote.url.search).toBe("?ref");
  expect(remote.url.hash).toBe("#part");
});

test("preserves IPv6 hosts and explicit SSH ports", () => {
  const remote = parseGitRemote(
    "ssh://git@[2001:db8::1]:2222/team/project.git",
  )!;
  expect(remote.url.hostname).toBe("[2001:db8::1]");
  expect(remote.url.port).toBe("2222");
  expect(remote.path).toBe("team/project.git");
});

test("distinguishes plain paths and malformed URLs", () => {
  expect(parseGitRemote("./team/project")).toBeUndefined();
  expect(() => parseGitRemote("https://[invalid/team/project")).toThrow();
});

test.each([
  ["github.com", true],
  ["example-enterprise.ghe.com", true],
  ["ghe.com", false],
  ["github.example.test", false],
  ["github.com.example.test", false],
  ["example-enterprise.ghe.com.example.test", false],
] as const)("recognizes GitHub Cloud host %s", (host, expected) => {
  expect(isGitHubCloudHost(host)).toBe(expected);
});
