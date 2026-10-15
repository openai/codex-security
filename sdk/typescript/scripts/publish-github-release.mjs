import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { constants } from "node:os";
import { basename, join } from "node:path";
import {
  composeReleaseNotes,
  resolveReleaseSummary,
  verifyGitHubRelease,
} from "./release-automation.mjs";

function runCommand(program, args, stderr = "inherit", stdout = "pipe") {
  return spawnSync(program, args, {
    encoding: "utf8",
    maxBuffer: Infinity,
    stdio: ["inherit", stdout, stderr],
  });
}
function output(result) {
  if (result.error) {
    console.error(result.error.message);
    throw { status: result.error.code === "ENOENT" ? 127 : 126 };
  }
  if (result.status !== 0) {
    throw { status: result.status ?? 128 + constants.signals[result.signal] };
  }
  return result.stdout;
}
function githubReleaseOrMissing(run, endpoint, label) {
  const result = run("gh", ["api", "--include", endpoint], "ignore");
  const fail = () => {
    throw new Error(`Unable to resolve the ${label}.`);
  };
  const raw = result.stdout ?? "";
  const separator = raw.search(/\r?\n\r?\n/u);
  const status = /^HTTP\/\d+(?:\.\d+)?\s+(\d{3})(?:\s|$)/u.exec(
    raw.slice(0, separator),
  );
  if (separator < 0 || status == null) fail();
  let response;
  try {
    response = JSON.parse(
      raw.slice(separator + (raw[separator] === "\r" ? 4 : 2)),
    );
  } catch {
    fail();
  }
  if (response == null || typeof response !== "object") fail();
  if (result.status === 0) {
    if (Number(status[1]) < 200 || Number(status[1]) >= 300) fail();
    return response;
  }
  if (status[1] !== "404") fail();
}

/** @param {Function} run */
export function publishGitHubRelease(env, workspace, run = runCommand) {
  const {
    GITHUB_REPOSITORY: repository,
    RELEASE_TAG: tag,
    RELEASE_VERSION: version,
    RELEASE_SHA: sha,
    RELEASE_ARCHIVE: archive,
    PREVIOUS_TAG: previousTag,
    MAKE_LATEST: makeLatest,
  } = env;
  const base = `repos/${repository}`;
  const release = (action, args, assets = []) => {
    const result = run(
      "gh",
      ["release", action, tag, ...assets, "--repo", repository, ...args],
      "inherit",
      "inherit",
    );
    output(result);
  };
  const verifyTag = () => {
    const fail = () => {
      console.error(
        "GitHub release tag must still point to the verified commit.",
      );
      throw { status: 1 };
    };
    const ref = run("gh", [
      "api",
      `${base}/git/ref/tags/${tag}`,
      "--jq",
      "[.object.type, .object.sha] | @tsv",
    ]);
    if (ref.status !== 0) fail();
    const [type, ...objectFields] = ref.stdout.replace(/\n+$/u, "").split("\t");
    const object = objectFields.join("\t");
    if (!/^[0-9a-fA-F]{40}$/u.test(object)) fail();
    let commit = object;
    if (type === "tag") {
      const peeled = run("gh", [
        "api",
        `${base}/git/tags/${object}`,
        "--jq",
        'if .object.type == "commit" then .object.sha else empty end',
      ]);
      if (peeled.status !== 0) fail();
      commit = peeled.stdout.replace(/\n+$/u, "");
    } else if (type !== "commit") fail();
    if (!/^[0-9a-fA-F]{40}$/u.test(commit) || commit !== sha) fail();
  };
  const existing = githubReleaseOrMissing(
    run,
    `${base}/releases/tags/${tag}`,
    "existing GitHub Release",
  );
  if (existing !== undefined) {
    const assetName = basename(archive);
    const destination = join(workspace, "downloaded-assets");
    mkdirSync(destination);
    release("download", ["--pattern", assetName, "--dir", destination]);
    const downloaded = join(destination, assetName);
    if (!lstatSync(downloaded, { throwIfNoEntry: false })?.isFile()) {
      console.error("Expected the exact existing GitHub release asset.");
      throw { status: 1 };
    }
    const verified = verifyGitHubRelease(
      existing,
      readFileSync(archive),
      tag,
      assetName,
      readFileSync(downloaded),
    );
    console.log(JSON.stringify(verified));
  }
  if (existing?.body != null && typeof existing.body !== "string")
    throw new Error("Existing release notes must be a string.");
  const existingNotes = (existing?.body ?? "").replace(/(?:\r?\n)+$/u, "");
  const notesArgs = [
    "api",
    "--method",
    "POST",
    `${base}/releases/generate-notes`,
    "-f",
    `tag_name=${tag}`,
    "-f",
    `target_commitish=${sha}`,
  ];
  if (
    run("git", ["cat-file", "-e", `${sha}:.github/release.yml`], "ignore")
      .status === 0
  )
    notesArgs.push("-f", "configuration_file_path=.github/release.yml");
  if (previousTag) notesArgs.push("-f", `previous_tag_name=${previousTag}`);
  const generatedResult = run("gh", notesArgs);
  const generated = JSON.parse(generatedResult.stdout);
  if (typeof generated.body !== "string")
    throw new Error("Generated GitHub release notes must be a string.");
  output(generatedResult);
  const tagged = run(
    "git",
    ["show", `${sha}:.github/release-notes.md`],
    "ignore",
  );
  const generatedNotes = generated.body.replace(/(?:\r?\n)+$/u, "");
  if (generatedNotes.length === 0)
    throw new Error("Generated GitHub release notes must not be empty.");
  const notes = composeReleaseNotes(
    generatedNotes,
    resolveReleaseSummary(
      version,
      tagged.status === 0 ? tagged.stdout : undefined,
      existingNotes,
    ),
  );
  const notesFile = join(workspace, "published-notes.md");
  writeFileSync(notesFile, notes);
  if (existing !== undefined) {
    const latest = githubReleaseOrMissing(
      run,
      `${base}/releases/latest`,
      "current Latest GitHub Release",
    );
    if (
      latest !== undefined &&
      (typeof latest.tag_name !== "string" || latest.tag_name.length === 0)
    )
      throw new Error("Unable to resolve the current Latest GitHub Release.");
    const currentlyLatest = String(latest?.tag_name === tag);
    const notesChanged = !Buffer.from(existingNotes).equals(Buffer.from(notes));
    if (notesChanged || currentlyLatest !== makeLatest) {
      const args = [`--latest=${makeLatest}`];
      if (notesChanged) args.push("--notes-file", notesFile);
      verifyTag();
      release("edit", args);
      if (notesChanged)
        console.log(
          "Updated existing GitHub Release with reviewed and generated notes.",
        );
      if (currentlyLatest !== makeLatest)
        console.log("Updated existing GitHub Release Latest status.");
    } else console.log("The verified GitHub Release already exists.");
    return;
  }
  verifyTag();
  release(
    "create",
    [
      "--title",
      `Codex Security ${version}`,
      "--verify-tag",
      "--notes-file",
      notesFile,
      `--latest=${makeLatest}`,
    ],
    [archive],
  );
}
