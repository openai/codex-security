import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { assertStableVersion, releaseVersion } from "./release-automation.mjs";

export const packagePath = "sdk/typescript/package.json";
export const notesPath = ".github/release-notes.md";
export const statePath = ".github/release-pr-state.json";
const templatePath = ".github/PULL_REQUEST_TEMPLATE.md";
const sectionIds = ["highlights", "upgrades"];
const releaseBranchPrefix = "release/next-";
const conventionalTitle = /^([a-z][a-z0-9-]*)(?:\([^)]*\))?(!)?: (.+)$/u;

function isReleasePull(pull) {
  return (
    conventionalTitle.exec(pull.title)?.[1] === "release" ||
    pull.head.ref.startsWith(releaseBranchPrefix)
  );
}

export function isBreakingChange(change) {
  return (
    conventionalTitle.exec(change.title)?.[2] === "!" ||
    /^(?:BREAKING CHANGE|BREAKING-CHANGE):\s+\S/mu.test(change.body ?? "") ||
    (change.labels ?? []).includes("breaking-change")
  );
}

export function nextReleaseVersion(version, changes) {
  assertStableVersion(version);
  const [major, minor, patch] = version.split(".").map(BigInt);
  if (major !== 0n) {
    throw new Error(
      "Review the release PR version policy before enabling it for 1.x.",
    );
  }
  if (changes.length === 0) return version;
  return changes.some((change) => change.breaking ?? isBreakingChange(change))
    ? `0.${minor + 1n}.0`
    : `0.${minor}.${patch + 1n}`;
}

function markdownText(value) {
  return value.replace(/[\r\n]+/gu, " ").replace(/[\\`*_[\]<>]/gu, "\\$&");
}

function changeLine(change) {
  const description = conventionalTitle.exec(change.title)?.[3] ?? change.title;
  const reference = change.number
    ? `#${change.number}`
    : change.sha.slice(0, 7);
  return `- ${markdownText(description)} ([${reference}](${change.url}))`;
}

function visibleChanges(changes) {
  return changes.filter((change) => {
    const type = conventionalTitle.exec(change.title)?.[1];
    return (
      !(change.labels ?? []).includes("skip-release-notes") &&
      (change.breaking || !["release", "test"].includes(type))
    );
  });
}

export function generateNoteSections(changes) {
  const visible = visibleChanges(changes);
  const breaking = visible.filter((change) => change.breaking);
  return {
    highlights: [
      "## Highlights",
      "",
      visible.length > 0
        ? visible.map(changeLine).join("\n")
        : "No release highlights have been drafted yet.",
    ].join("\n"),
    upgrades: [
      "## Upgrade notes",
      "",
      breaking.length > 0
        ? [
            "Review migration steps for these breaking changes:",
            "",
            ...breaking.map(changeLine),
          ].join("\n")
        : "Review compatibility and document any required migration steps before releasing.",
    ].join("\n"),
  };
}

function sectionBlock(id, content) {
  return `<!-- release-section: ${id}:start -->\n${content}\n<!-- release-section: ${id}:end -->`;
}

function findSection(notes, id) {
  const markers = [
    ...notes.matchAll(
      new RegExp(`^<!-- release-section: ${id}:(start|end) -->\\r?$`, "gm"),
    ),
  ];
  if (
    markers.length !== 2 ||
    markers[0][1] !== "start" ||
    markers[1][1] !== "end"
  )
    return null;
  const start = markers[0].index;
  const end = markers[1].index + markers[1][0].length;
  return { start, end, text: notes.slice(start, end) };
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function updateReleaseNotes(
  version,
  generated,
  previousNotes,
  previousSections,
) {
  const header = `<!-- release-version: ${version} -->`;
  const sections = {};
  if (previousSections === undefined) {
    const blocks = sectionIds.map((id) => {
      const block = sectionBlock(id, generated[id]);
      sections[id] = { generatedHash: hash(block), humanOwned: false };
      return block;
    });
    return { notes: `${header}\n\n${blocks.join("\n\n")}\n`, sections };
  }

  let notes = previousNotes;
  if (notes !== null) {
    notes = /^<!-- release-version: [^\r\n]* -->/u.test(notes)
      ? notes.replace(/^<!-- release-version: [^\r\n]* -->/u, header)
      : `${header}\n\n${notes}`;
  }
  for (const id of sectionIds) {
    const previous = previousSections[id];
    const block = notes === null ? null : findSection(notes, id);
    const humanOwned =
      previous?.reset !== true &&
      (previous?.humanOwned !== false ||
        block === null ||
        hash(block.text) !== previous.generatedHash);
    if (humanOwned) {
      sections[id] = {
        generatedHash: previous?.generatedHash ?? null,
        humanOwned: true,
      };
      continue;
    }
    const next = sectionBlock(id, generated[id]);
    if (block === null) {
      notes = `${notes ?? `${header}\n`}\n${next}\n`;
    } else {
      notes = notes.slice(0, block.start) + next + notes.slice(block.end);
    }
    sections[id] = { generatedHash: hash(next), humanOwned: false };
  }
  return { notes, sections };
}

function updatePackageVersion(packageText, version) {
  const expected = JSON.parse(packageText);
  expected.version = version;
  // Preserve formatting while selecting only the top-level version field.
  for (const match of packageText.matchAll(
    /("version"\s*:\s*)("(?:\\.|[^"\\])*")/gu,
  )) {
    const start = match.index + match[1].length;
    const updated =
      packageText.slice(0, start) +
      JSON.stringify(version) +
      packageText.slice(start + match[2].length);
    if (isDeepStrictEqual(JSON.parse(updated), expected)) return updated;
  }
  throw new Error("Unable to update only the top-level package version.");
}

export function createReleasePlan(history, previous = null) {
  const { baseVersion, baseCommit, mainSha, packageText, changes } = history;
  if (
    previous &&
    (previous.state.baseVersion !== baseVersion ||
      previous.state.baseCommit !== baseCommit)
  ) {
    throw new Error(
      "The release branch belongs to a different release cycle; review it before continuing.",
    );
  }
  const version = nextReleaseVersion(baseVersion, changes);
  const generated = generateNoteSections(changes);
  const { notes, sections } = updateReleaseNotes(
    version,
    generated,
    previous?.notes ?? null,
    previous?.state.sections,
  );
  const state = { baseVersion, baseCommit, sections };
  return {
    baseVersion,
    baseCommit,
    mainSha,
    version,
    branch: `${releaseBranchPrefix}${baseVersion}`,
    title:
      changes.length > 0
        ? `release: bump Codex Security to ${version}`
        : "release: prepare the next Codex Security release",
    changes,
    generated,
    humanOwned: sectionIds.filter((id) => sections[id].humanOwned),
    files: {
      [packagePath]: updatePackageVersion(packageText, version),
      [notesPath]: notes,
      [statePath]: `${JSON.stringify(state, null, 2)}\n`,
    },
  };
}

export function createGitRepository(directory) {
  const git = (...args) =>
    execFileSync("git", args, {
      cwd: directory,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
  return {
    git,
    ensureCommit(sha) {
      try {
        git("cat-file", "-e", `${sha}^{commit}`);
      } catch {
        git("fetch", "--no-tags", "origin", sha);
      }
    },
    readFile(sha, path) {
      if (git("ls-tree", sha, "--", path).trim() === "") return null;
      return git("show", `${sha}:${path}`);
    },
  };
}

export async function readReleaseHistory(repo, mainSha, github) {
  repo.ensureCommit(mainSha);
  const packageText = repo.readFile(mainSha, packagePath);
  const baseVersion = releaseVersion(JSON.parse(packageText));
  let baseCommit = mainSha;
  for (const sha of repo
    .git("log", "--first-parent", "--format=%H", mainSha, "--", packagePath)
    .trim()
    .split("\n")) {
    const packageJson = JSON.parse(repo.readFile(sha, packagePath));
    if (packageJson.version !== baseVersion) break;
    baseCommit = sha;
  }

  const commits = repo
    .git("rev-list", "--first-parent", "--reverse", `${baseCommit}..${mainSha}`)
    .trim()
    .split("\n")
    .filter(Boolean);
  const changes = new Map();
  for (const sha of commits) {
    const body = repo.git("show", "-s", "--format=%B", sha);
    const pulls = await github.list(`commits/${sha}/pulls?per_page=100`);
    const pull = pulls.find(
      (candidate) => candidate.merged_at && candidate.base.ref === "main",
    );
    const change = {
      sha,
      number: pull?.number ?? null,
      title: pull?.title ?? body.split("\n")[0],
      labels: (pull?.labels ?? []).map((label) => label.name),
      url: pull?.html_url ?? `${github.repositoryUrl}/commit/${sha}`,
    };
    change.breaking = isBreakingChange({
      ...change,
      body: [pull?.body ?? "", body].join("\n"),
    });
    const key = pull ? `pr-${pull.number}` : sha;
    if (changes.has(key)) {
      changes.get(key).breaking ||= change.breaking;
    } else {
      changes.set(key, change);
    }
  }
  return {
    baseVersion,
    baseCommit,
    mainSha,
    packageText,
    changes: [...changes.values()],
  };
}

function readReleaseBranch(repo, mainSha, headSha) {
  repo.ensureCommit(headSha);
  const mergeBase = repo.git("merge-base", mainSha, headSha).trim();
  const paths = repo
    .git("diff", "--no-renames", "--name-only", "-z", mergeBase, headSha)
    .split("\0")
    .filter(Boolean);
  if (
    paths.some((path) => ![packagePath, notesPath, statePath].includes(path))
  ) {
    return {
      holdReason:
        "The release branch has other file edits. Preserve or merge them before running the updater.",
    };
  }
  const originalPackage = JSON.parse(repo.readFile(mergeBase, packagePath));
  const branchPackage = JSON.parse(repo.readFile(headSha, packagePath));
  delete originalPackage.version;
  delete branchPackage.version;
  if (!isDeepStrictEqual(originalPackage, branchPackage)) {
    return {
      holdReason:
        "The release branch has package edits beyond its version. Preserve them before running the updater.",
    };
  }
  const state = JSON.parse(repo.readFile(headSha, statePath));
  if (!state?.sections) {
    throw new Error(
      "The existing release branch has no note ownership state; it must be reviewed manually.",
    );
  }
  return { state, notes: repo.readFile(headSha, notesPath), mergeBase };
}

function initialPullBody(template) {
  const sections = {
    Summary:
      "Keep a draft release proposal current with changes merged into main.",
    Changes:
      "Update the package version and draft release notes. The version header and PR title are maintained by automation. Edit the marked note sections in `.github/release-notes.md`; edited or deleted sections become human-owned. New suggestions appear in subsequent bot comments. The PR description is never regenerated.",
    Testing:
      "The updater does not run package tests. Check required CI and Codex review on the current head before marking this draft ready. Request a final Codex review if the last review targets an older head. Record any additional checks here.",
    "Risk and rollout":
      "This PR does not merge itself. Merging a nonempty proposal starts the existing CI and protected release process. An empty proposal leaves the package version unchanged. Review migration details and complete the public disclosure review before merging.",
  };
  let body = template;
  for (const [heading, content] of Object.entries(sections)) {
    body = body.replace(
      new RegExp(`(## ${heading}\\n)[\\s\\S]*?(?=\\n## |$)`, "u"),
      `$1\n${content}\n`,
    );
  }
  return body;
}

function reviewComment(
  plan,
  headSha,
  proposalMarker,
  suggestionsMarker,
  requestReview,
) {
  const marker = `<!-- release-pr-head: ${headSha} -->`;
  return [
    marker,
    proposalMarker,
    suggestionsMarker,
    `Release proposal updated through main commit \`${plan.mainSha}\`.`,
    plan.humanOwned.length > 0
      ? `Preserved human-owned sections: ${plan.humanOwned.join(", ")}. The suggestions below have not replaced them.`
      : "The note sections still match the generated draft and were refreshed.",
    "These suggestions use merged titles, not a review of migration requirements. The committed notes remain authoritative.",
    ...sectionIds.map((id) => plan.generated[id]),
    ...(requestReview ? [`@codex review the current head ${headSha}.`] : []),
  ].join("\n\n");
}

async function branchHead(github, branch) {
  try {
    return (await github.request("GET", `git/ref/heads/${branch}`)).object.sha;
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

function pullHoldReason(pull, branch) {
  if (
    pull?.state !== "open" ||
    pull.head.ref !== branch ||
    pull.base.ref !== "main"
  ) {
    return "The release PR was closed or retargeted during the update. Review it before continuing.";
  }
  if (!pull.draft) {
    return `Release PR #${pull.number} is ready for review. Convert it back to a draft to resume automatic updates.`;
  }
  return null;
}

function releaseHoldReason(openPulls, pullNumber, branch, repository) {
  const retargeted = openPulls.find(
    (candidate) =>
      candidate.head.ref === branch &&
      candidate.head.repo?.full_name === repository &&
      candidate.base.ref !== "main",
  );
  if (retargeted)
    return `Release PR #${retargeted.number} was retargeted. Restore its main base before resuming updates.`;
  const other = openPulls.find(
    (candidate) =>
      candidate.number !== pullNumber &&
      candidate.base.ref === "main" &&
      isReleasePull(candidate),
  );
  if (other)
    return `Another release PR is open: #${other.number}. It has not been changed.`;
  const current = openPulls.find(
    (candidate) => candidate.number === pullNumber,
  );
  return pullNumber === undefined ? null : pullHoldReason(current, branch);
}

async function ensurePullRequest(
  github,
  plan,
  pull,
  template,
  headSha,
  currentPulls,
) {
  const holdReason = releaseHoldReason(
    currentPulls ?? (await github.list("pulls?state=open&per_page=100")),
    pull?.number,
    plan.branch,
    github.repository,
  );
  if (holdReason)
    return { action: "held", reason: holdReason, reviewRequested: false };
  if (pull) {
    pull = await github.request("GET", `pulls/${pull.number}`);
    const reason = pullHoldReason(pull, plan.branch);
    if (reason)
      return {
        action: "held",
        reason,
        pull: pull.number,
        reviewRequested: false,
      };
    if (pull.title !== plan.title) {
      await github.request("PATCH", `pulls/${pull.number}`, {
        title: plan.title,
      });
    }
  } else {
    pull = await github.request("POST", "pulls", {
      title: plan.title,
      head: plan.branch,
      base: "main",
      draft: true,
      body: initialPullBody(template),
    });
  }
  const current = await github.request("GET", `pulls/${pull.number}`);
  const reason = pullHoldReason(current, plan.branch);
  if (reason)
    return {
      action: "held",
      reason,
      pull: current.number,
      reviewRequested: false,
    };
  if (current.head.sha !== headSha) {
    return {
      pull: current.number,
      reviewRequested: false,
      reason:
        "GitHub has not exposed the updated PR head yet. Rerun the updater before final review.",
    };
  }
  const marker = `<!-- release-pr-head: ${headSha} -->`;
  const proposalMarker = `<!-- release-pr-proposal: ${hash(JSON.stringify(plan.files))} -->`;
  const suggestionsMarker = `<!-- release-pr-suggestions: ${hash(JSON.stringify(plan.generated))} -->`;
  const comments = await github.list(
    `issues/${current.number}/comments?per_page=100`,
  );
  const previous = comments.findLast((comment) =>
    comment.body?.startsWith("<!-- release-pr-head: "),
  );
  const requestReview = !previous?.body.includes(proposalMarker);
  const reviewRequested = comments.some(
    (comment) =>
      comment.body?.includes(marker) &&
      comment.body.includes(`@codex review the current head ${headSha}.`),
  );
  if (requestReview || !previous?.body.includes(suggestionsMarker)) {
    await github.request("POST", `issues/${current.number}/comments`, {
      body: reviewComment(
        plan,
        headSha,
        proposalMarker,
        suggestionsMarker,
        requestReview,
      ),
    });
  }
  return {
    pull: current.number,
    reviewRequested: reviewRequested || requestReview,
  };
}

export async function reconcileReleasePullRequest({
  repo,
  github,
  dryRun = true,
}) {
  // Rebuild the plan only when main or the proposal actually moves.
  for (;;) {
    const mainSha = await branchHead(github, "main");
    const history = await readReleaseHistory(repo, mainSha, github);
    const branch = `${releaseBranchPrefix}${history.baseVersion}`;
    const openPulls = await github.list("pulls?state=open&per_page=100");
    const pull = openPulls.find(
      (candidate) =>
        candidate.head.ref === branch &&
        candidate.head.repo?.full_name === github.repository,
    );
    let holdReason = releaseHoldReason(
      openPulls,
      pull?.number,
      branch,
      github.repository,
    );
    if (!holdReason && !pull) {
      const previousPulls = await github.list(
        `pulls?state=closed&head=${encodeURIComponent(`${github.owner}:${branch}`)}&per_page=100`,
      );
      if (previousPulls.length > 0)
        holdReason = `Release PR #${previousPulls[0].number} was closed. Reopen it to resume this cycle.`;
    }

    const headSha = holdReason ? null : await branchHead(github, branch);
    const previous = headSha ? readReleaseBranch(repo, mainSha, headSha) : null;
    holdReason ??= previous?.holdReason;
    const plan = createReleasePlan(history, holdReason ? null : previous);
    if (holdReason) return { action: "held", reason: holdReason, dryRun, plan };
    if (pull && !headSha)
      throw new Error("The open release PR has no branch head.");
    const changed =
      !headSha ||
      previous.mergeBase !== mainSha ||
      Object.entries(plan.files).some(
        ([path, content]) => repo.readFile(headSha, path) !== content,
      );
    if (dryRun)
      return {
        action: !pull ? "would-create" : changed ? "would-update" : "unchanged",
        dryRun,
        plan,
      };

    let commitSha = headSha;
    let currentPulls;
    if (changed) {
      if ((await branchHead(github, "main")) !== mainSha) continue;
      const tree = await github.request("POST", "git/trees", {
        base_tree: repo.git("rev-parse", `${mainSha}^{tree}`).trim(),
        tree: Object.entries(plan.files).map(([path, content]) => ({
          path,
          mode: "100644",
          type: "blob",
          ...(content === null ? { sha: null } : { content }),
        })),
      });
      const commit = await github.request("POST", "git/commits", {
        message: plan.title,
        tree: tree.sha,
        parents: [...new Set([headSha, mainSha].filter(Boolean))],
      });
      if ((await branchHead(github, "main")) !== mainSha) continue;
      currentPulls = await github.list("pulls?state=open&per_page=100");
      const holdReason = releaseHoldReason(
        currentPulls,
        pull?.number,
        plan.branch,
        github.repository,
      );
      if (holdReason)
        return { action: "held", reason: holdReason, dryRun, plan };
      try {
        if (headSha) {
          await github.request("PATCH", `git/refs/heads/${plan.branch}`, {
            sha: commit.sha,
            force: false,
          });
        } else {
          await github.request("POST", "git/refs", {
            ref: `refs/heads/${plan.branch}`,
            sha: commit.sha,
          });
        }
      } catch (error) {
        if (
          [409, 422].includes(error.status) &&
          (await branchHead(github, plan.branch)) !== headSha
        )
          continue;
        throw error;
      }
      commitSha = commit.sha;
    }
    if ((await branchHead(github, plan.branch)) !== commitSha) continue;
    const publication = await ensurePullRequest(
      github,
      plan,
      pull,
      repo.readFile(mainSha, templatePath),
      commitSha,
      pull ? currentPulls : undefined,
    );
    return {
      action: !pull ? "created" : changed ? "updated" : "unchanged",
      dryRun,
      headSha: commitSha,
      ...publication,
      plan,
    };
  }
}

export function createGitHubClient(repository, token, fetcher = fetch) {
  const apiRoot = `https://api.github.com/repos/${repository}/`;
  async function responseFor(method, path, body) {
    for (let retry = 0; ; retry += 1) {
      const response = await fetcher(`${apiRoot}${path}`, {
        method,
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": "2026-03-10",
          "Content-Type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (response.ok) return response;
      if (
        method === "GET" &&
        retry < 2 &&
        [500, 502, 503, 504].includes(response.status)
      ) {
        await response.body?.cancel().catch(() => undefined);
        await delay(1000 * 2 ** retry);
        continue;
      }
      const error = new Error(
        `GitHub ${method} ${path} failed with HTTP ${response.status}.`,
      );
      error.status = response.status;
      throw error;
    }
  }
  return {
    repository,
    owner: repository.split("/")[0],
    repositoryUrl: `https://github.com/${repository}`,
    async request(method, path, body) {
      return (await responseFor(method, path, body)).json();
    },
    async list(path) {
      const items = [];
      for (let page = 1; ; page += 1) {
        const response = await responseFor(
          "GET",
          `${path}${path.includes("?") ? "&" : "?"}page=${page}`,
        );
        items.push(...(await response.json()));
        if (!response.headers.get("link")?.includes('rel="next"')) return items;
      }
    },
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const directory = fileURLToPath(new URL("../../..", import.meta.url));
  const repository = process.env.GITHUB_REPOSITORY ?? "openai/codex-security";
  const token =
    process.env.GH_TOKEN ??
    execFileSync("gh", ["auth", "token"], {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  const result = await reconcileReleasePullRequest({
    repo: createGitRepository(directory),
    github: createGitHubClient(repository, token),
    dryRun: process.env.RELEASE_PR_DRY_RUN !== "false",
  });
  console.log(JSON.stringify(result, null, 2));
}
