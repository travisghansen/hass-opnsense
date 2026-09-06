/** Validate that a dependency pull request remains safe to auto-merge. */
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const DEPENDABOT = "dependabot[bot]";
const WEB_FLOW = "web-flow";

function refuse(message) {
  throw new Error(`Refusing auto-merge; ${message}`);
}

function dependencyEcosystem(headRef) {
  if (headRef.startsWith("dependabot/uv/")) return "uv";
  if (headRef.startsWith("dependabot/npm_and_yarn/")) return "npm";
  if (headRef.startsWith("dependabot/github_actions/")) return "github-actions";
  refuse(`unsupported Dependabot branch: ${headRef}`);
}

function isTrustedBaseFile(trustedBaseDirectory, path) {
  const base = resolve(trustedBaseDirectory);
  const candidate = resolve(base, path);
  const pathFromBase = relative(base, candidate);
  if (
    pathFromBase === "" ||
    isAbsolute(pathFromBase) ||
    pathFromBase === ".." ||
    pathFromBase.startsWith(`..${sep}`)
  )
    return false;
  return existsSync(candidate) && statSync(candidate).isFile();
}

function assertAllowedFiles(ecosystem, changedFiles, trustedBaseDirectory) {
  if (changedFiles.length === 0)
    refuse("the pull request has no changed files.");
  if (ecosystem === "uv") {
    if (!isTrustedBaseFile(trustedBaseDirectory, "uv.lock"))
      refuse("the trusted base does not use uv.");
    if (changedFiles.length !== 1 || changedFiles[0] !== "uv.lock")
      refuse("uv updates must change only uv.lock.");
    return;
  }
  if (ecosystem === "npm") {
    if (
      !isTrustedBaseFile(trustedBaseDirectory, "package.json") ||
      !isTrustedBaseFile(trustedBaseDirectory, "package-lock.json")
    )
      refuse("the trusted base does not use npm.");
    const isPackageFile = (path) =>
      path === "package.json" || path === "package-lock.json";
    const isLockfileOnly =
      changedFiles.length === 1 && changedFiles[0] === "package-lock.json";
    const isManifestAndLockfile =
      changedFiles.length === 2 &&
      changedFiles.includes("package.json") &&
      changedFiles.includes("package-lock.json") &&
      changedFiles.every(isPackageFile);
    if (!isLockfileOnly && !isManifestAndLockfile)
      refuse(
        "npm updates must change only package.json and package-lock.json.",
      );
    return;
  }

  const isExistingAllowedFile = (path) =>
    (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(path) ||
      /(^|\/)action\.ya?ml$/.test(path)) &&
    isTrustedBaseFile(trustedBaseDirectory, path);
  if (!changedFiles.every(isExistingAllowedFile))
    refuse("the update changes a file outside the trusted dependency scope.");
}

function assertDirectDependabotHistory(event, commits) {
  const [commit] = commits;
  if (
    commits.length !== 1 ||
    commit?.author?.login !== DEPENDABOT ||
    commit?.commit?.verification?.verified !== true ||
    commit?.sha !== event.pull_request.head.sha
  )
    refuse("the pull request does not have a verified Dependabot head commit.");
}

function assertUpdateBranchHistory(event, commits) {
  if (event.action !== "synchronize")
    refuse(`the triggering actor was not ${DEPENDABOT}.`);
  if (commits.length < 2)
    refuse("the synchronization was not a GitHub Update branch merge.");
  if (
    commits[0]?.author?.login !== DEPENDABOT ||
    commits[0]?.commit?.verification?.verified !== true
  )
    refuse("the pull request history does not begin with Dependabot.");

  for (let index = 1; index < commits.length; index += 1) {
    const commit = commits[index];
    const previous = commits[index - 1];
    if (
      commit?.committer?.login !== WEB_FLOW ||
      commit?.commit?.verification?.verified !== true ||
      commit?.parents?.length !== 2 ||
      commit.parents[0]?.sha !== previous?.sha
    )
      refuse("the pull request contains a non-Dependabot edit.");
  }

  const latest = commits.at(-1);
  if (
    latest?.sha !== event.pull_request.head.sha ||
    latest.parents[1]?.sha !== event.pull_request.base.sha
  )
    refuse("the latest commit is not an update from the current base branch.");
}

/**
 * Authorize a Dependabot update or a chain containing only GitHub Update branch merges.
 *
 * @param {object} input Validation inputs from the pull-request event and API.
 */
export function authorizeDependabotUpdate({
  actor,
  changedFiles,
  commits,
  event,
  trustedBaseDirectory = process.cwd(),
}) {
  const pullRequest = event.pull_request;
  if (
    event.repository?.fork !== false ||
    pullRequest?.user?.login !== DEPENDABOT ||
    pullRequest?.head?.repo?.full_name !== event.repository?.full_name ||
    pullRequest?.base?.ref !== event.repository?.default_branch
  )
    refuse(
      "the pull request does not have the required Dependabot provenance.",
    );

  const ecosystem = dependencyEcosystem(pullRequest.head.ref);
  if (actor === DEPENDABOT) assertDirectDependabotHistory(event, commits);
  else assertUpdateBranchHistory(event, commits);
  assertAllowedFiles(ecosystem, changedFiles, trustedBaseDirectory);
  return ecosystem;
}

function main() {
  const [, , eventPath, changedFilesPath, commitsPath] = process.argv;
  if (!eventPath || !changedFilesPath || !commitsPath)
    throw new Error(
      "Usage: dependabot-auto-merge.mjs EVENT CHANGED_FILES COMMITS",
    );
  const event = JSON.parse(readFileSync(eventPath, "utf8"));
  const changedFiles = readFileSync(changedFilesPath, "utf8")
    .split("\n")
    .filter(Boolean);
  const commitPages = JSON.parse(readFileSync(commitsPath, "utf8"));
  const commits = commitPages.flat();
  authorizeDependabotUpdate({
    actor: process.env.GITHUB_ACTOR,
    changedFiles,
    commits,
    event,
  });
  console.log("Authorized dependency update files and commit history.");
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
)
  main();
