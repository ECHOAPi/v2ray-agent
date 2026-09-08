"use strict";

const { readFileSync } = require("node:fs");

function readVersion(source) {
  const matches = [...source.matchAll(/^[ \t]*echoContent green "(?:当前版本：|Current version: )(v\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?)"[ \t]*$/gm)];
  if (matches.length !== 1) throw new Error("Expected exactly one complete installer version");
  return matches[0][1];
}

async function optional404(request) {
  try {
    return (await request()).data;
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function publishRelease({ github, context, core, readFile = readFileSync }) {
  const version = readVersion(readFile("install.sh", "utf8"));
  if (readVersion(readFile("shell/install_en.sh", "utf8")) !== version) {
    throw new Error("Installer versions disagree");
  }
  if (!/^[a-f0-9]{40}$/.test(context.sha)) throw new Error("Invalid workflow commit");
  const repo = { owner: context.repo.owner, repo: context.repo.repo };
  const existing = await optional404(() => github.rest.repos.getReleaseByTag({ ...repo, tag: version }));
  if (existing) {
    core.info("Version already published; no changes: " + version);
    return { created: false, tag: version };
  }
  // An existing unmatched or annotated tag needs manual review; never move it.
  const ref = await optional404(() => github.rest.git.getRef({ ...repo, ref: "tags/" + version }));
  if (ref && (ref.object.type !== "commit" || ref.object.sha !== context.sha)) {
    throw new Error("Existing tag does not point directly to the workflow commit");
  }
  const prerelease = version.includes("-");
  const result = await github.rest.repos.createRelease({
    ...repo,
    tag_name: version,
    name: version,
    target_commitish: context.sha,
    body: "Source: https://github.com/" + repo.owner + "/" + repo.repo + "/commit/" + context.sha,
    draft: false,
    prerelease,
    make_latest: prerelease ? "false" : "true",
  });
  core.info("Published " + version);
  return { created: true, tag: version, url: result.data.html_url };
}

// No historical release or tag cleanup: retention is a separate manual decision.
module.exports = { readVersion, publishRelease };
