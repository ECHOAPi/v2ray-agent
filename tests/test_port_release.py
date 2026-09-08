"""Run the release JavaScript with a strict in-memory GitHub API double."""
import json
from pathlib import Path
import subprocess
import unittest

REPO = Path(__file__).resolve().parents[1]
HARNESS = r"""
const { readVersion, publishRelease } = require('./.github/scripts/release.cjs');
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const calls = [];
const response = (name, normal) => async (args) => {
  calls.push({ name, args });
  const status = input[name + 'Status'];
  if (status) { const error = new Error(name + ' failed'); error.status = status; throw error; }
  return { data: input[name + 'Data'] || normal };
};
const github = { rest: {
  repos: {
    getReleaseByTag: response('lookup', { tag_name: 'existing' }),
    createRelease: response('create', { html_url: 'https://example.invalid/release' }),
  },
  git: { getRef: response('ref', { object: { type: 'commit', sha: 'a'.repeat(40) } }) },
}};
(async () => {
  try {
    if (input.parse !== undefined) return { version: readVersion(input.parse), calls };
    const version = input.version || 'v3.5.24-port.4';
    const result = await publishRelease({
      github,
      context: { repo: { owner: 'test', repo: 'repo' }, sha: input.sha || 'a'.repeat(40) },
      core: { info() {} },
      readFile: (path) => path === 'install.sh' ? '    echoContent green "当前版本：' + version + '"'
        : '    echoContent green "Current version: ' + (input.englishVersion || version) + '"',
    });
    return { result, calls };
  } catch (error) {
    return { error: error.message, calls };
  }
})().then((result) => process.stdout.write(JSON.stringify(result)));
"""


class ReleaseTests(unittest.TestCase):
    def run_js(self, **arguments):
        result = subprocess.run(["node", "-e", HARNESS], cwd=REPO, input=json.dumps(arguments),
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_complete_versions_are_parsed_from_both_installers(self):
        for name in ("install.sh", "shell/install_en.sh"):
            result = self.run_js(parse=(REPO / name).read_text())
            self.assertEqual(result["version"], "v3.5.24-port.4")
        for version in ("v3.5.24", "v3.5.24-port.4", "v3.5.24-rc.1"):
            result = self.run_js(parse=f'echoContent green "当前版本：{version}"')
            self.assertEqual(result["version"], version)

    def test_missing_truncated_duplicate_and_malformed_versions_are_rejected(self):
        good = 'echoContent green "当前版本：v3.5.24-port.4"'
        for text in ("# no version", good + "\n" + good,
                     good.replace("-port.4", "-port..4"), good.replace("-port.4", "-port/4"),
                     good.replace('-port.4"', '-port.4"+untrusted')):
            with self.subTest(text=text):
                result = self.run_js(parse=text)
                self.assertIn("error", result)
                self.assertEqual(result["calls"], [])

    def test_existing_release_is_idempotent_without_mutations(self):
        result = self.run_js()
        self.assertFalse(result["result"]["created"])
        self.assertEqual([call["name"] for call in result["calls"]], ["lookup"])
        self.assertEqual(result["calls"][0]["args"]["tag"], "v3.5.24-port.4")

    def test_new_release_uses_full_tag_and_exact_workflow_commit(self):
        for version in ("v3.5.24", "v3.5.24-port.4"):
            result = self.run_js(version=version, lookupStatus=404, refStatus=404)
            self.assertTrue(result["result"]["created"])
            self.assertEqual([call["name"] for call in result["calls"]], ["lookup", "ref", "create"])
            arguments = result["calls"][-1]["args"]
            self.assertEqual(arguments["tag_name"], version)
            self.assertEqual(arguments["target_commitish"], "a" * 40)
            self.assertEqual(arguments["prerelease"], "-" in version)
            self.assertEqual(arguments["make_latest"], "false" if "-" in version else "true")

    def test_network_auth_and_rate_limit_errors_do_not_publish(self):
        for status in (401, 403, 429, 500):
            for stage in ("lookup", "ref"):
                with self.subTest(status=status, stage=stage):
                    args = {"lookupStatus": 404, stage + "Status": status}
                    result = self.run_js(**args)
                    self.assertIn("error", result)
                    self.assertNotIn("create", [call["name"] for call in result["calls"]])

    def test_create_failure_stops_without_cleanup_calls(self):
        result = self.run_js(lookupStatus=404, refStatus=404, createStatus=422)
        self.assertIn("error", result)
        self.assertEqual([call["name"] for call in result["calls"]], ["lookup", "ref", "create"])

    def test_existing_conflicting_or_annotated_tag_is_not_overwritten(self):
        for obj in ({"type": "commit", "sha": "b" * 40}, {"type": "tag", "sha": "a" * 40}):
            result = self.run_js(lookupStatus=404, refData={"object": obj})
            self.assertIn("error", result)
            self.assertEqual([call["name"] for call in result["calls"]], ["lookup", "ref"])
        result = self.run_js(lookupStatus=404)
        self.assertTrue(result["result"]["created"])

    def test_mismatched_installers_or_invalid_commit_fail_before_api_access(self):
        for values in ({"englishVersion": "v3.5.24-port.3"}, {"sha": "master"}):
            result = self.run_js(**values)
            self.assertIn("error", result)
            self.assertEqual(result["calls"], [])

    def test_workflow_calls_tested_module_and_has_no_destructive_cleanup(self):
        workflow = (REPO / ".github/workflows/create_release.yml").read_text()
        self.assertIn("await publishRelease({ github, context, core });", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertNotIn("outputs.tag", workflow)
        source = (REPO / ".github/scripts/release.cjs").read_text()
        for name in ("deleteRelease", "deleteRef", "listReleases", "listCommits"):
            self.assertNotIn(name, source + workflow)
