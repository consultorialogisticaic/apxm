"""Pin the `ci` command and the policy of the CI workflow.

The workflow is the contract with the VPS platform: it must run only on a push to main,
never cancel a run, store nothing on GitHub, and hold the OIDC permission only where it
is used. These checks read the files, so they run in the MLIR-free gate.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CI_PATH = REPOSITORY_ROOT / "tools" / "scripts" / "ci.py"
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
NIGHTLY = REPOSITORY_ROOT / ".github" / "workflows" / "nightly.yml"
PUBLISH = REPOSITORY_ROOT / ".github" / "scripts" / "publish" / "publish.sh"
DEKK_MANIFEST_PATH = REPOSITORY_ROOT / ".dekk.toml"


def load_ci():
    sys.path.insert(0, str(CI_PATH.parent))
    try:
        spec = importlib.util.spec_from_file_location("apxm_ci", CI_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CiCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ci = load_ci()
        with DEKK_MANIFEST_PATH.open("rb") as handle:
            cls.commands = tomllib.load(handle)["commands"]

    def test_every_step_is_a_declared_dekk_command(self) -> None:
        for name in self.ci.CI_COMMANDS:
            self.assertIn(name, self.commands)

    def test_ci_is_declared_and_runs_the_script(self) -> None:
        self.assertEqual(self.commands["ci"]["run"], "python tools/scripts/ci.py")
        self.assertIn("test-ci", self.commands)

    def test_the_gate_that_needs_no_toolchain_runs_first_and_the_cohort_last(self) -> None:
        steps = self.ci.CI_COMMANDS
        self.assertEqual(steps[0], "check-service")
        self.assertLess(steps.index("prepare-release-descriptors"), steps.index("package-release"))
        self.assertLess(steps.index("package-release"), steps.index("verify-package"))
        self.assertIn("test-compiler", steps)
        self.assertIn("build", steps)

    def test_steps_resolve_to_the_declared_run_strings(self) -> None:
        resolved = dict(self.ci.resolve_steps({n: v["run"] for n, v in self.commands.items() if "run" in v}))
        for name in self.ci.CI_COMMANDS:
            self.assertEqual(resolved[name], self.commands[name]["run"])

    def test_skip_rejects_a_step_the_command_does_not_run(self) -> None:
        commands = {n: v["run"] for n, v in self.commands.items() if "run" in v}
        self.assertEqual(len(self.ci.resolve_steps(commands, skip=("build",))), len(self.ci.CI_COMMANDS) - 1)
        with self.assertRaises(KeyError):
            self.ci.resolve_steps(commands, skip=("fmt-check",))


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.code = "\n".join(
            line for line in cls.text.splitlines() if not line.lstrip().startswith("#")
        )

    def test_no_github_storage_and_no_github_hosted_runner(self) -> None:
        for forbidden in (
            "upload-artifact",
            "download-artifact",
            "actions/cache",
            "ghcr.io",
            "ubuntu-latest",
            "gh release",
            "action-gh-release",
        ):
            self.assertNotIn(forbidden, self.code, forbidden)

    def test_no_setup_action_cache_input(self) -> None:
        self.assertNotRegex(self.code, r"(?m)^\s*cache:")

    def test_runs_only_on_push_to_main_and_manual_dispatch(self) -> None:
        self.assertNotIn("pull_request", self.code)
        self.assertRegex(self.code, r"push:\n\s+branches: \[main\]")
        self.assertIn("paths-ignore:", self.code)

    def test_concurrency_group_never_cancels(self) -> None:
        self.assertIn("cancel-in-progress: false", self.code)
        self.assertNotIn("cancel-in-progress: true", self.code)

    def test_the_push_workflow_runs_the_fast_check_and_not_the_heavy_suites(self) -> None:
        self.assertIn("dekk agents check-service-fast", self.code)
        self.assertNotRegex(self.code, r"dekk agents ci\b")
        self.assertNotIn("schedule:", self.code)

    def test_id_token_is_granted_per_job_and_never_at_the_top_level(self) -> None:
        top = self.code.split("jobs:")[0]
        self.assertNotIn("id-token", top)
        check, image = self.code.split("  image:")
        self.assertNotIn("id-token", check)
        self.assertEqual(len(re.findall(r"id-token: write", image)), 1)
        self.assertEqual(len(re.findall(r"contents: read", self.code)), 3)

    def test_only_the_publishing_job_publishes_and_only_from_main(self) -> None:
        check, image = self.code.split("  image:")
        self.assertNotIn("publish", check.replace("Publishing", ""))
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", image)
        self.assertEqual(image.count(".github/scripts/publish/publish.sh"), 1)

    def test_labels_and_prefix_come_from_repository_variables(self) -> None:
        self.assertIn("runs-on: ${{ vars.CI_POOL_LABEL }}", self.code)
        self.assertIn("runs-on: ${{ vars.CI_PUBLISH_LABEL }}", self.code)
        self.assertIn("AUDIENCE_PREFIX: ${{ vars.CI_AUDIENCE_PREFIX }}", self.code)
        self.assertNotRegex(self.code, r"runs-on: \[")

    def test_publishing_goes_through_the_helper_with_its_contract_inputs(self) -> None:
        for name in ("WORKLOAD", "AUDIENCE_PREFIX", "CI_WORKFLOW", "ORAS_VERSION", "ORAS_SHA256"):
            self.assertRegex(self.code, rf"(?m)^\s+{name}: ")
        for forbidden in ("DEPLOY_KEY", "deploy-key", "ssh-key", "secrets.", "docker push"):
            self.assertNotIn(forbidden, self.text)
        scripts = REPOSITORY_ROOT / ".github" / "scripts"
        self.assertEqual(sorted(p.name for p in scripts.iterdir()), ["publish"])

    def test_the_vendored_helper_attests_and_retries_the_platform_calls(self) -> None:
        script = PUBLISH.read_text(encoding="utf-8")
        self.assertIn("application/vnd.hostplane.ci-oidc.v1+jwt", script)
        self.assertIn("::add-mask::", script)
        self.assertIn("--retry-connrefused", script)
        self.assertIn("RELEASE_BRANCH_REF:-refs/heads/main", script)

    def test_actions_are_pinned_to_a_commit(self) -> None:
        for use in re.findall(r"uses: (\S+)", self.code):
            self.assertRegex(use, r"@[0-9a-f]{40}$")


class NightlyWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = NIGHTLY.read_text(encoding="utf-8")
        cls.code = "\n".join(
            line for line in cls.text.splitlines() if not line.lstrip().startswith("#")
        )

    def test_runs_on_a_schedule_and_on_demand_never_on_pull_requests(self) -> None:
        self.assertRegex(self.code, r"schedule:\n\s+- cron: ")
        self.assertIn("workflow_dispatch:", self.code)
        for forbidden in ("pull_request", "push:"):
            self.assertNotIn(forbidden, self.code)

    def test_runs_the_whole_ci_check_on_the_shared_pool_without_a_token(self) -> None:
        self.assertIn("runs-on: ${{ vars.CI_POOL_LABEL }}", self.code)
        self.assertRegex(self.code, r"dekk agents ci\b")
        self.assertNotIn("id-token", self.code)
        self.assertIn("contents: read", self.code)
        self.assertNotIn("publish", self.code)

    def test_a_run_is_never_cancelled_and_its_group_differs_from_the_push_check(self) -> None:
        self.assertIn("cancel-in-progress: false", self.code)
        self.assertIn("group: apxm-nightly", self.code)

    def test_stores_nothing_on_github_and_pins_actions(self) -> None:
        for forbidden in ("upload-artifact", "actions/cache", "ghcr.io", "ubuntu-latest", "secrets."):
            self.assertNotIn(forbidden, self.code)
        for use in re.findall(r"uses: (\S+)", self.code):
            self.assertRegex(use, r"@[0-9a-f]{40}$")

    def test_the_heavy_suites_are_a_subset_of_the_gate_and_the_fast_check_is_declared(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "gate_for_nightly", CI_PATH.with_name("service_gate.py")
        )
        gate = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = gate
        spec.loader.exec_module(gate)
        for name in gate.HEAVY_SERVICE_COMMANDS:
            self.assertIn(name, gate.SERVICE_GATE_COMMANDS)
        fast = [n for n, _ in gate.resolve_steps(
            gate.load_commands(), skip=gate.HEAVY_SERVICE_COMMANDS)]
        self.assertNotIn("test-source-port", fast)
        self.assertIn("clippy", fast)
        self.assertIn("commit-lint", fast)
        with DEKK_MANIFEST_PATH.open("rb") as handle:
            commands = tomllib.load(handle)["commands"]
        self.assertEqual(
            commands["check-service-fast"]["run"], "python tools/scripts/service_gate.py --fast"
        )
        self.assertIn("check-service", load_ci().CI_COMMANDS)


if __name__ == "__main__":
    unittest.main()
