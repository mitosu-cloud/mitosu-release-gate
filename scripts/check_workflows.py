#!/usr/bin/env python3
"""Fail closed if a workflow weakens the public release-gate boundary."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
APPROVAL_WORKFLOWS = {
    "authorize-release.yml": "agent-release-approve",
    "authorize-promotion.yml": "agent-release-promote",
}
EXPECTED_WORKFLOWS = set(APPROVAL_WORKFLOWS) | {"ci.yml"}
PINNED_ACTION = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    print(f"release-gate invariant failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def action_references(text: str) -> list[str]:
    return re.findall(r"^\s*-?\s*uses:\s*([^#\s]+)", text, flags=re.MULTILINE)


def check_pinned_actions(name: str, text: str) -> None:
    for reference in action_references(text):
        if "@" not in reference:
            fail(f"{name} has an action without a ref: {reference}")
        action, revision = reference.rsplit("@", 1)
        if action.startswith("./"):
            continue
        if not PINNED_ACTION.fullmatch(revision):
            fail(f"{name} action is not pinned to a full commit: {reference}")


def check_approval_workflow(name: str, environment: str, text: str) -> None:
    forbidden = (
        "pull_request:",
        "pull_request_target:",
        "schedule:",
        "repository_dispatch:",
        "secrets.",
        "ubuntu-latest",
        "oidc.jwt",
    )
    for value in forbidden:
        if value in text:
            fail(f"{name} contains forbidden approval-runner text: {value}")
    required = (
        "workflow_dispatch:",
        "id-token: write",
        "contents: read",
        f"environment: {environment}",
        "group: release-approval",
        "mitosu-release-gate",
        "persist-credentials: false",
        "inputs.controller_request_id",
        "seal_oidc_authorization.py",
        "authorization/authorization.cms",
        "retention-days: 1",
    )
    for value in required:
        if value not in text:
            fail(f"{name} is missing required boundary: {value}")


def check_ci_workflow(text: str) -> None:
    required = (
        "pull_request:",
        "contents: read",
        "group: public-gate-ci",
        "mitosu-public-gate-ci",
        "self-hosted",
    )
    for value in required:
        if value not in text:
            fail(f"ci.yml is missing: {value}")
    for value in ("id-token: write", "release-approval", "mitosu-release-gate", "secrets."):
        if value in text:
            fail(f"ci.yml reaches a privileged boundary: {value}")


def main() -> None:
    actual = {path.name for path in WORKFLOW_DIRECTORY.glob("*.yml")}
    if actual != EXPECTED_WORKFLOWS:
        fail(f"unexpected workflow set: {sorted(actual)}")

    for name in sorted(actual):
        text = (WORKFLOW_DIRECTORY / name).read_text(encoding="utf-8")
        check_pinned_actions(name, text)
        if name in APPROVAL_WORKFLOWS:
            check_approval_workflow(name, APPROVAL_WORKFLOWS[name], text)
        else:
            check_ci_workflow(text)

    policy = (ROOT / "policy" / "release-gate-v1.json").read_text(encoding="utf-8")
    for name, environment in APPROVAL_WORKFLOWS.items():
        if name not in policy or environment not in policy:
            fail(f"policy does not bind {name} to {environment}")

    print("release-gate workflow invariants passed")


if __name__ == "__main__":
    main()
