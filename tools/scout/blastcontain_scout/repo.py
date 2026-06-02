"""
Git / GitHub plumbing — turn a scout run into a draft PR.

Default mode is a dry-run preview (no writes, no git). With --apply it creates a
branch, writes the digest + inert scaffolds, and commits; with --open-pr it also
runs `gh pr create`. The scout never pushes to a protected branch and never merges
— a human reviews the PR (derive-then-ratify).
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field


@dataclass
class FileWrite:
    path: str        # absolute path
    content: str


@dataclass
class PublishPlan:
    branch: str
    base: str
    commit_message: str
    pr_title: str
    pr_body: str
    files: list[FileWrite] = field(default_factory=list)


def _run(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def preview(plan: PublishPlan, root: str) -> str:
    lines = [
        "DRY RUN — no files written, no git operations.",
        f"  base branch:  {plan.base}",
        f"  new branch:   {plan.branch}",
        f"  PR title:     {plan.pr_title}",
        f"  commit:       {plan.commit_message}",
        f"  files ({len(plan.files)}):",
    ]
    for f in plan.files:
        rel = os.path.relpath(f.path, root)
        lines.append(f"    + {rel}  ({len(f.content)} bytes)")
    lines += ["", "Re-run with --apply to write + commit, or --open-pr to also open the PR."]
    return "\n".join(lines)


def _write_files(files: list[FileWrite]) -> None:
    for f in files:
        parent = os.path.dirname(os.path.abspath(f.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(f.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f.content)


def publish(plan: PublishPlan, root: str, open_pr: bool) -> dict:
    """Create branch, write files, commit, optionally open a PR. Returns a result dict."""
    # Branch off base.
    r = _run(["git", "checkout", "-b", plan.branch], root)
    if r.returncode != 0:
        return {"ok": False, "step": "checkout", "error": r.stderr.strip()}

    _write_files(plan.files)

    rel_paths = [os.path.relpath(f.path, root) for f in plan.files]
    r = _run(["git", "add", *rel_paths], root)
    if r.returncode != 0:
        return {"ok": False, "step": "add", "error": r.stderr.strip()}

    r = _run(["git", "commit", "-m", plan.commit_message], root)
    if r.returncode != 0:
        return {"ok": False, "step": "commit", "error": r.stderr.strip()}

    result = {"ok": True, "branch": plan.branch, "committed": rel_paths, "pr": None}

    if open_pr:
        # Push then open the PR via gh.
        rp = _run(["git", "push", "-u", "origin", plan.branch], root)
        if rp.returncode != 0:
            result["pr_error"] = f"push failed: {rp.stderr.strip()}"
            return result
        rg = _run(
            ["gh", "pr", "create", "--title", plan.pr_title,
             "--body", plan.pr_body, "--base", plan.base],
            root,
        )
        if rg.returncode == 0:
            result["pr"] = rg.stdout.strip()
        else:
            result["pr_error"] = rg.stderr.strip()
    return result
