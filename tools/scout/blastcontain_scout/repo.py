"""
Git / GitHub plumbing — turn a scout run into a draft PR.

Default mode is a dry-run preview (no writes, no git). With --apply it creates a
branch, writes the digest + inert scaffolds, and commits; with --open-pr it also
runs `gh pr create`. The scout never pushes to a protected branch and never merges
— a human reviews the PR (derive-then-ratify).
"""
from __future__ import annotations

import os
import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path


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
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding='utf-8')


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
    rel_paths = [Path(os.path.relpath(f.path, root)).as_posix() for f in plan.files]
    identity = hashlib.sha256(json.dumps(asdict(plan), sort_keys=True).encode()).hexdigest()
    marker = 'blastcontain-scout.plan-' + identity
    previous = _run(['git', 'config', '--local', '--get', marker], root)
    status = _run(['git', 'status', '--porcelain', '-z'], root)
    if status.returncode:
        return {'ok': False, 'step': 'status', 'error': status.stderr.strip()}
    base = previous.stdout.strip()
    committed = False
    if base:
        branch = _run(['git', 'branch', '--show-current'], root).stdout.strip()
        entries = [s for s in status.stdout.split('\0') if s]
        if branch != plan.branch or any(s[3:] not in rel_paths or 'R' in s[:2] or 'C' in s[:2]
                                        for s in entries):
            return {'ok': False, 'step': 'resume', 'error': 'Pending proposal requires its original branch and no unrelated changes'}
        # Never overwrite edits made since a failed attempt.
        for file in plan.files:
            path = Path(file.path)
            if path.is_symlink() or (path.exists() and path.read_text(encoding='utf-8') != file.content):
                return {'ok': False, 'step': 'resume', 'error': 'Pending proposal files changed; restore or review them before retrying'}
        head = _run(['git', 'rev-parse', 'HEAD'], root).stdout.strip()
        if head != base:
            parent = _run(['git', 'rev-parse', 'HEAD^'], root).stdout.strip()
            message = _run(['git', 'log', '-1', '--format=%B'], root).stdout.strip()
            changed = _run(['git', 'diff', '--name-only', base, 'HEAD'], root).stdout.splitlines()
            if (parent != base or message != plan.commit_message or status.stdout
                    or not set(changed) <= set(rel_paths) or not all(Path(f.path).is_file() for f in plan.files)):
                return {'ok': False, 'step': 'resume', 'error': 'Branch no longer matches the recorded proposal commit'}
            committed = True
    else:
        if status.stdout:
            return {'ok': False, 'step': 'status', 'error': 'Commit or stash existing changes before publishing'}
        r = _run(['git', 'checkout', '-b', plan.branch, plan.base], root)
        if r.returncode:
            return {'ok': False, 'step': 'checkout', 'error': r.stderr.strip()}
        base = _run(['git', 'rev-parse', 'HEAD'], root).stdout.strip()
        r = _run(['git', 'config', '--local', marker, base], root)
        if r.returncode:
            return {'ok': False, 'step': 'checkpoint', 'error': r.stderr.strip()}

    if not committed:
        _write_files(plan.files)
        r = _run(["git", "add", *rel_paths], root)
        if r.returncode != 0:
            return {"ok": False, "step": "add", "error": r.stderr.strip()}
        r = _run(["git", "commit", "-m", plan.commit_message], root)
        if r.returncode != 0:
            return {"ok": False, "step": "commit", "error": r.stderr.strip()}

    result = {"ok": True, "branch": plan.branch, "committed": rel_paths, "pr": None,
              'commit': _run(['git', 'rev-parse', 'HEAD'], root).stdout.strip()}

    if open_pr:
        # Push then open the PR via gh.
        rp = _run(["git", "push", "-u", "origin", plan.branch], root)
        if rp.returncode != 0:
            result["pr_error"] = f"push failed: {rp.stderr.strip()}"
            return result
        existing = _run(['gh', 'pr', 'list', '--head', plan.branch, '--base', plan.base,
                         '--state', 'open', '--json', 'url'], root)
        if existing.returncode == 0:
            matches = json.loads(existing.stdout)
            if len(matches) == 1:
                result['pr'] = matches[0]['url']
                return result
        with tempfile.TemporaryDirectory(prefix='scout-pr-') as tmp:
            body = Path(tmp) / 'body.md'
            body.write_text(plan.pr_body, encoding='utf-8')
            rg = _run(
                ["gh", "pr", "create", "--draft", "--title", plan.pr_title,
                 "--body-file", str(body), "--base", plan.base, '--head', plan.branch],
                root,
            )
        if rg.returncode == 0:
            result["pr"] = rg.stdout.strip()
        else:
            result["pr_error"] = rg.stderr.strip()
    return result
