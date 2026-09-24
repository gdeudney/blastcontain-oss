"""Read committed research mappings and trace exact Drill identities without executing code.

This optional feature uses the installed Drill contracts. Ordinary Scout scanning
and database recovery do not require Drill.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Literal

from blastcontain_drill.contracts import AcceptanceRecord, ContractError, PluginManifest
from blastcontain_drill.contracts.wire import WireRecord, require_text, unique
from blastcontain_drill.plugins.catalog import check_acceptance, parse_json, review_digest
from blastcontain_drill.suites.artifacts import digest
from blastcontain_drill.suites.catalog import SourceSnapshot
from blastcontain_drill.suites.planner import accepted

MAX_BLOB = 2 * 1024 * 1024


def revision(value):
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
        raise ContractError("Expected a full Git commit ID")


def relative_path(value):
    path = PurePosixPath(value)
    if (
        not value
        or not path.parts
        or str(path) != value
        or path.is_absolute()
        or ":" in value
        or "\\" in value
        or any(p in (".", "..", ".git") for p in path.parts)
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ContractError("Expected a normalized repository-relative file path")


@dataclass(frozen=True)
class PaperRef(WireRecord):
    id: str
    fingerprint: str

    def validate(self):
        if not re.fullmatch(r"\d{4}\.\d{4,5}", self.id) or not re.fullmatch(
            r"[0-9a-f]{64}", self.fingerprint
        ):
            raise ContractError("Expected an arXiv ID and exact Scout metadata fingerprint")


@dataclass(frozen=True)
class ArtifactRef(WireRecord):
    path: str
    sha256: str
    kind: Literal["code", "validation", "license", "reproduction_protocol"]

    def validate(self):
        relative_path(self.path)
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ContractError("Expected a file SHA-256")


@dataclass(frozen=True)
class CoverageReview(WireRecord):
    actor: str
    rationale: str
    content_license: str
    license_status: Literal["reviewed", "unresolved", "incompatible"]

    def validate(self):
        for value in (self.actor, self.rationale, self.content_license):
            require_text(value, "review field")


@dataclass(frozen=True)
class ResearchMap(WireRecord):
    id: str
    papers: tuple[PaperRef, ...]
    source: SourceSnapshot
    plugins: tuple[PluginManifest, ...]
    scenario_ids: tuple[str, ...]
    code_revision: str
    files: tuple[ArtifactRef, ...]
    coverage: Literal[
        "dataset_only", "partial_method", "research_informed_examples", "full_reproduction"
    ]
    limitations: str
    review: CoverageReview
    acceptances: tuple[AcceptanceRecord, ...]
    schema_version: Literal[1] = 1

    def validate(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.id):
            raise ContractError("Expected a symbolic mapping ID")
        revision(self.code_revision)
        require_text(self.limitations, "coverage limitations")
        if not 1 <= len(self.papers) <= 32 or not 1 <= len(self.files) <= 128:
            raise ContractError("Mapping needs 1–32 papers and 1–128 artifact files")
        unique(tuple(p.id for p in self.papers), "paper IDs")
        unique(tuple(f.path for f in self.files), "artifact paths")
        unique(tuple(p.id for p in self.plugins), "plugin IDs")
        unique(self.scenario_ids, "scenario IDs")
        if not self.scenario_ids or not set(self.scenario_ids) <= {
            s.id for s in self.source.scenarios
        }:
            raise ContractError("Mapping must name existing source scenarios")
        kinds = {f.kind for f in self.files}
        if not {"code", "validation", "license"} <= kinds:
            raise ContractError("Mapping needs code, validation and license artifacts")
        if self.coverage == "full_reproduction" and "reproduction_protocol" not in kinds:
            raise ContractError(
                "Full reproduction requires a separately reviewed comparison protocol"
            )
        if any(r.kind == "suite" for r in self.acceptances):
            raise ContractError(
                "Suite acceptance belongs to its own exact plan, not the research map"
            )


class GitObjects:
    """Bounded local Git object reads; no checkout, fetch, hooks or plugin imports."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.key = hashlib.sha256(
            self.run("rev-parse", "--path-format=absolute", "--git-common-dir").strip()
        ).hexdigest()

    def run(self, *args, allowed=(0,)):
        result = subprocess.run(
            ["git", "--no-replace-objects", "--literal-pathspecs", "-C", str(self.root), *args],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if result.returncode not in allowed:
            raise ContractError("Requested local Git object or revision is unavailable")
        return result.stdout

    def commit(self, ref):
        value = (
            self.run("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
            .decode()
            .strip()
        )
        revision(value)
        return value

    def ancestor(self, older, newer):
        revision(older)
        revision(newer)
        result = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "--literal-pathspecs",
                "-C",
                str(self.root),
                "merge-base",
                "--is-ancestor",
                older,
                newer,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if result.returncode not in (0, 1):
            raise ContractError("Cannot determine local Git ancestry")
        return result.returncode == 0

    def blob(self, commit, path):
        revision(commit)
        relative_path(path)
        tree = self.run("ls-tree", "-z", commit, "--", path)
        if not tree or tree.split(b" ", 1)[0] not in (b"100644", b"100755"):
            raise ContractError("Artifact must be a regular committed file")
        name = commit + ":" + path
        size = int(self.run("cat-file", "-s", name))
        if not 0 <= size <= MAX_BLOB:
            raise ContractError("Git artifact exceeds 2 MiB")
        data = self.run("cat-file", "blob", name)
        if len(data) != size:
            raise ContractError("Git artifact size changed")
        return data


def inspect_mapping(root, commit, path, tracker, *, main_ref="origin/main"):
    git = GitObjects(root)
    revision(commit)
    main = git.commit(main_ref)
    raw = git.blob(commit, path)
    mapping = ResearchMap.from_dict(parse_json(raw))
    diagnostics = []
    if not git.ancestor(commit, main):
        diagnostics.append("mapping_unmerged")
    if not git.ancestor(mapping.code_revision, commit):
        diagnostics.append("code_revision_not_in_mapping_history")
    try:
        if git.blob(main, path) != raw:
            diagnostics.append("current_manifest_changed")
    except ContractError:
        diagnostics.append("current_manifest_missing")
    artifacts = []
    for artifact in mapping.files:
        observed = hashlib.sha256(git.blob(mapping.code_revision, artifact.path)).hexdigest()
        if observed != artifact.sha256:
            raise ContractError("Declared artifact digest does not match its Git revision")
        try:
            current = hashlib.sha256(git.blob(main, artifact.path)).hexdigest()
        except ContractError:
            current = None
        if current != artifact.sha256:
            diagnostics.append("current_artifact_changed:" + artifact.path)
        artifacts.append({**artifact.to_dict(), "current_sha256": current})
    paper_state = {p["id"]: p for p in tracker.snapshot()["papers"]}
    papers = []
    for paper in mapping.papers:
        state = paper_state.get(paper.id)
        current = state and state["fingerprint"] == paper.fingerprint
        if not current:
            diagnostics.append("paper_metadata_unknown_or_changed:" + paper.id)
        if state and state["review_stale"]:
            diagnostics.append("paper_review_stale:" + paper.id)
        if state and state["review_status"] == "rejected":
            diagnostics.append("paper_review_rejected:" + paper.id)
        papers.append(
            {
                **paper.to_dict(),
                "metadata_current": bool(current),
                "review_status": state["review_status"] if state else None,
                "review_stale": state["review_stale"] if state else None,
            }
        )
    if mapping.review.license_status != "reviewed":
        diagnostics.append("license_" + mapping.review.license_status)
    try:
        accepted(mapping.acceptances, "content", mapping.source.id, mapping.source.content_digest)
    except ContractError:
        diagnostics.append("content_acceptance_missing_stale_or_revoked")
    for plugin in mapping.plugins:
        try:
            check_acceptance(plugin, mapping.acceptances)
        except ContractError:
            diagnostics.append("plugin_acceptance_missing_stale_or_revoked:" + plugin.id)
    return {
        "schema_version": 1,
        "repo_key": git.key,
        "mapping_id": mapping.id,
        "mapping_commit": commit,
        "manifest_path": path,
        "manifest_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "main_commit": main,
        "code_revision": mapping.code_revision,
        "papers": papers,
        "coverage": mapping.coverage,
        "limitations": mapping.limitations,
        "source_id": mapping.source.id,
        "source_content_digest": mapping.source.content_digest,
        "source_code_digest": mapping.source.code_digest,
        "source_revision": mapping.source.revision,
        "scenario_ids": list(mapping.scenario_ids),
        "plugins": [
            {
                "id": p.id,
                "review_digest": review_digest(p),
                "license": p.license,
                "artifact_digest": p.artifact_digest,
                "roles": list(p.roles),
            }
            for p in mapping.plugins
        ],
        "review": mapping.review.to_dict(),
        "acceptances": [a.to_dict() for a in mapping.acceptances],
        "artifacts": artifacts,
        "diagnostics": sorted(set(diagnostics)),
        "git_and_reviews_current": not diagnostics,
        "validation_evidence": "committed_records_not_independently_rerun",
    }


def refresh_mapping(tracker, report, *, actor, expected_revision):
    """Append a checked workflow snapshot; never grant or change Drill acceptance."""
    require_text(actor, "refresh actor")
    if type(expected_revision) is not int or expected_revision < 0:
        raise ContractError("Explicit nonnegative database revision is required")
    encoded = json.dumps(report, sort_keys=True)
    report = json.loads(encoded)
    with tracker._write(expected_revision):
        old = latest_mappings(tracker, repo_key=report["repo_key"]).get(report["mapping_id"])
        if old == report:
            return False
        papers = {p["id"] for p in report["papers"]}
        if old:
            papers |= {p["id"] for p in old["papers"]}
        for pid in papers:
            row = tracker.db.execute("SELECT fingerprint FROM papers WHERE id=?", (pid,)).fetchone()
            if row is None:
                raise ContractError("Import all cited Scout metadata before refreshing provenance")
            current = next((p for p in report["papers"] if p["id"] == pid), None)
            if current and bool(row[0] == current["fingerprint"]) != current["metadata_current"]:
                raise ContractError("Paper metadata changed while inspecting provenance; reload")
        for pid in sorted(papers):
            tracker._event(pid, "artifact_refresh", {"actor": actor, "report": json.loads(encoded)})
    return True


def latest_mappings(tracker, *, repo_key):
    result = {}
    for row in tracker.db.execute(
        "SELECT data FROM events WHERE action='artifact_refresh' ORDER BY id"
    ):
        report = json.loads(row[0])["report"]
        if report["repo_key"] == repo_key:
            result[report["mapping_id"]] = report
    return result


def trace_lock(lock, reports, *, verification=None, paper_id=None):
    """Join exact accepted lock identities; verification comes from Drill's verifier."""
    lock.to_dict()
    if verification and verification.run and verification.run.lock_digest != lock.lock_digest:
        raise ContractError("Verified run does not match the supplied lock")
    identities = {(i.kind, i.id): i for i in lock.plan.identities}
    rows = []
    for case in lock.plan.cases:
        matches = []
        identity = identities.get(("external_source", case.source_id)) or identities.get(
            ("builtin_source", case.source_id)
        )
        for report in reports:
            if paper_id and paper_id not in {p["id"] for p in report["papers"]}:
                continue
            if (
                report["source_id"] != case.source_id
                or case.scenario_id not in report["scenario_ids"]
            ):
                continue
            matched = bool(
                identity
                and identity.content_digest == report["source_content_digest"]
                and identity.artifact_digest == report["source_code_digest"]
                and identity.revision == report["source_revision"]
            )
            for plugin in report["plugins"]:
                current = identities.get(("plugin", plugin["id"]))
                matched = matched and bool(
                    current
                    and current.content_digest == plugin["review_digest"]
                    and current.artifact_digest == plugin["artifact_digest"]
                )
                if "attack_strategy" in plugin["roles"]:
                    matched = matched and case.strategy == plugin["id"]
            matches.append(
                {
                    "mapping_id": report["mapping_id"],
                    "mapping_commit": report["mapping_commit"],
                    "code_revision": report["code_revision"],
                    "checked_main_commit": report["main_commit"],
                    "papers": report["papers"],
                    "coverage": report["coverage"],
                    "limitations": report["limitations"],
                    "identity_matches": matched,
                    "git_and_reviews_current": report["git_and_reviews_current"],
                    "review": report["review"],
                    "artifacts": report["artifacts"],
                    "diagnostics": report["diagnostics"],
                }
            )
        if not paper_id or matches:
            result = (
                next((r for r in verification.run.cases if r.case_id == case.id), None)
                if verification and verification.run
                else None
            )
            rows.append(
                {
                    "case_id": case.id,
                    "source_id": case.source_id,
                    "scenario_id": case.scenario_id,
                    "plugin_id": case.strategy,
                    "mappings": matches,
                    "result": result.result.to_dict() if result and result.result else None,
                }
            )
    return {
        "schema_version": 1,
        "lock_digest": lock.lock_digest,
        "cases": rows,
        "run_id": verification.run_id if verification else None,
        "envelope_digest": verification.envelope_digest if verification else None,
        "run_trusted": verification.trusted if verification else False,
        "run_replayed": verification.replayed if verification else False,
        "run_security_passed": verification.security_passed if verification else None,
        "provenance_complete": bool(rows)
        and all(
            any(m["identity_matches"] and m["git_and_reviews_current"] for m in row["mappings"])
            for row in rows
        ),
        "provenance_digest": digest(rows),
    }
