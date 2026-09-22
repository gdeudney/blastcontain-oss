"""Optional Scout operations; fixed operator-selected database and repository."""

from pathlib import Path

from ..contracts import ContractError


class Research:
    def __init__(self, database=None, repository=None):
        self.database = Path(database).absolute() if database else None
        self.repository = Path(repository).absolute() if repository else None
        if self.database is not None:
            # An explicit launch flag selects the writable review database.
            with self.tracker(readonly=False):
                pass

    def tracker(self, *, readonly=True):
        if self.database is None:
            raise ContractError("Start the workbench with an explicit Scout database")
        try:
            from blastcontain_scout.tracker import Tracker
        except ImportError:
            raise ContractError("Install Scout from the same supported checkout") from None
        return Tracker(self.database, readonly=readonly)

    def snapshot(self):
        if self.database is None:
            return {"available": False, "reason": "No Scout database was selected at launch"}
        with self.tracker() as tracker:
            snapshot = tracker.snapshot()
        return {
            "available": True,
            "revision": snapshot["revision"],
            "papers": snapshot["papers"],
            "implementations": snapshot["implementations"],
            "events": [
                {"paper_id": e["paper_id"], "action": e["action"], "recorded_at": e["recorded_at"]}
                for e in snapshot["events"]
            ],
        }

    def review(self, *, paper_id, status, actor, note, expected_revision):
        if type(expected_revision) is not int or expected_revision < 0:
            raise ContractError("Reload the current Scout revision before reviewing")
        if not all(type(v) is str for v in (paper_id, status, actor, note)):
            raise ContractError("Research review fields must be text")
        try:
            with self.tracker(readonly=False) as tracker:
                tracker.review(
                    paper_id, status, note, actor=actor, expected_revision=expected_revision
                )
        except ValueError as error:
            raise ContractError(str(error)) from None
        return self.snapshot()

    def mappings(self):
        if self.repository is None:
            raise ContractError("Start the workbench with an explicit research repository")
        from blastcontain_scout.provenance import GitObjects, inspect_mapping, latest_mappings

        with self.tracker() as tracker:
            tracker.db.execute("BEGIN")
            try:
                git = GitObjects(self.repository)
                main = git.commit("origin/main")
                saved = latest_mappings(tracker, repo_key=git.key)
                reports = [
                    inspect_mapping(
                        self.repository,
                        r["mapping_commit"],
                        r["manifest_path"],
                        tracker,
                        main_ref=main,
                    )
                    for r in saved.values()
                ]
                return {
                    "checked_main_commit": main,
                    "database_revision": tracker.revision,
                    "mappings": reports,
                    "database_divergence": [
                        r["mapping_id"]
                        for r in reports
                        if {k: v for k, v in r.items() if k != "main_commit"}
                        != {k: v for k, v in saved[r["mapping_id"]].items() if k != "main_commit"}
                    ],
                }
            finally:
                tracker.db.rollback()

    def trace(self, lock, verification):
        if self.database is None or self.repository is None:
            return {
                "available": False,
                "reason": "Scout database and repository are required for research tracing",
            }
        from blastcontain_scout.provenance import trace_lock

        mappings = self.mappings()
        return {
            "available": True,
            "checked_main_commit": mappings["checked_main_commit"],
            "database_revision": mappings["database_revision"],
            "database_divergence": mappings["database_divergence"],
            "trace": trace_lock(lock, mappings["mappings"], verification=verification),
        }
