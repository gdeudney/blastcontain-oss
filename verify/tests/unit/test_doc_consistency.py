"""Doc/code drift guards.

Facts asserted in prose (check counts, version strings) rot silently in a
single-maintainer repo — the hardcoded generator_version bug and the
"27 checks across 14 categories" claim are the same failure mode. These tests
pin every duplicated fact to its single source of truth in code, so a PR that
adds a check or bumps a version with stale docs fails CI naming the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from blastcontain_verify import __version__
from blastcontain_verify.constants import ALL_CHECK_IDS
from blastcontain_verify.reporter import _group_of

VERIFY_ROOT = Path(__file__).parents[2]
SPEC = (VERIFY_ROOT / "docs" / "spec.md").read_text(encoding="utf-8")
README = (VERIFY_ROOT / "README.md").read_text(encoding="utf-8")
PYPROJECT = (VERIFY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
CHANGELOG = (VERIFY_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


class TestCheckInventory:
    def test_spec_documents_exactly_the_implemented_checks(self):
        """spec.md §5 has one `#### <ID>` section per check — no more, no less."""
        spec_ids = set(re.findall(r"^#### ([A-Z]+-\d+)", SPEC, flags=re.MULTILINE))
        missing = ALL_CHECK_IDS - spec_ids
        stale = spec_ids - ALL_CHECK_IDS
        assert not missing, f"Checks missing a spec.md section: {sorted(missing)}"
        assert not stale, f"spec.md documents nonexistent checks: {sorted(stale)}"

    def test_readme_check_and_category_counts(self):
        """README's 'N security checks across M categories' matches the inventory."""
        m = re.search(r"(\d+) security checks across (\d+) categories", README)
        assert m, "README no longer states 'N security checks across M categories'"
        claimed_checks, claimed_categories = int(m.group(1)), int(m.group(2))

        actual_categories = {_group_of(cid) for cid in ALL_CHECK_IDS}
        assert claimed_checks == len(ALL_CHECK_IDS), (
            f"README claims {claimed_checks} checks; code implements "
            f"{len(ALL_CHECK_IDS)} (constants.ALL_CHECK_IDS)"
        )
        assert claimed_categories == len(actual_categories), (
            f"README claims {claimed_categories} categories; reporter groups the "
            f"checks into {len(actual_categories)}: {sorted(actual_categories)}"
        )

    def test_every_check_id_maps_to_a_named_category(self):
        """No check ID falls through reporter._CHECK_GROUPS into 'Other'."""
        unmapped = {cid for cid in ALL_CHECK_IDS if _group_of(cid) == "Other"}
        assert not unmapped, f"Check IDs without a reporter group: {sorted(unmapped)}"


class TestVersionCoherence:
    def test_pyproject_matches_package_version(self):
        m = re.search(r'^version = "([^"]+)"', PYPROJECT, flags=re.MULTILINE)
        assert m, "pyproject.toml has no version field"
        assert m.group(1) == __version__, (
            f"pyproject.toml says {m.group(1)}, __init__.__version__ says {__version__}"
        )

    def test_changelog_has_entry_for_current_version(self):
        assert f"## [{__version__}]" in CHANGELOG, (
            f"CHANGELOG.md has no '## [{__version__}]' section — add one when bumping"
        )

    def test_audit_packet_generator_version_reads_package_version(self):
        """Regression pin for the hardcoded generator_version bug (fixed in 0.3.1)."""
        reporter_src = (
            VERIFY_ROOT / "blastcontain_verify" / "reporter.py"
        ).read_text(encoding="utf-8")
        assert '"generator_version"] = __version__' in reporter_src.replace("payload[", ""), (
            "reporter.write_audit_packet must set generator_version from __version__, "
            "not a literal"
        )
