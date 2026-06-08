"""Digest rendering + the inert scaffold generator (must emit valid Python)."""
from __future__ import annotations

import ast

from blastcontain_scout.analyze import Analysis
from blastcontain_scout.arxiv import Paper
from blastcontain_scout.render import (
    render_digest,
    render_scaffold,
    scaffold_filename,
    scaffold_relpath,
    slug,
)


def _analysis(kind="dataset", lic="unknown — verify before vendoring"):
    p = Paper(
        arxiv_id="2401.12345", title="A Universal Jailbreak", summary="new attack",
        published="2024-01-15", updated="2024-01-20", authors=["Jane Doe"],
        categories=["cs.CR"], abs_url="http://arxiv.org/abs/2401.12345v2",
    )
    return Analysis(
        paper=p, relevance=0.9, relevant=True, kind=kind,
        summary="a universal jailbreak for agents", suggested_category="jailbreak",
        artifact_url="https://github.com/foo/bar", license_note=lic,
        rationale="clear", scored_by="llm",
    )


def test_slug_and_filename():
    assert slug("2401.12345") == "c_2401_12345"
    assert scaffold_filename(_analysis()) == "c_2401_12345.py"


def test_scaffold_is_valid_python_and_inert():
    src = render_scaffold(_analysis())
    compile(src, "c_2401_12345.py", "exec")     # must parse
    assert "return False" in src                 # is_available() inert
    assert "2401.12345" in src
    assert "AttackSource" in src
    # absolute import so the scaffold is valid at any contrib/ nesting depth
    assert "from blastcontain_drill.corpus.base import" in src


def test_scaffold_resists_code_injection():
    # arXiv is open submission: a hostile paper could carry a docstring-breakout
    # payload in any free-text field. The scaffold must treat all of it as data.
    payload = 'Pwned """\nimport os\nos.system("touch /tmp/pwned")\nINJECTED = """'
    p = Paper(
        arxiv_id="2401.99999", title=payload, summary="abs",
        published="2024-01-01", updated="2024-01-01",
        authors=['Eve """\nEVIL = 1\n"""'], categories=["cs.CR"],
        abs_url='http://arxiv.org/abs/2401.99999"""\nBAD = 1',
    )
    a = Analysis(
        paper=p, relevance=0.9, relevant=True, kind="dataset",
        summary='sum """\nimport sys', suggested_category="jailbreak",
        artifact_url=None, license_note='MIT """\nNOPE = 1', rationale="", scored_by="llm",
    )
    src = render_scaffold(a)
    tree = ast.parse(src)                        # still valid Python after the payload

    # The payload must NOT have escaped into executable code: no import/usage of `os`
    # and no module-level call statements should exist anywhere in the AST.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [getattr(node, "module", None)] + [n.name for n in node.names]
            assert "os" not in mods and "sys" not in mods
        assert not (isinstance(node, ast.Attribute) and node.attr == "system")
    assert not any(isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                   for n in tree.body)          # no top-level call broke out

    # And the hostile text survives intact as data inside the PAPER dict.
    paper_dict = next(
        ast.literal_eval(n.value) for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "PAPER" for t in n.targets)
    )
    assert paper_dict["title"] == payload
    assert paper_dict["authors"] == ['Eve """\nEVIL = 1\n"""']


def test_scaffold_relpath_buckets_by_source_and_month():
    # arxiv/<YYYY-MM>/c_<id>.py — keeps any one directory small as the corpus grows
    assert scaffold_relpath(_analysis(), "arxiv") == "arxiv/2024-01/c_2401_12345.py"


def test_digest_groups_and_flags_license():
    md = render_digest([_analysis("dataset"), _analysis("intel")], "2026-06-02")
    assert "# Corpus Scout digest" in md
    assert "Datasets" in md
    assert "arXiv:2401.12345" in md
    assert "License watch" in md                 # unknown license -> flagged


def test_digest_omits_irrelevant():
    a = _analysis()
    a.relevant = False
    md = render_digest([a], "2026-06-02")
    assert "0 relevant new paper" in md
