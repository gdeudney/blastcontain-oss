"""arXiv Atom parsing + query building (model-free, fixture-based)."""
from __future__ import annotations

from blastcontain_scout.arxiv import build_query, parse_feed

FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <entry>
    <id>http://arxiv.org/abs/2401.12345v2</id>
    <updated>2024-01-20T00:00:00Z</updated>
    <published>2024-01-15T00:00:00Z</published>
    <title>A Universal Jailbreak Attack on LLM Agents</title>
    <summary>We introduce a new jailbreak technique and release a dataset at
      https://github.com/foo/bar with prompts that bypass guardrails.</summary>
    <author><name>Jane Doe</name></author>
    <author><name>John Roe</name></author>
    <category term="cs.CR"/>
    <category term="cs.CL"/>
    <link href="http://arxiv.org/abs/2401.12345v2" rel="alternate" type="text/html"/>
    <link title="pdf" href="http://arxiv.org/pdf/2401.12345v2" rel="related" type="application/pdf"/>
  </entry>
  <entry>
    <id>http://arxiv.org/abs/2402.00001v1</id>
    <updated>2024-02-01T00:00:00Z</updated>
    <published>2024-02-01T00:00:00Z</published>
    <title>On the Theory of Widgets</title>
    <summary>An unrelated paper about widgets and manufacturing.</summary>
    <author><name>A. Smith</name></author>
    <category term="cs.LG"/>
    <link title="pdf" href="http://arxiv.org/pdf/2402.00001v1" type="application/pdf"/>
  </entry>
</feed>"""


def test_parse_feed_normalizes_entries():
    papers = parse_feed(FEED)
    assert len(papers) == 2
    p = papers[0]
    assert p.arxiv_id == "2401.12345"          # version stripped
    assert p.title.startswith("A Universal Jailbreak")
    assert "release a dataset" in p.summary
    assert p.authors == ["Jane Doe", "John Roe"]
    assert "cs.CR" in p.categories
    assert p.pdf_url.endswith("2401.12345v2")


def test_parse_feed_handles_garbage():
    assert parse_feed("not xml") == []


def test_parse_feed_rejects_xxe_entities():
    # The arXiv feed is untrusted network input. defusedxml must refuse to expand
    # an external-entity (XXE) payload, and parse_feed must degrade to "no papers"
    # rather than read the file or crash the run.
    xxe = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE feed [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        '<feed xmlns="http://www.w3.org/2005/Atom">\n'
        "  <entry><id>http://arxiv.org/abs/1</id><title>&xxe;</title></entry>\n"
        "</feed>"
    )
    assert parse_feed(xxe) == []


def test_build_query_has_categories_and_terms():
    q = build_query()
    assert "cat:cs.CR" in q
    assert "abs:jailbreak" in q
    assert 'abs:"prompt injection"' in q
    assert " AND " in q
