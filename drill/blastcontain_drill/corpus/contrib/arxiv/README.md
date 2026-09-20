# Scout arXiv proposals

Scout writes inactive candidate sources under `<YYYY-MM>/c_<arxiv_id>.py`.
They are excluded from Drill wheels and do not become available until reviewed.
The paper ID in `PAPER["arxiv_id"]` is the join key to Scout's research database.

After review, implement a source under `corpus/arxiv/` (or extend an existing
source), register it explicitly in `corpus/__init__.py`, add tests and update
`corpus/arxiv/registry.json`. A proposal file is not an implemented attack.
