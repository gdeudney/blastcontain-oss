"""
BlastContain Scout — a separate, scheduled agent that scans arXiv for new
jailbreak / LLM-agent-attack research and opens *draft* pull requests proposing
additions to the Drill corpus.

It embodies the BlastContain "derive then ratify" tenet: the scout *derives*
candidate attacks (a new AttackSource or Operator scaffold + a digest); a human
*ratifies* by reviewing and merging the PR. It never auto-touches a security
corpus, and it flags dataset licenses so non-permissive sources are quarantined
as intel, not vendored.
"""

__version__ = "0.1.0"
