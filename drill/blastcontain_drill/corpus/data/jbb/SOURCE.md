# Vendored dataset — JailbreakBench / JBB-Behaviors

- **Source:** https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors (`data/{harmful,benign}-behaviors.csv`)
- **Upstream:** https://github.com/JailbreakBench/jailbreakbench (NeurIPS 2024)
- **License:** MIT (data + code) — permissive, ungated; safe to vendor in an Apache-2.0 package.
- **Pinned revision:** `886acc352a31533ffbcf4ef22c744658688086fc` (HF dataset commit; `JBB_REVISION = "886acc3"` in `corpus/jailbreakbench.py`, recorded in the signed report as `jailbreakbench@886acc3`). Reproducible fetch: `…/resolve/886acc352a31533ffbcf4ef22c744658688086fc/data/harmful-behaviors.csv`.
- **Vendored:** 2026-06-02 (100 harmful + 100 benign behaviors); unchanged upstream since 2024-09-26.
- **Schema:** `Index, Goal, Target, Behavior, Category, Source`.

The **benign** split is thematically paired with the harmful split: it lets Drill measure
**over-refusal / false-positives** (a refusal on a safe request) — a signal the action plane and the
hand-written seed corpus cannot express. Loaded by `corpus/jailbreakbench.py`. We take the data only;
the upstream Llama-Guard judge is not used (Drill has its own scorers).

To refresh: re-download both CSVs from the resolve URL above and overwrite in place.
