"""
blastcontain-verify — pre-deployment compliance scanner for AI agents.

See: https://github.com/blastcontain/verify
"""
from __future__ import annotations

__version__ = "0.4.1"


def _harden_runtime_env() -> None:
    """
    Make the optional ML/NLP dependencies safe to import and run inside the
    hardened scan container (``--read-only`` root fs, no writable ``$HOME``,
    ``--network none``).

    The libraries pulled in by the ``[full]`` extra — presidio's URL
    recogniser (``tldextract``), ``litellm`` (the Cisco mcp/skill scanners),
    Hugging Face / ``onnxruntime`` — try to (a) write caches under
    ``~/.cache`` and (b) fetch resources over the network the first time they
    are used. In the hardened container ``$HOME`` is ``/home/verify`` on a
    read-only filesystem and there is no network, so those attempts raise
    (``OSError: Read-only file system`` / ``socket.gaierror``). Because these
    dependencies are unpinned, the resolved version combination decides
    whether that surfaces as harmless log noise or propagates out of a check
    and aborts the whole scan.

    We pre-empt it by pointing every cache at a writable directory (the
    ``/tmp`` tmpfs the hardened profile mounts ``rw``) and forcing offline
    mode — *before* any optional dependency is imported. Every value uses
    ``setdefault`` so an operator's own configuration always wins, and the
    cache base is writability-probed so nothing here can itself raise.
    """
    import os
    import tempfile

    def _writable(path: str) -> bool:
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".bc-write-probe")
            with open(probe, "w") as fh:
                fh.write("")
            os.remove(probe)
            return True
        except OSError:
            return False

    # First writable cache base: an operator override, then the real home
    # cache, then the temp dir (the hardened container's writable tmpfs).
    home = os.path.expanduser("~")
    candidates = [
        os.environ.get("XDG_CACHE_HOME"),
        os.path.join(home, ".cache") if home and home != "~" else None,
        os.path.join(tempfile.gettempdir(), "blastcontain-verify"),
    ]
    base = next((c for c in candidates if c and _writable(c)), None)
    if base is None:
        return  # nothing writable — leave the environment untouched

    os.environ.setdefault("XDG_CACHE_HOME", base)
    os.environ.setdefault("TLDEXTRACT_CACHE", os.path.join(base, "tldextract"))
    os.environ.setdefault("HF_HOME", os.path.join(base, "huggingface"))
    os.environ.setdefault("MPLCONFIGDIR", os.path.join(base, "matplotlib"))

    # Force offline / no-phone-home so a missing network degrades to bundled
    # data instead of a slow, failing fetch (and the read-only cache write
    # that often rides along with it).
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

    # NOTE: we deliberately do NOT override $HOME. Redirecting the per-library
    # caches above (which all honour these specific env vars) is enough, and
    # leaving $HOME pointing at the read-only /home/verify is what keeps PERM-01
    # correct — a writable home would be flagged as a writable persistence path.

    # presidio's URL recogniser (tldextract) still *attempts* the network on
    # first use and only then falls back to its bundled public-suffix
    # snapshot. Offline that attempt logs an alarming (but fully handled)
    # traceback. We expect it, so quiet those third-party loggers to keep the
    # scan output readable — the recognisers still degrade correctly.
    import logging

    for noisy in ("tldextract", "presidio-analyzer", "filelock"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)


_harden_runtime_env()

