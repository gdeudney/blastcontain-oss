"""
BlastContain Verify — tool-specific constants.

Verify-only constants live here (secret patterns, code patterns, file
extensions, capability bit positions, persistence paths). Shared types
that other BlastContain tools also need — MIT_RISK_MAP, TIER_BLAST_WEIGHTS
— live in `blastcontain_core.constants` and are re-exported here so
existing imports inside this package keep working unchanged.
"""
from __future__ import annotations
import os
import sys

# Re-export shared primitives from core for backwards compatibility.
from blastcontain_core.constants import MIT_RISK_MAP, TIER_BLAST_WEIGHTS  # noqa: F401


# ── Credential secret names to flag in files and process environment ───────────
SECRET_ENV_NAMES: frozenset[str] = frozenset({
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "GH_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID",
    "DATABASE_PASSWORD", "DB_PASSWORD", "DATABASE_URL", "SECRET_KEY", "API_KEY",
    "PRIVATE_KEY", "SLACK_TOKEN", "SLACK_BOT_TOKEN", "DISCORD_TOKEN",
    "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN", "STRIPE_SECRET_KEY",
    "GOOGLE_API_KEY", "GOOGLE_CLOUD_API_KEY", "HUGGINGFACE_API_KEY",
    "COHERE_API_KEY", "MISTRAL_API_KEY", "TOGETHER_API_KEY",
    "PINECONE_API_KEY", "WEAVIATE_API_KEY", "REDIS_PASSWORD",
})

SECRET_VALUE_PREFIXES: tuple[str, ...] = (
    "ghp_", "ghs_", "gho_", "ghr_",    # GitHub tokens
    "sk-ant-",                           # Anthropic
    "sk-",                               # OpenAI
    "xoxb-", "xoxp-", "xoxa-",         # Slack
    "AKIA", "ASIA",                      # AWS key IDs
    "AIza",                              # Google
    "hf_",                               # HuggingFace
)

SECRET_SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".yaml", ".yml", ".json", ".conf", ".config", ".cfg",
    ".ini", ".toml", ".properties", ".xml", ".sh", ".bash", ".zsh",
    ".tf", ".tfvars",
})

# Filenames to always scan regardless of extension.
# Note: pathlib Path('.env').suffix == '' so .env files won't match by extension.
SECRET_SCAN_FILENAMES: frozenset[str] = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    "credentials", ".credentials", "secrets", ".netrc", ".pgpass",
})

SECRET_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".eggs",
})


# ── Dangerous code patterns ────────────────────────────────────────────────────
# (regex_pattern, human_readable_label, severity)
CODE_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    (r"\beval\s*\(",                    "eval() — arbitrary code execution"),
    (r"\bexec\s*\(",                    "exec() — arbitrary code execution"),
    (r"os\.system\s*\(",               "os.system() — shell command execution"),
    (r"subprocess[.\w]*\(.*shell\s*=\s*True", "subprocess with shell=True"),
    (r"__import__\s*\(",               "__import__() — dynamic import"),
]

CODE_HIGH_PATTERNS: list[tuple[str, str]] = [
    (r"pickle\.loads?\s*\(",           "pickle.load() — insecure deserialization"),
    # Flag yaml.load(...) ONLY when no Loader= is passed. The [^)] class spans
    # newlines, so multi-line calls are matched; the negative lookahead lets a
    # safe `yaml.load(f, Loader=yaml.SafeLoader)` pass without a finding.
    (r"yaml\.load\s*\((?![^)]*Loader\s*=)[^)]*\)", "yaml.load() without Loader — use yaml.safe_load()"),
    (r"marshal\.loads?\s*\(",          "marshal.load() — insecure deserialization"),
    (r"jsonpickle\.decode\s*\(",       "jsonpickle.decode() — insecure deserialization"),
]

CODE_SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".mjs", ".cjs",
    ".rb", ".go", ".java", ".cs", ".php",
    ".sh", ".bash",
})

# Directories skipped during code pattern scanning.
# Includes the blastcontain packages themselves so the scanner
# does not flag its own pattern definitions as findings.
# Test directories are excluded because they intentionally contain
# dangerous patterns as fixtures — deployed agents should not have tests.
CODE_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".eggs",
    # test directories — intentional dangerous patterns as fixtures
    "tests", "test", "__tests__", "spec",
    # blastcontain packages — skip own source to prevent self-detection
    "blastcontain_verify", "blastcontain_drill", "blastcontain_discovery",
})


# ── MCP dangerous capability combinations ─────────────────────────────────────
MCP_CAPABILITY_CATEGORIES: dict[str, frozenset[str]] = {
    "Read": frozenset({
        "read_file", "read", "list_dir", "list_directory", "get_object",
        "query_db", "query", "search", "fetch", "get", "retrieve", "download",
        "cat", "ls", "find", "stat",
    }),
    "Execute": frozenset({
        "exec", "execute", "shell_exec", "shell", "run_command", "run",
        "eval", "execute_script", "bash", "sh", "cmd", "terminal",
        "subprocess", "spawn",
    }),
    "Send": frozenset({
        "http_post", "send_email", "email", "upload_file", "upload",
        "s3_put", "put_object", "webhook", "notify", "send_message",
        "post", "publish", "emit", "data_export",
    }),
    "Write": frozenset({
        "write_file", "write", "delete_file", "delete", "remove",
        "insert_db", "insert", "update_db", "update",
        "create_file", "mkdir", "truncate",
    }),
    "Credential": frozenset({
        "get_secret", "read_env", "aws_credentials", "oauth_token",
        "get_credentials", "read_secret", "fetch_token", "get_token",
        "credentials", "secrets",
    }),
}

# (cat_a, cat_b, attack_pattern, severity)
MCP_DANGEROUS_PAIRS: list[tuple[str, str, str, str]] = [
    ("Read",       "Send",       "Read data then exfiltrate it via send tool",        "CRITICAL"),
    ("Credential", "Send",       "Read credentials then exfiltrate them",             "CRITICAL"),
    ("Execute",    "Write",      "Execute payload then persist binary to disk",        "CRITICAL"),
    ("Read",       "Execute",    "Read attacker-controlled file then execute it",      "CRITICAL"),
    ("Write",      "Execute",    "Drop binary to disk then execute it",               "CRITICAL"),
    ("Read",       "Write",      "Read data then corrupt or overwrite it",            "HIGH"),
]


# ── Exfiltration-capable skill tool name patterns ──────────────────────────────
EXFIL_SKILL_PATTERNS: list[str] = [
    "http_post", "post_request", "send_email", "email", "exec", "execute",
    "shell", "upload_file", "upload", "s3_put", "put_object", "data_export",
    "export", "send_message", "webhook", "notify", "publish",
]


# ── Model weight file extensions ───────────────────────────────────────────────
MODEL_EXTENSIONS: frozenset[str] = frozenset({
    ".bin", ".pt", ".pth", ".ckpt", ".pkl",
    ".gguf", ".ggml", ".safetensors",
    ".onnx", ".pb", ".h5", ".keras",
    ".tflite", ".mlmodel",
})

ATTESTATION_EXTENSIONS: frozenset[str] = frozenset({".sha256", ".sig", ".asc", ".minisig"})
ATTESTATION_FILENAMES: frozenset[str] = frozenset({"manifest.json", "checksums.txt", "sha256sums"})


# ── Memory namespace danger flags ──────────────────────────────────────────────
GENERIC_NAMESPACES: frozenset[str] = frozenset({
    "default", "prod", "production", "shared", "global", "vectors",
    "main", "common", "data",
})

VECTOR_DB_ENV_INDICATORS: frozenset[str] = frozenset({
    "PINECONE_API_KEY", "PINECONE_ENVIRONMENT",
    "QDRANT_URL", "QDRANT_HOST",
    "WEAVIATE_URL", "WEAVIATE_HOST",
    "CHROMA_HOST", "CHROMADB_HOST",
    "REDIS_URL", "PGVECTOR_URL",
})


# ── Linux dangerous capabilities ───────────────────────────────────────────────
DANGEROUS_CAPS: frozenset[str] = frozenset({
    "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
    "CAP_SETUID", "CAP_SETGID", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
    "CAP_DAC_OVERRIDE", "CAP_NET_RAW",
})


# ── Persistence probe paths (computed at import time) ──────────────────────────
def _persistence_paths() -> list[str]:
    home = os.path.expanduser("~")
    paths: list[str] = []
    if sys.platform.startswith("linux"):
        paths += [
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".bash_profile"),
            os.path.join(home, ".profile"),
            "/etc/cron.d",
            "/etc/crontab",
            "/etc/rc.local",
        ]
    elif sys.platform == "darwin":
        paths += [
            os.path.join(home, "Library", "LaunchAgents"),
            os.path.join(home, ".zshrc"),
            os.path.join(home, ".bash_profile"),
        ]
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        paths += [
            os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        ]
    return paths


PERSISTENCE_PATHS: list[str] = _persistence_paths()
