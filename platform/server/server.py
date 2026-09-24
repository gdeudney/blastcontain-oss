"""
BlastContain Server — uvicorn entry point.

Run: uvicorn server:app --host 0.0.0.0 --port 8080

Configuration (environment):
  BLASTCONTAIN_DB_URL            database (default sqlite:///blastcontain.db)
  BLASTCONTAIN_API_TOKEN         require Bearer auth on /v1 routes when set
  BLASTCONTAIN_SIGNING_KEY_PATH  Ed25519 PEM for Charter attestation
  BLASTCONTAIN_SIGNING_KEY       HMAC fallback (advisory without a real key)
  BLASTCONTAIN_SIGNER_DID        signer identity recorded in signed_by
"""
from blastcontain.app import create_app

app = create_app()
