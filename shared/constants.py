"""Shared path and filename constants."""

from pathlib import Path

# Default root directory where all user data and config are stored.
DEFAULT_DATA_DIR = Path("data")

# Path relative to data dir where the shared crypto parameters live.
PARAMS_PATH = Path("config/crypto_params.json")
