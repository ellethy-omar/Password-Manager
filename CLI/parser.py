"""CLI argument parser definition."""

import argparse
from pathlib import Path

from shared.constants import DEFAULT_DATA_DIR


def build_parser() -> argparse.ArgumentParser:
    """Build and return the root ArgumentParser for the password manager CLI."""
    parser = argparse.ArgumentParser(description="Secure Password Manager")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Root storage directory (default: data/)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Module 1: user initialisation ---
    init = subparsers.add_parser("init-user", help="Initialize a new user and empty vault")
    init.add_argument("--user", required=True)
    init.add_argument("--master-password", required=True)

    # --- Module 2: credential management ---
    add = subparsers.add_parser("add", help="Add a credential to the vault")
    add.add_argument("--user", required=True)
    add.add_argument("--master-password", required=True)
    add.add_argument("--site", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--password", required=True)

    retrieve = subparsers.add_parser("retrieve", help="Retrieve a stored credential")
    retrieve.add_argument("--user", required=True)
    retrieve.add_argument("--master-password", required=True)
    retrieve.add_argument("--site", required=True)
    retrieve.add_argument("--username", default="")

    update = subparsers.add_parser("update", help="Update a credential's password")
    update.add_argument("--user", required=True)
    update.add_argument("--master-password", required=True)
    update.add_argument("--site", required=True)
    update.add_argument("--username", required=True)
    update.add_argument("--new-password", required=True)

    delete = subparsers.add_parser("delete", help="Delete a credential from the vault")
    delete.add_argument("--user", required=True)
    delete.add_argument("--master-password", required=True)
    delete.add_argument("--site", required=True)
    delete.add_argument("--username", required=True)

    list_cmd = subparsers.add_parser("list", help="List all credentials")
    list_cmd.add_argument("--user", required=True)
    list_cmd.add_argument("--master-password", required=True)

    # --- Module 3: vault integrity ---
    verify = subparsers.add_parser("verify", help="Verify the vault's digital signature")
    verify.add_argument("--user", required=True)

    # --- Module 4: export / import ---
    prepare = subparsers.add_parser(
        "prepare-import",
        help="Prepare a signed DH session for the recipient (run on recipient device)",
    )
    prepare.add_argument("--recipient", required=True)
    prepare.add_argument("--sender", required=True)
    prepare.add_argument("--out", type=Path, required=True)

    export_cmd = subparsers.add_parser(
        "export",
        help="Export the sender's vault securely to a recipient",
    )
    export_cmd.add_argument("--sender", required=True)
    export_cmd.add_argument("--master-password", required=True)
    export_cmd.add_argument("--recipient-session", type=Path, required=True)
    export_cmd.add_argument("--out", type=Path, required=True)

    import_cmd = subparsers.add_parser(
        "import",
        help="Import a received transfer package",
    )
    import_cmd.add_argument("--recipient", required=True)
    import_cmd.add_argument("--sender", required=True)
    import_cmd.add_argument("--master-password", required=True)
    import_cmd.add_argument("--package", type=Path, required=True)

    return parser
