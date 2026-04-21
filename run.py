#!/usr/bin/env python3
"""Entry-point script for the Secure Password Manager.

Usage
-----
    python run.py <command> [options]

Run  ``python run.py --help``  for the full command reference.
"""

from CLI.app import PasswordManagerApp
from CLI.parser import build_parser
from CLI.commands import dispatch


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    app = PasswordManagerApp(base_dir=args.base_dir)
    dispatch(app, args)


if __name__ == "__main__":
    main()
