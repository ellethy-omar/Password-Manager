"""CLI command dispatcher.

Each branch calls the appropriate method on :class:`CLI.app.PasswordManagerApp`
and prints a human-readable result.  All errors are caught and displayed before
raising SystemExit(1).
"""

import json
import sys

from CLI.app import PasswordManagerApp


def dispatch(app: PasswordManagerApp, args) -> None:
    """Execute the CLI sub-command described by *args* using *app*."""
    try:
        _dispatch(app, args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)


def _dispatch(app: PasswordManagerApp, args) -> None:
    if args.command == "init-user":
        app.initialize_user(args.user, args.master_password)
        print(f"Initialized user '{args.user}'")

    elif args.command == "add":
        app.add_credential(
            args.user, args.master_password, args.site, args.username, args.password
        )
        print("Credential added and vault re-signed")

    elif args.command == "retrieve":
        item = app.retrieve_credential(
            args.user, args.master_password, args.site, args.username
        )
        print(json.dumps(item, indent=2))

    elif args.command == "update":
        app.update_credential(
            args.user, args.master_password, args.site, args.username, args.new_password
        )
        print("Credential updated and vault re-signed")

    elif args.command == "delete":
        app.delete_credential(
            args.user, args.master_password, args.site, args.username
        )
        print("Credential deleted and vault re-signed")

    elif args.command == "list":
        print(json.dumps(app.list_credentials(args.user, args.master_password), indent=2))

    elif args.command == "verify":
        if app.verify_vault(args.user):
            print("Vault signature is valid")
        else:
            print("Vault signature is INVALID", file=sys.stderr)
            raise SystemExit(1)

    elif args.command == "prepare-import":
        app.prepare_import_session(args.recipient, args.sender, args.out)
        print(f"Recipient import session created at {args.out}")

    elif args.command == "export":
        app.export_vault(args.sender, args.master_password, args.recipient_session, args.out)
        print(f"Export package created at {args.out}")

    elif args.command == "import":
        app.import_vault(args.recipient, args.sender, args.master_password, args.package)
        print("Vault imported and re-signed by recipient")
