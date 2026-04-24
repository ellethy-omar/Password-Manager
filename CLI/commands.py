import json
from typing import Callable

from CLI.app import PasswordManagerApp
from shared.printPrinter import success, error

def dispatch(app: PasswordManagerApp, args) -> None:
    """Execute CLI command safely."""
    try:
        COMMANDS[args.command](app, args)
    except Exception as exc:
        error(f"Error: {exc}")
        raise SystemExit(1)


def handle_init(app: PasswordManagerApp, args) -> None:
    app.initialize_user(args.user, args.master_password)
    success(f"Initialized user '{args.user}'")


def handle_add(app: PasswordManagerApp, args) -> None:
    app.add_credential(
        args.user, args.master_password, args.site, args.username, args.password
    )
    success("Credential added and vault re-signed")


def handle_retrieve(app: PasswordManagerApp, args) -> None:
    item = app.retrieve_credential(
        args.user, args.master_password, args.site, args.username
    )
    print(json.dumps(item, indent=2))


def handle_update(app: PasswordManagerApp, args) -> None:
    app.update_credential(
        args.user, args.master_password, args.site, args.username, args.new_password
    )
    success("Credential updated and vault re-signed")


def handle_delete(app: PasswordManagerApp, args) -> None:
    app.delete_credential(
        args.user, args.master_password, args.site, args.username
    )
    success("Credential deleted and vault re-signed")


def handle_list(app: PasswordManagerApp, args) -> None:
    data = app.list_credentials(args.user, args.master_password)
    print(json.dumps(data, indent=2))


def handle_verify(app: PasswordManagerApp, args) -> None:
    if app.verify_vault(args.user):
        success("Vault signature is valid")
    else:
        error("Vault signature is INVALID")
        raise SystemExit(1)


def handle_prepare_import(app: PasswordManagerApp, args) -> None:
    app.prepare_import_session(args.recipient, args.sender, args.out)
    success(f"Recipient import session created at {args.out}")


def handle_export(app: PasswordManagerApp, args) -> None:
    app.export_vault(
        args.sender, args.master_password, args.recipient_session, args.out
    )
    success(f"Export package created at {args.out}")


def handle_import(app: PasswordManagerApp, args) -> None:
    app.import_vault(
        args.recipient, args.sender, args.master_password, args.package
    )
    success("Vault imported and re-signed by recipient")

COMMANDS: dict[str, Callable[[PasswordManagerApp, object], None]] = {
    "init-user": handle_init,
    "add": handle_add,
    "retrieve": handle_retrieve,
    "update": handle_update,
    "delete": handle_delete,
    "list": handle_list,
    "verify": handle_verify,
    "prepare-import": handle_prepare_import,
    "export": handle_export,
    "import": handle_import,
}