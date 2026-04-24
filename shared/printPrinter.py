import sys

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def success(msg: str) -> None:
    print(f"{GREEN}{msg}{RESET}")

def error(msg: str) -> None:
    print(f"{RED}{msg}{RESET}", file=sys.stderr)