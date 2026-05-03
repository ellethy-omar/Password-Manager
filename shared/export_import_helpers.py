from pathlib import Path
import time

HANDSHAKE_TIMEOUT = 120
POLL_INTERVAL = 1


def file_pooling(path: Path) -> None:
    elapsed = 0
    while True:
        # path.stat() returns metadata about a file
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
        if elapsed >= HANDSHAKE_TIMEOUT:
            raise TimeoutError(
                f"Timed out after {HANDSHAKE_TIMEOUT}s waiting for {path}. "
                "Make sure the sender terminal has started."
            )
