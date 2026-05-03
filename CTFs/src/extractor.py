import re
import numpy as np

FLAG_PATTERNS = [
    r"CMPN\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"[A-Z0-9_]{8,}",
]


def extract_ascii(arr: np.ndarray) -> str:
    flat = arr.flatten()
    return "".join(chr(v) for v in flat if 32 <= int(v) <= 126)


def search_flags(text: str, patterns: list[str] | None = None) -> dict[str, list[str]]:
    patterns = patterns or FLAG_PATTERNS
    return {
        pat: hits
        for pat in patterns
        if (hits := re.findall(pat, text))
    }


def print_stats(array: np.ndarray, label: str = "array") -> None:
    print(f"Stats: {label}")
    print(f"shape: {array.shape}")
    print(f"dtype: {array.dtype}")
    print(f"min: {array.min()}")
    print(f"max: {array.max()}")
    print(f"mean: {array.mean():.2f}")
    print(f"std: {array.std():.2f}")
    unique = np.unique(array)
    print(f"unique: {len(unique)}")
