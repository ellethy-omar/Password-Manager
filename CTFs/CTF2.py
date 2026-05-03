# python3.14 CTF2.py

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from src import (
    load_pair,
    xor, diff, diff_amplified, threshold, average,
    extract_ascii, search_flags, print_stats,
    save_batch,
)

DEFAULT_LAYER1  = "assets/Layer1.png"
DEFAULT_LAYER2  = "assets/Layer2.png"
OUTPUT_DIR      = Path("outputs")

def run(layer1_path: str, layer2_path: str) -> None:
    print(f"Loading images")
    rgb1, rgb2 = load_pair(layer1_path, layer2_path, mode="RGB")
    gray1, gray2 = load_pair(layer1_path, layer2_path, mode="L")
    print(f"shape: {rgb1.shape}")

    print("Applying transforms")
    results = {
        "xor": xor(rgb1, rgb2),
        "diff": diff(rgb1, rgb2),
        "diff_amplified": diff_amplified(rgb1, rgb2, factor=10),
        "average": average(rgb1, rgb2),
        "threshold": threshold(xor(gray1, gray2), cutoff=10),
    }
    save_batch(results, OUTPUT_DIR)

    print("Statististics")
    xor_gray = xor(gray1, gray2)
    print_stats(xor_gray, label="XOR (grayscale)")

    print("Done.")


if __name__ == "__main__":
    l1 = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LAYER1
    l2 = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_LAYER2
    run(l1, l2)