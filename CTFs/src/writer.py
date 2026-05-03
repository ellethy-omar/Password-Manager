from pathlib import Path
from PIL import Image
import numpy as np


def save(arr: np.ndarray, path: str | Path, mode: str | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if mode is None:
        mode = {2: "L", 3: "RGB", 4: "RGBA"}.get(arr.ndim)
        if mode is None:
            raise ValueError(f"Cannot infer mode for array with ndim={arr.ndim}")

    Image.fromarray(arr, mode=mode).save(path)
    print(f"saved to: {path}")
    return path


def save_batch(results: dict[str, np.ndarray], output_dir: str | Path) -> list[Path]:
    output_dir = Path(output_dir)
    saved = []
    for name, arr in results.items():
        out = output_dir / f"result_{name}.png"
        saved.append(save(arr, out))
    return saved
