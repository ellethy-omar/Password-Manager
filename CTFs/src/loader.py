from pathlib import Path
from PIL import Image
import numpy as np


def load_image(path: str | Path, mode: str = "RGB") -> Image.Image:
    img = Image.open(path)
    return img.convert(mode)


def to_array(img: Image.Image) -> np.ndarray:
    return np.array(img, dtype=np.uint8)


def load_pair(path1: str | Path, path2: str | Path, mode: str = "RGB") -> tuple[np.ndarray, np.ndarray]:
    image1 = load_image(path1, mode)
    image2 = load_image(path2, mode)

    if image1.size != image2.size:
        min_width = min(image1.width, image2.width)
        min_height = min(image1.height, image2.height)
        image1 = image1.crop((0, 0, min_width, min_height))
        image2 = image2.crop((0, 0, min_width, min_height))

    return to_array(image1), to_array(image2)
