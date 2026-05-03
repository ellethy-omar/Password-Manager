import numpy as np

def xor(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return np.bitwise_xor(a, b)


def diff(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return np.abs(a.astype(np.int16) - b.astype(np.int16)).astype(np.uint8)


def diff_amplified(a: np.ndarray, b: np.ndarray, factor: int = 10) -> np.ndarray:
    return np.clip(diff(a, b).astype(np.int32) * factor, 0, 255).astype(np.uint8)


def bitwise_and(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return a & b


def bitwise_or(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return a | b


def average(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return ((a.astype(np.uint16) + b.astype(np.uint16)) // 2).astype(np.uint8)

def threshold(a: np.ndarray, cutoff: int = 10) -> np.ndarray:
    return (a > cutoff).astype(np.uint8) * 255
