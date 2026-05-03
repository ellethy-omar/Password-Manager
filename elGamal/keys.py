from dataclasses import dataclass


@dataclass
class ElGamalPrivateKey:
    p: int
    alpha: int
    x: int


@dataclass
class ElGamalPublicKey:
    p: int
    alpha: int
    y: int
