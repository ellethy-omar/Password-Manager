# python3.14 CTF6.py

from sympy import factorint

values = {}
with open("assets/challenge.txt", "r") as f:
    for line in f:
        if " = " in line:
            key, val = line.split(" = ", 1)
            key = key.strip()
            if key in ["n", "e", "ciphertext", "c"]:
                values[key] = int(val.strip())

n = values.get("n")
e = values.get("e")
c = values.get("ciphertext") or values.get("c")

# factor n
factors = factorint(n)
p, q = list(factors.keys())

# decrypt
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)

# print flag
flag = bytes.fromhex(hex(m)[2:]).decode('utf-8')
print("Decrypted flag:", flag)