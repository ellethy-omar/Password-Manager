# python3.14 CTF5.py

import requests
import time

TARGET     = "http://cbc-ctf.westeurope.azurecontainer.io:5000"
BLOCK_SIZE = 16
CIPHERTEXT_HEX = "b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975"


def oracle(ciphertext_bytes: bytes) -> bool:
    r = requests.post(
        f"{TARGET}/oracle",
        json={"ciphertext_hex": ciphertext_bytes.hex()},
        timeout=10
    )
    return r.json().get("valid_padding", False)


def decrypt_block(target_block: bytes, prev_block: bytes) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - byte_pos

        modified_prev = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            modified_prev[k] = intermediate[k] ^ padding_val

        found = False
        for guess in range(256):
            modified_prev[byte_pos] = guess

            if oracle(bytes(modified_prev) + target_block):
                if byte_pos == BLOCK_SIZE - 1 and byte_pos > 0:
                    confirm = bytearray(modified_prev)
                    confirm[byte_pos - 1] ^= 1   # flip one byte earlier
                    if not oracle(bytes(confirm) + target_block):
                        continue  # false positive — keep scanning

                # We found the right guess!
                # intermediate[byte_pos] = guess XOR padding_val
                intermediate[byte_pos] = guess ^ padding_val
                pt_byte = intermediate[byte_pos] ^ prev_block[byte_pos]
                print(f"  byte[{byte_pos:2d}] = 0x{pt_byte:02x} "
                      f"'{chr(pt_byte) if 32 <= pt_byte < 127 else '?'}'")
                found = True
                break

            time.sleep(0.05)  # small delay to avoid overwhelming the server

        if not found:
            print(f"  [!] Could not find byte {byte_pos} — server may be rate-limiting, try again")
            intermediate[byte_pos] = 0

    # XOR the recovered intermediate bytes with the real previous block to get plaintext
    plaintext_block = bytes(i ^ p for i, p in zip(intermediate, prev_block))
    return plaintext_block



def main():
    # Parse the ciphertext into blocks
    ciphertext = bytes.fromhex(CIPHERTEXT_HEX)
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    # blocks[0]  = IV
    # blocks[1]  = C1  (first ciphertext block)
    # blocks[2]  = C2  (second ciphertext block)
    print(f"Ciphertext: {len(ciphertext)} bytes → {len(blocks)} blocks (IV + {len(blocks)-1} cipher)")
    print(f"IV : {blocks[0].hex()}")
    for i in range(1, len(blocks)):
        print(f"C{i} : {blocks[i].hex()}")

    # Quick sanity check — does the original ciphertext have valid padding?
    print(f"\nSanity check (original ciphertext valid?): {oracle(ciphertext)}")

    # Decrypt each ciphertext block
    full_plaintext = b""
    for block_idx in range(1, len(blocks)):
        print(f"\nDecrypting block {block_idx}/{len(blocks)-1}...")
        # Each block is decrypted using the block before it as the "previous block"
        # For block 1: previous = IV
        # For block 2: previous = C1
        pt_block = decrypt_block(
            target_block = blocks[block_idx],
            prev_block   = blocks[block_idx - 1]
        )
        # print(f"  --> Raw: {pt_block.hex()}")
        full_plaintext += pt_block

    pad_len = full_plaintext[-1]
    if 1 <= pad_len <= BLOCK_SIZE:
        full_plaintext = full_plaintext[:-pad_len]

    print("\n" + "=" * 55)
    print(f"Decrypted flag: {full_plaintext.decode(errors='replace')}")


if __name__ == "__main__":
    main()