# python3.14 CTF3.py

def brute_force_bit_shift():
    
    with open("assets/shifted.txt") as f:
        numbers = list(map(int, f.read().split()))

    decoded_string = ""

    for num in numbers:
        original = num >> 1  # right shift to make numbers smaller
        decoded_string += chr(original)
    print(f"flag: {decoded_string}")

brute_force_bit_shift()