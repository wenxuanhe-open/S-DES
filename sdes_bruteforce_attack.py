from itertools import product
import time
from concurrent.futures import ThreadPoolExecutor
import ast
import datetime

class SDES:
    def __init__(self, key):
        self.key = key
        self.p10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
        self.p8 = (6, 3, 7, 4, 8, 5, 10, 9)
        self.ip = (2, 6, 3, 1, 4, 8, 5, 7)
        self.ip_inv = (4, 1, 3, 5, 7, 2, 8, 6)
        self.ep = (4, 1, 2, 3, 2, 3, 4, 1)
        self.p4 = (2, 4, 3, 1)
        self.sbox1 = [(1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2)]
        self.sbox2 = [(0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3)]
        self.key1, self.key2 = self.generate_keys(key)

    def permute(self, key, table):
        return [key[i - 1] for i in table]

    def left_shift(self, bits, n):
        return bits[n:] + bits[:n]

    def generate_keys(self, key):
        permuted_key = self.permute(key, self.p10)
        left, right = permuted_key[:5], permuted_key[5:]
        left, right = self.left_shift(left, 1), self.left_shift(right, 1)
        key1 = self.permute(left + right, self.p8)
        left, right = self.left_shift(left, 2), self.left_shift(right, 2)
        key2 = self.permute(left + right, self.p8)
        return key1, key2

    def initial_permutation(self, bits):
        return self.permute(bits, self.ip)

    def inverse_initial_permutation(self, bits):
        return self.permute(bits, self.ip_inv)

    def expand_and_permute(self, half_bits):
        return self.permute(half_bits, self.ep)

    def xor(self, bits1, bits2):
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def sbox_substitution(self, bits, sbox):
        row = (bits[0] << 1) | bits[3]
        col = (bits[1] << 1) | bits[2]
        return [int(b) for b in format(sbox[row][col], '02b')]

    def f_function(self, half_bits, subkey):
        expanded_bits = self.expand_and_permute(half_bits)
        xored_bits = self.xor(expanded_bits, subkey)
        left, right = xored_bits[:4], xored_bits[4:]
        sbox_out = self.sbox_substitution(left, self.sbox1) + self.sbox_substitution(right, self.sbox2)
        return self.permute(sbox_out, self.p4)

    def fk(self, bits, key):
        left, right = bits[:4], bits[4:]
        f_output = self.f_function(right, key)
        left = self.xor(left, f_output)
        return left + right

    def switch(self, bits):
        return bits[4:] + bits[:4]

    def encrypt(self, plaintext):
        bits = self.initial_permutation(plaintext)
        bits = self.fk(bits, self.key1)
        bits = self.switch(bits)
        bits = self.fk(bits, self.key2)
        return self.inverse_initial_permutation(bits)

    def decrypt(self, ciphertext):
        bits = self.initial_permutation(ciphertext)
        bits = self.fk(bits, self.key2)
        bits = self.switch(bits)
        bits = self.fk(bits, self.key1)
        return self.inverse_initial_permutation(bits)

def brute_force_attack_all_pairs(pairs):
    possible_keys = list(product([0, 1], repeat=10))
    matching_keys = set(possible_keys)  # Start with all possible keys

    round_number = 1
    all_round_results = []
    for plaintext, ciphertext in pairs:
        current_matching_keys = []
        for key in matching_keys:
            sdes = SDES(key)
            if sdes.encrypt(plaintext) == ciphertext:
                current_matching_keys.append(key)

        matching_keys = current_matching_keys
        round_result = f"Round {round_number}: {len(matching_keys)} keys match. Keys: {[ ''.join(map(str, key)) for key in matching_keys ]}"
        all_round_results.append(round_result)
        round_number += 1

        # If at any point there's only one matching key, we can stop early
        if len(matching_keys) == 1:
            break

    return matching_keys, all_round_results

if __name__ == "__main__":
    # Read plaintext and ciphertext pairs from the provided file "ciphertext_results.txt"
    with open("ciphertext_results.txt", "r") as file:
        lines = file.readlines()

    pairs = []
    for line in lines:
        try:
            # Ensure the line contains both plaintext and ciphertext data
            if ", Ciphertext: " in line:
                data = line.strip().split(", Ciphertext: ")
                plaintext_str = data[0].split(": ")[1]
                ciphertext_str = data[1]
                
                # Parse the plaintext and ciphertext strings into lists
                plaintext = ast.literal_eval(plaintext_str)
                ciphertext = ast.literal_eval(ciphertext_str)
                pairs.append((plaintext, ciphertext))
            else:
                raise ValueError("Malformed line in input file.")
        except (ValueError, IndexError, SyntaxError) as e:
            print(f"Skipping malformed line: {line.strip()} - Error: {str(e)}")

    # Start timing the brute force attack
    start_time = time.time()
    start_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Perform brute force attack across all pairs to find the common key
    all_round_results = []
    all_round_results.append(f"Brute Force Attack for all pairs started at {start_timestamp}")
    matching_keys, round_results = brute_force_attack_all_pairs(pairs)
    all_round_results.extend(round_results)

    end_time = time.time()
    end_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_time_taken = end_time - start_time

    if len(matching_keys) == 1:
        result = f"Unique Key found: {''.join(map(str, matching_keys[0]))}\n"
    elif len(matching_keys) > 1:
        result = f"Multiple possible keys found: {[ ''.join(map(str, key)) for key in matching_keys ]}\n"
    else:
        result = "No key found.\n"

    result += f"Brute force attack started at: {start_timestamp}, ended at: {end_timestamp}, total time taken: {total_time_taken:.2f} seconds\n"

    # Combine all results and print/write to file
    all_round_results.append(result)
    full_result = "\n".join(all_round_results)
    print(full_result)
    with open("bruteforce_results.txt", "w") as output_file:
        output_file.write(full_result)