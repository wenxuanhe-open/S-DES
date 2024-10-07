class SDES:
    def __init__(self, key):
        self.key = key
        self.subkey1, self.subkey2 = self.generate_subkeys(key)

    def permute(self, bits, table):
        return [bits[i - 1] for i in table]

    def left_shift(self, bits, n):
        return bits[n:] + bits[:n]

    def sbox_lookup(self, sbox, row, col):
        return sbox[row][col]

    def bits_to_int(self, bits):
        return int(''.join(map(str, bits)), 2)

    def int_to_bits(self, value, length):
        return [int(x) for x in bin(value)[2:].zfill(length)]

    def generate_subkeys(self, key):
        P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        P8 = [6, 3, 7, 4, 8, 5, 10, 9]

        key_permuted = self.permute(key, P10)
        left, right = key_permuted[:5], key_permuted[5:]

        left_shifted_1 = self.left_shift(left, 1)
        right_shifted_1 = self.left_shift(right, 1)
        subkey1 = self.permute(left_shifted_1 + right_shifted_1, P8)

        left_shifted_2 = self.left_shift(left_shifted_1, 2)
        right_shifted_2 = self.left_shift(right_shifted_1, 2)
        subkey2 = self.permute(left_shifted_2 + right_shifted_2, P8)

        return subkey1, subkey2

    def fk(self, bits, subkey):
        EP = [4, 1, 2, 3, 2, 3, 4, 1]
        S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 0, 2],
        ]
        S1 = [
            [0, 1, 2, 3],
            [2, 3, 1, 0],
            [3, 0, 1, 2],
            [2, 1, 0, 3],
        ]
        P4 = [2, 4, 3, 1]

        left, right = bits[:4], bits[4:]
        right_expanded = self.permute(right, EP)
        xor_result = [a ^ b for a, b in zip(right_expanded, subkey)]

        xor_left, xor_right = xor_result[:4], xor_result[4:]

        row = (xor_left[0] << 1) + xor_left[3]
        col = (xor_left[1] << 1) + xor_left[2]
        s0_val = self.sbox_lookup(S0, row, col)
        s0_bits = self.int_to_bits(s0_val, 2)

        row = (xor_right[0] << 1) + xor_right[3]
        col = (xor_right[1] << 1) + xor_right[2]
        s1_val = self.sbox_lookup(S1, row, col)
        s1_bits = self.int_to_bits(s1_val, 2)

        sbox_output = s0_bits + s1_bits
        p4_result = self.permute(sbox_output, P4)
        left_result = [a ^ b for a, b in zip(left, p4_result)]

        return left_result + right

    def encrypt(self, plaintext):
        IP = [2, 6, 3, 1, 4, 8, 5, 7]
        IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

        ip_bits = self.permute(plaintext, IP)
        result_fk1 = self.fk(ip_bits, self.subkey1)
        swapped = result_fk1[4:] + result_fk1[:4]
        result_fk2 = self.fk(swapped, self.subkey2)
        ciphertext = self.permute(result_fk2, IP_inv)
        return ciphertext

    def decrypt(self, ciphertext):
        IP = [2, 6, 3, 1, 4, 8, 5, 7]
        IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]

        ip_bits = self.permute(ciphertext, IP)
        result_fk1 = self.fk(ip_bits, self.subkey2)
        swapped = result_fk1[4:] + result_fk1[:4]
        result_fk2 = self.fk(swapped, self.subkey1)
        plaintext = self.permute(result_fk2, IP_inv)
        return plaintext


# # Example usage
# key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]  # 10-bit key
# plaintext = [1, 0, 0, 1, 0, 1, 1, 1]  # 8-bit plaintext

# key = [0, 1, 1, 0, 1, 0, 1, 1, 1, 0]  # 10-bit key
# plaintext = [1, 1, 0, 0, 1, 0, 1, 1]  # 8-bit plaintext

key = [1, 0, 1, 1, 0, 1, 0, 1, 1, 0]  # 10-bit key
plaintext = [0, 1, 1, 0, 0, 1, 0, 1]  # 8-bit plaintext

sdes = SDES(key)
ciphertext = sdes.encrypt(plaintext)  # Encrypt the plaintext
decrypted_text = sdes.decrypt(ciphertext)  # Decrypt the ciphertext

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)