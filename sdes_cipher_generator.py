import random

class SDES:
    def __init__(self, key):
        # Initialize the key and various permutation tables
        self.key = key
        self.p10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)  # Permutation P10
        self.p8 = (6, 3, 7, 4, 8, 5, 10, 9)  # Permutation P8
        self.ip = (2, 6, 3, 1, 4, 8, 5, 7)  # Initial Permutation IP
        self.ip_inv = (4, 1, 3, 5, 7, 2, 8, 6)  # Inverse Initial Permutation IP^-1
        self.ep = (4, 1, 2, 3, 2, 3, 4, 1)  # Expansion Permutation E/P
        self.p4 = (2, 4, 3, 1)  # Permutation P4
        self.sbox1 = [(1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2)]  # S-Box 1
        self.sbox2 = [(0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3)]  # S-Box 2
        # Generate the subkeys for encryption and decryption
        self.key1, self.key2 = self.generate_keys(key)
    
    def permute(self, key, table):
        # Permute the key according to the given table
        return [key[i - 1] for i in table]

    def left_shift(self, bits, n):
        # Perform a left circular shift by n bits
        return bits[n:] + bits[:n]

    def generate_keys(self, key):
        # Generate two subkeys from the original key
        permuted_key = self.permute(key, self.p10)  # Apply P10 permutation
        left, right = permuted_key[:5], permuted_key[5:]  # Split into two halves
        left, right = self.left_shift(left, 1), self.left_shift(right, 1)  # Left shift by 1
        key1 = self.permute(left + right, self.p8)  # Apply P8 to get the first subkey
        left, right = self.left_shift(left, 2), self.left_shift(right, 2)  # Left shift by 2
        key2 = self.permute(left + right, self.p8)  # Apply P8 to get the second subkey
        return key1, key2

    def initial_permutation(self, bits):
        # Apply the initial permutation IP
        return self.permute(bits, self.ip)

    def inverse_initial_permutation(self, bits):
        # Apply the inverse initial permutation IP^-1
        return self.permute(bits, self.ip_inv)

    def expand_and_permute(self, half_bits):
        # Expand and permute the 4-bit input to 8 bits using E/P
        return self.permute(half_bits, self.ep)

    def xor(self, bits1, bits2):
        # XOR two lists of bits
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def sbox_substitution(self, bits, sbox):
        # Perform substitution using the given S-box
        row = (bits[0] << 1) | bits[3]  # Determine row from the first and last bit
        col = (bits[1] << 1) | bits[2]  # Determine column from the middle bits
        return [int(b) for b in format(sbox[row][col], '02b')]  # Get the corresponding value and convert to 2 bits

    def sbox_substitution(self, bits, sbox):
        # Perform substitution using the given S-box
        row = (bits[0] << 1) | bits[3]  # Determine row from the first and last bit
        col = (bits[1] << 1) | bits[2]  # Determine column from the middle bits
        value = sbox[row][col]  # Get the corresponding value from the S-box
        return [int(b) for b in format(value, '02b')]  # Convert the value to 2 bits

    def f_function(self, half_bits, subkey):
        # Apply the F function to 4 bits using a given subkey
        expanded_bits = self.expand_and_permute(half_bits)  # Expand and permute the 4 bits
        xored_bits = self.xor(expanded_bits, subkey)  # XOR with the subkey
        left, right = xored_bits[:4], xored_bits[4:]  # Split into two halves
        # Apply S-boxes to each half and concatenate the results
        sbox_out = self.sbox_substitution(left, self.sbox1) + self.sbox_substitution(right, self.sbox2)
        return self.permute(sbox_out, self.p4)  # Apply P4 permutation

    def fk(self, bits, key):
        # Apply the fk function which includes F function and XOR with the left half
        left, right = bits[:4], bits[4:]  # Split input into left and right halves
        f_output = self.f_function(right, key)  # Apply the F function to the right half
        left = self.xor(left, f_output)  # XOR the result with the left half
        return left + right  # Concatenate the modified left half with the original right half

    def switch(self, bits):
        # Switch the left and right halves (used in the encryption/decryption process)
        return bits[4:] + bits[:4]

    def encrypt(self, plaintext):
        # Encrypt the plaintext using the generated subkeys
        bits = self.initial_permutation(plaintext)  # Apply initial permutation
        bits = self.fk(bits, self.key1)  # Apply fk function with the first subkey
        bits = self.switch(bits)  # Switch the halves
        bits = self.fk(bits, self.key2)  # Apply fk function with the second subkey
        ciphertext = self.inverse_initial_permutation(bits)  # Apply the inverse initial permutation
        return ciphertext

    def decrypt(self, ciphertext):
        # Decrypt the ciphertext using the generated subkeys (in reverse order)
        bits = self.initial_permutation(ciphertext)  # Apply initial permutation
        bits = self.fk(bits, self.key2)  # Apply fk function with the second subkey
        bits = self.switch(bits)  # Switch the halves
        bits = self.fk(bits, self.key1)  # Apply fk function with the first subkey
        plaintext = self.inverse_initial_permutation(bits)  # Apply the inverse initial permutation
        return plaintext

def generate_random_plaintexts(count, length=8):
    plaintexts = set()  
    while len(plaintexts) < count:
        plaintext = tuple(random.randint(0, 1) for _ in range(length))  
        plaintexts.add(plaintext)  
    return list(plaintexts)


key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]  # 10-bit key
sdes = SDES(key)

plaintexts = generate_random_plaintexts(50)
results = []

for plaintext in plaintexts:
    ciphertext = sdes.encrypt(plaintext) 
    results.append((plaintext, ciphertext)) 

with open('ciphertext_results.txt', 'w') as f:
    for plaintext, ciphertext in results:
        f.write(f"Plaintext: {list(plaintext)}, Ciphertext: {list(ciphertext)}\n")

print("Plaintext and ciphertext have been written to the file ciphertext_results.txt")