import sys
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

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


class SDESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Set up the GUI elements
        self.setWindowTitle('S-DES Encryption/Decryption')
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        self.key_label = QLabel('Enter 10-bit Key (e.g. 1010000010):')
        layout.addWidget(self.key_label)

        self.key_input = QLineEdit()
        layout.addWidget(self.key_input)

        self.plaintext_label = QLabel('Enter 8-bit Plaintext (e.g. 10010111):')
        layout.addWidget(self.plaintext_label)

        self.plaintext_input = QLineEdit()
        layout.addWidget(self.plaintext_input)

        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt_text)
        layout.addWidget(self.encrypt_button)

        self.ciphertext_label = QLabel('Ciphertext:')
        layout.addWidget(self.ciphertext_label)

        self.ciphertext_output = QLineEdit()
        self.ciphertext_output.setReadOnly(True)
        layout.addWidget(self.ciphertext_output)

        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt_text)
        layout.addWidget(self.decrypt_button)

        self.decrypted_label = QLabel('Decrypted Text:')
        layout.addWidget(self.decrypted_label)

        self.decrypted_output = QLineEdit()
        self.decrypted_output.setReadOnly(True)
        layout.addWidget(self.decrypted_output)

        self.setLayout(layout)

    def encrypt_text(self):
        # Encrypt the input plaintext using the provided key
        key = [int(bit) for bit in self.key_input.text()]
        plaintext = [int(bit) for bit in self.plaintext_input.text()]
        sdes = SDES(key)
        ciphertext = sdes.encrypt(plaintext)
        self.ciphertext_output.setText(''.join(map(str, ciphertext)))

    def decrypt_text(self):
        # Decrypt the input ciphertext using the provided key
        key = [int(bit) for bit in self.key_input.text()]
        ciphertext = [int(bit) for bit in self.ciphertext_output.text()]
        sdes = SDES(key)
        decrypted_text = sdes.decrypt(ciphertext)
        self.decrypted_output.setText(''.join(map(str, decrypted_text)))


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ex = SDESApp()
    ex.show()
    sys.exit(app.exec_())

# Example usage
key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]  # 10-bit key
plaintext = [1, 0, 0, 1, 0, 1, 1, 1]  # 8-bit plaintext

sdes = SDES(key)
ciphertext = sdes.encrypt(plaintext)  # Encrypt the plaintext
decrypted_text = sdes.decrypt(ciphertext)  # Decrypt the ciphertext

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)