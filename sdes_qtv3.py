import sys
from itertools import product
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QTextEdit)
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt

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

    def encrypt_text(self, text):
        # Encrypt an ASCII string, byte by byte
        return [self.encrypt(self.byte_to_bits(ord(char))) for char in text]

    def decrypt_text(self, encrypted_bits_list):
        # Decrypt a list of bits corresponding to ASCII characters
        return ''.join(chr(self.bits_to_byte(self.decrypt(bits))) for bits in encrypted_bits_list)

    def byte_to_bits(self, byte):
        # Convert a byte (0-255) to 8 bits
        return [int(b) for b in format(byte, '08b')]

    def bits_to_byte(self, bits):
        # Convert 8 bits to a byte (0-255)
        return int(''.join(map(str, bits)), 2)

class SDESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Set up the GUI elements
        self.setWindowTitle('S-DES Encryption/Decryption')
        self.setGeometry(100, 100, 600, 500)
        self.setStyleSheet("background-color: #f0f0f0;")

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)

        # Title Label
        title_label = QLabel('S-DES Encryption/Decryption Tool')
        title_label.setFont(QFont('Arial', 16))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("padding: 10px; color: #2c3e50;")
        layout.addWidget(title_label)

        # Key Input Section
        key_layout = QHBoxLayout()
        self.key_label = QLabel('10-bit Key:')
        self.key_label.setFont(QFont('Arial', 12))
        key_layout.addWidget(self.key_label)

        self.key_input = QLineEdit()
        self.key_input.setFont(QFont('Arial', 12))
        self.key_input.setPlaceholderText('e.g. 1010000010')
        key_layout.addWidget(self.key_input)

        layout.addLayout(key_layout)

        # Plaintext Input Section
        plaintext_layout = QHBoxLayout()
        self.plaintext_label = QLabel('Plaintext:')
        self.plaintext_label.setFont(QFont('Arial', 12))
        plaintext_layout.addWidget(self.plaintext_label)

        self.plaintext_input = QLineEdit()
        self.plaintext_input.setFont(QFont('Arial', 12))
        self.plaintext_input.setPlaceholderText('e.g. HELLO or 10010111')
        plaintext_layout.addWidget(self.plaintext_input)

        layout.addLayout(plaintext_layout)

        # Encrypt Button
        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.setFont(QFont('Arial', 12))
        self.encrypt_button.setStyleSheet("background-color: #3498db; color: white; padding: 10px;")
        self.encrypt_button.clicked.connect(self.encrypt_text)
        layout.addWidget(self.encrypt_button)

        # Ciphertext Output Section
        ciphertext_layout = QHBoxLayout()
        self.ciphertext_label = QLabel('Ciphertext:')
        self.ciphertext_label.setFont(QFont('Arial', 12))
        ciphertext_layout.addWidget(self.ciphertext_label)

        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setFont(QFont('Arial', 12))
        self.ciphertext_output.setReadOnly(True)
        self.ciphertext_output.setStyleSheet("background-color: #ecf0f1;")
        self.ciphertext_output.setFixedHeight(100)
        ciphertext_layout.addWidget(self.ciphertext_output)

        layout.addLayout(ciphertext_layout)

        # Decrypt Button
        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.setFont(QFont('Arial', 12))
        self.decrypt_button.setStyleSheet("background-color: #2ecc71; color: white; padding: 10px;")
        self.decrypt_button.clicked.connect(self.decrypt_text)
        layout.addWidget(self.decrypt_button)

        # Decrypted Text Output Section
        decrypted_layout = QHBoxLayout()
        self.decrypted_label = QLabel('Decrypted Text:')
        self.decrypted_label.setFont(QFont('Arial', 12))
        decrypted_layout.addWidget(self.decrypted_label)

        self.decrypted_output = QLineEdit()
        self.decrypted_output.setFont(QFont('Arial', 12))
        self.decrypted_output.setReadOnly(True)
        self.decrypted_output.setStyleSheet("background-color: #ecf0f1;")
        decrypted_layout.addWidget(self.decrypted_output)

        layout.addLayout(decrypted_layout)

        self.setLayout(layout)

    def encrypt_text(self):
        # Encrypt the input plaintext using the provided key
        try:
            key = [int(bit) for bit in self.key_input.text()]
            plaintext = self.plaintext_input.text()
            if len(key) != 10:
                raise ValueError("Key must be 10 bits.")
            sdes = SDES(key)

            # Determine if the plaintext is binary or ASCII
            if plaintext.isdigit() and len(plaintext) == 8 and set(plaintext).issubset({'0', '1'}):
                # Handle 8-bit binary input
                plaintext_bits = [int(bit) for bit in plaintext]
                encrypted_bits = sdes.encrypt(plaintext_bits)
                encrypted_text = ' '.join(map(str, encrypted_bits))
            else:
                # Handle ASCII string input
                encrypted_bits_list = sdes.encrypt_text(plaintext)
                encrypted_text = ' '.join(''.join(map(str, bits)) for bits in encrypted_bits_list)
            
            self.ciphertext_output.setText(encrypted_text)
        except ValueError as e:
            QMessageBox.critical(self, "Input Error", str(e))

    def decrypt_text(self):
        # Decrypt the input ciphertext using the provided key
        try:
            key = [int(bit) for bit in self.key_input.text()]
            encrypted_text = self.ciphertext_output.toPlainText()
            if len(key) != 10:
                raise ValueError("Key must be 10 bits.")
            sdes = SDES(key)

            # Determine if the input is binary or ASCII encrypted text
            encrypted_bits_list = [list(map(int, bits)) for bits in encrypted_text.split() if bits.isdigit()]
            if len(encrypted_bits_list[0]) == 8:
                # Decrypt ASCII-based encrypted text
                decrypted_text = sdes.decrypt_text(encrypted_bits_list)
            else:
                # Handle decryption of binary ciphertext
                decrypted_bits = [int(bit) for bit in encrypted_text.split()]
                decrypted_text = ''.join(map(str, sdes.decrypt(decrypted_bits)))
            
            self.decrypted_output.setText(decrypted_text)
        except ValueError as e:
            QMessageBox.critical(self, "Input Error", str(e))
        except SyntaxError:
            QMessageBox.critical(self, "Input Error", "Invalid encrypted bits format.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SDESApp()
    ex.show()
    sys.exit(app.exec_())