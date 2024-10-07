import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QMessageBox)
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt

class SDES:
    # The SDES class implementation is the same as provided earlier
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

class SDESGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('SDES Encryption/Decryption Tool')
        self.setGeometry(100, 100, 450, 400)
        self.setStyleSheet("background-color: #e3f2fd;")

        layout = QVBoxLayout()

        # Title
        title = QLabel("S-DES Encryption/Decryption Tool")
        title.setFont(QFont('Arial', 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #0d47a1;")
        layout.addWidget(title)

        # Key input
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("e.g. 1010000010")
        self.key_input.setFont(QFont('Arial', 14))
        self.key_input.setStyleSheet("padding: 10px; border: 2px solid #90caf9; border-radius: 5px;")
        layout.addWidget(QLabel("10-bit Key:", self))
        layout.addWidget(self.key_input)

        # Plaintext input
        self.plaintext_input = QLineEdit(self)
        self.plaintext_input.setPlaceholderText("e.g. 10010111")
        self.plaintext_input.setFont(QFont('Arial', 14))
        self.plaintext_input.setStyleSheet("padding: 10px; border: 2px solid #90caf9; border-radius: 5px;")
        layout.addWidget(QLabel("8-bit Plaintext:", self))
        layout.addWidget(self.plaintext_input)

        # Encrypt Button
        encrypt_button = QPushButton("Encrypt", self)
        encrypt_button.setFont(QFont('Arial', 14))
        encrypt_button.setStyleSheet("background-color: #2196f3; color: white; padding: 10px; border-radius: 5px;")
        encrypt_button.clicked.connect(self.encrypt_text)
        layout.addWidget(encrypt_button)

        # Ciphertext Output
        self.ciphertext_output = QLineEdit(self)
        self.ciphertext_output.setReadOnly(True)
        self.ciphertext_output.setFont(QFont('Arial', 14))
        self.ciphertext_output.setStyleSheet("padding: 10px; border: 2px solid #90caf9; border-radius: 5px;")
        layout.addWidget(QLabel("Ciphertext:", self))
        layout.addWidget(self.ciphertext_output)

        # Decrypt Button
        decrypt_button = QPushButton("Decrypt", self)
        decrypt_button.setFont(QFont('Arial', 14))
        decrypt_button.setStyleSheet("background-color: #4caf50; color: white; padding: 10px; border-radius: 5px;")
        decrypt_button.clicked.connect(self.decrypt_text)
        layout.addWidget(decrypt_button)

        # Decrypted Text Output
        self.decrypted_output = QLineEdit(self)
        self.decrypted_output.setReadOnly(True)
        self.decrypted_output.setFont(QFont('Arial', 14))
        self.decrypted_output.setStyleSheet("padding: 10px; border: 2px solid #90caf9; border-radius: 5px;")
        layout.addWidget(QLabel("Decrypted Text:", self))
        layout.addWidget(self.decrypted_output)

        self.setLayout(layout)

    def encrypt_text(self):
        key = self.parse_input(self.key_input.text(), 10)
        plaintext = self.parse_input(self.plaintext_input.text(), 8)

        if key and plaintext:
            sdes = SDES(key)
            ciphertext = sdes.encrypt(plaintext)
            self.ciphertext_output.setText(''.join(map(str, ciphertext)))

    def decrypt_text(self):
        key = self.parse_input(self.key_input.text(), 10)
        ciphertext = self.parse_input(self.ciphertext_output.text(), 8)

        if key and ciphertext:
            sdes = SDES(key)
            plaintext = sdes.decrypt(ciphertext)
            self.decrypted_output.setText(''.join(map(str, plaintext)))

    def parse_input(self, text, expected_length):
        if len(text) != expected_length or not set(text).issubset({'0', '1'}):
            self.show_message(f"Input must be {expected_length} bits long (0s and 1s only).")
            return None
        return [int(bit) for bit in text]

    def show_message(self, message):
        msg = QMessageBox()
        msg.setWindowTitle("Error")
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SDESGUI()
    ex.show()
    sys.exit(app.exec_())