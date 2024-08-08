# This code sets up a simple password manager with GUI, encryption, and decryption functions.
#You can save passwords, encrypt them, and display decrypted passwords in the GUI

# Create basic GUI for password manager using PyQt5:

import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit

# Uses cryptography library to encrypt/decrypt passwords.
# Imports required modules and generates key

from cryptography.fernet import Fernet

class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.passwords = []

    def initUI(self):
        self.setWindowTitle('Password Manager')

        layout = QVBoxLayout()

        self.label = QLabel('Enter your password:', self)
        layout.addWidget(self.label)

        self.password_input = QLineEdit(self)
        layout.addWidget(self.password_input)

        # Connects buttons to functions (line 36 & 40)

        self.save_button = QPushButton('Save Password', self)
        self.save_button.clicked.connect(self.save_password)
        layout.addWidget(self.save_button)

        self.show_passwords_button = QPushButton('Show Passwords', self)
        self.show_passwords_button.clicked.connect(self.show_passwords)
        layout.addWidget(self.show_passwords_button)

        self.passwords_display = QTextEdit(self)
        self.passwords_display.setReadOnly(True)
        layout.addWidget(self.passwords_display)

        self.setLayout(layout)

    # Adds methods to encrypt/decrypt passwords

    def encrypt_password(self, password):
        return self.cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()

    # Add functions to save and display passwords

    def save_password(self):
        password = self.password_input.text()
        if password:
            encrypted_password = self.encrypt_password(password)
            self.passwords.append(encrypted_password)
            self.password_input.clear()

    def show_passwords(self):
        self.passwords_display.clear()
        for encrypted_password in self.passwords:
            decrypted_password = self.decrypt_password(encrypted_password)
            self.passwords_display.append(decrypted_password)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PasswordManager()
    ex.show()
    sys.exit(app.exec_())























# Callie Gardunio
#TechJunkie12