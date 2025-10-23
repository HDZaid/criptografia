# gui/tabs/tab_encrypt.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QFileDialog, QMessageBox
)
from utils.message_utils import text_to_bytes, bytes_to_text, bytes_to_base64_str, base64_str_to_bytes
from crypto.encryption_manager import encrypt_with_public, decrypt_with_private
from crypto.key_manager import load_public_key_from_pem, load_private_key_from_pem
import os

class TabEncrypt(QWidget):
    def __init__(self):
        super().__init__()
        self.public_key = None
        self.private_key = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout()

        # Input / file
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Escribe el mensaje aquí o carga un archivo...")
        layout.addWidget(QLabel("Mensaje / texto:"))
        layout.addWidget(self.input_text)

        file_btn_layout = QHBoxLayout()
        self.btn_load_file = QPushButton("Cargar archivo de texto")
        self.btn_load_public = QPushButton("Cargar clave pública (.pem)")
        self.btn_load_private = QPushButton("Cargar clave privada (.pem)")
        file_btn_layout.addWidget(self.btn_load_file)
        file_btn_layout.addWidget(self.btn_load_public)
        file_btn_layout.addWidget(self.btn_load_private)
        layout.addLayout(file_btn_layout)

        # Encrypt / decrypt
        action_layout = QHBoxLayout()
        self.btn_encrypt = QPushButton("Cifrar con clave pública")
        self.btn_decrypt = QPushButton("Descifrar con clave privada (base64)")
        action_layout.addWidget(self.btn_encrypt)
        action_layout.addWidget(self.btn_decrypt)
        layout.addLayout(action_layout)

        # Outputs
        layout.addWidget(QLabel("Texto cifrado (Base64):"))
        self.output_cipher = QTextEdit()
        self.output_cipher.setReadOnly(True)
        layout.addWidget(self.output_cipher)

        layout.addWidget(QLabel("Texto descifrado:"))
        self.output_plain = QTextEdit()
        self.output_plain.setReadOnly(True)
        layout.addWidget(self.output_plain)

        self.setLayout(layout)

        # conexiones
        self.btn_load_file.clicked.connect(self.load_file)
        self.btn_load_public.clicked.connect(self.load_public)
        self.btn_load_private.clicked.connect(self.load_private)
        self.btn_encrypt.clicked.connect(self.encrypt_text)
        self.btn_decrypt.clicked.connect(self.decrypt_text)

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo de texto", filter="Text Files (*.txt);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.input_text.setPlainText(content)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar el archivo:\n{e}")

    def load_public(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave pública", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                pem = f.read()
            self.public_key = load_public_key_from_pem(pem)
            QMessageBox.information(self, "Clave pública", f"Clave pública cargada: {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar la clave pública:\n{e}")

    def load_private(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave privada", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                pem = f.read()
            self.private_key = load_private_key_from_pem(pem)
            QMessageBox.information(self, "Clave privada", f"Clave privada cargada: {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar la clave privada:\n{e}")

    def encrypt_text(self):
        if not self.public_key:
            QMessageBox.warning(self, "Atención", "Carga la clave pública antes de cifrar.")
            return
        plain = self.input_text.toPlainText()
        if plain == "":
            QMessageBox.warning(self, "Atención", "Escribe o carga un mensaje para cifrar.")
            return
        try:
            ciphertext = encrypt_with_public(self.public_key, text_to_bytes(plain))
            b64 = bytes_to_base64_str(ciphertext)
            self.output_cipher.setPlainText(b64)
            QMessageBox.information(self, "Cifrado", "Mensaje cifrado correctamente. Copia el Base64 resultante.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al cifrar:\n{e}")

    def decrypt_text(self):
        if not self.private_key:
            QMessageBox.warning(self, "Atención", "Carga la clave privada antes de descifrar.")
            return
        b64 = self.output_cipher.toPlainText().strip()
        if b64 == "":
            # también permitir que el usuario pegue base64 en la caja de cifrado
            b64 = self.input_text.toPlainText().strip()
            if b64 == "":
                QMessageBox.warning(self, "Atención", "Pega o escribe el Base64 del texto cifrado en la caja de 'Texto cifrado' o en el campo de entrada.")
                return
        try:
            ciphertext = base64_str_to_bytes(b64)
            plaintext = decrypt_with_private(self.private_key, ciphertext)
            self.output_plain.setPlainText(bytes_to_text(plaintext))
            QMessageBox.information(self, "Descifrado", "Mensaje descifrado correctamente.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al descifrar:\n{e}")
