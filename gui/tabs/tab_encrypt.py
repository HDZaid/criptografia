# gui/tabs/tab_encrypt.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, 
    QFileDialog, QMessageBox, QGroupBox, QScrollArea
)
from PyQt5.QtCore import Qt
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
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # ============ PASO 1: CARGAR CLAVES ============
        keys_group = self._create_section("PASO 1: CARGAR CLAVES")
        keys_layout = QVBoxLayout()
        
        keys_h = QHBoxLayout()
        self.btn_load_public = QPushButton("📁 Clave Pública (.pem)")
        self.btn_load_private = QPushButton("📁 Clave Privada (.pem)")
        keys_h.addWidget(self.btn_load_public)
        keys_h.addWidget(self.btn_load_private)
        keys_layout.addLayout(keys_h)
        
        self.lbl_keys_status = QLabel("⏳ Sin claves cargadas")
        self.lbl_keys_status.setStyleSheet("color: #666; font-size: 9pt;")
        keys_layout.addWidget(self.lbl_keys_status)
        keys_group.setLayout(keys_layout)
        main_layout.addWidget(keys_group)

        # ============ SECCIÓN CENTRAL: CIFRAR Y DESCIFRAR LADO A LADO ============
        center_layout = QHBoxLayout()
        center_layout.setSpacing(12)

        # ---- LADO IZQUIERDO: CIFRAR ----
        encrypt_group = self._create_section("🔐 PASO 2: CIFRAR UN MENSAJE")
        encrypt_layout = QVBoxLayout()
        
        encrypt_layout.addWidget(QLabel("📝 Tu mensaje (texto plano):"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Escribe el mensaje que deseas cifrar...")
        self.input_text.setMinimumHeight(100)
        encrypt_layout.addWidget(self.input_text)
        
        encrypt_btn_layout = QVBoxLayout()
        self.btn_load_file = QPushButton("📁 Cargar archivo .txt")
        self.btn_load_file.setMinimumHeight(35)
        self.btn_encrypt = QPushButton("🔐 CIFRAR MENSAJE")
        self.btn_encrypt.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 11pt; padding: 12px;")
        self.btn_encrypt.setMinimumHeight(45)
        encrypt_btn_layout.addWidget(self.btn_load_file)
        encrypt_btn_layout.addWidget(self.btn_encrypt)
        encrypt_layout.addLayout(encrypt_btn_layout)
        
        encrypt_group.setLayout(encrypt_layout)
        center_layout.addWidget(encrypt_group)

        # ---- LADO DERECHO: DESCIFRAR ----
        decrypt_group = self._create_section("🔓 PASO 3: DESCIFRAR UN MENSAJE")
        decrypt_layout = QVBoxLayout()
        
        decrypt_layout.addWidget(QLabel("🔒 Mensaje cifrado (Base64):"))
        self.input_cipher = QTextEdit()
        self.input_cipher.setPlaceholderText("Pega aquí el mensaje cifrado en Base64...")
        self.input_cipher.setMinimumHeight(100)
        decrypt_layout.addWidget(self.input_cipher)
        
        decrypt_btn_layout = QVBoxLayout()
        decrypt_spacer = QLabel("")  # Espaciador para alineación
        self.btn_decrypt = QPushButton("🔓 DESCIFRAR MENSAJE")
        self.btn_decrypt.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 11pt; padding: 12px;")
        self.btn_decrypt.setMinimumHeight(45)
        decrypt_btn_layout.addWidget(decrypt_spacer)
        decrypt_btn_layout.addWidget(self.btn_decrypt)
        decrypt_layout.addLayout(decrypt_btn_layout)
        
        decrypt_group.setLayout(decrypt_layout)
        center_layout.addWidget(decrypt_group)

        main_layout.addLayout(center_layout, 1)  # Le damos peso 1 para que se expanda

        # ============ RESULTADOS ============
        result_group = self._create_section("RESULTADOS")
        result_layout = QVBoxLayout()
        
        # Contenedor con dos columnas para resultados
        result_container = QHBoxLayout()
        result_container.setSpacing(12)

        # Resultado de cifrado
        cipher_col = QVBoxLayout()
        cipher_col.addWidget(QLabel("📋 Texto cifrado (Base64):"))
        self.output_cipher = QTextEdit()
        self.output_cipher.setReadOnly(True)
        self.output_cipher.setMinimumHeight(80)
        cipher_col.addWidget(self.output_cipher)
        result_container.addLayout(cipher_col)

        # Resultado de descifrado
        plain_col = QVBoxLayout()
        plain_col.addWidget(QLabel("📝 Texto descifrado:"))
        self.output_plain = QTextEdit()
        self.output_plain.setReadOnly(True)
        self.output_plain.setMinimumHeight(80)
        plain_col.addWidget(self.output_plain)
        result_container.addLayout(plain_col)

        result_layout.addLayout(result_container)
        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)
        
        self.setLayout(main_layout)

        # Conexiones
        self.btn_load_file.clicked.connect(self.load_file)
        self.btn_load_public.clicked.connect(self.load_public)
        self.btn_load_private.clicked.connect(self.load_private)
        self.btn_encrypt.clicked.connect(self.encrypt_text)
        self.btn_decrypt.clicked.connect(self.decrypt_text)

    def _create_section(self, title):
        group = QGroupBox(title)
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 10pt;
                color: #0078D7;
                border: 2px solid #0078D7;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
        """)
        return group

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", filter="Text Files (*.txt);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.input_text.setPlainText(f.read())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar:\n{e}")

    def load_public(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave pública", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self.public_key = load_public_key_from_pem(f.read())
            self.lbl_keys_status.setText(f"✅ Clave pública: {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")

    def load_private(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave privada", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self.private_key = load_private_key_from_pem(f.read())
            self.lbl_keys_status.setText(f"✅ Clave privada: {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")

    def encrypt_text(self):
        if not self.public_key:
            QMessageBox.warning(self, "⚠️ Atención", "Carga la clave pública primero")
            return
        plain = self.input_text.toPlainText().strip()
        if not plain:
            QMessageBox.warning(self, "⚠️ Atención", "Escribe un mensaje para cifrar")
            return
        try:
            ciphertext = encrypt_with_public(self.public_key, text_to_bytes(plain))
            b64 = bytes_to_base64_str(ciphertext)
            self.output_cipher.setPlainText(b64)
            QMessageBox.information(self, "✅ Listo", "Mensaje cifrado. Cópialo del área de resultados.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")

    def decrypt_text(self):
        if not self.private_key:
            QMessageBox.warning(self, "⚠️ Atención", "Carga la clave privada primero")
            return
        b64 = self.input_cipher.toPlainText().strip()
        if not b64:
            QMessageBox.warning(self, "⚠️ Atención", "Pega un mensaje cifrado en Base64")
            return
        try:
            ciphertext = base64_str_to_bytes(b64)
            plaintext = decrypt_with_private(self.private_key, ciphertext)
            self.output_plain.setPlainText(bytes_to_text(plaintext))
            QMessageBox.information(self, "✅ Listo", "Mensaje descifrado correctamente.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")