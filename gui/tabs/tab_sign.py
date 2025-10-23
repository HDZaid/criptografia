# gui/tabs/tab_sign.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QFileDialog, QMessageBox
)
from crypto.signature_manager import sign_with_private, verify_with_public
from crypto.key_manager import load_private_key_from_pem, load_public_key_from_pem
from utils.message_utils import text_to_bytes, bytes_to_base64_str, base64_str_to_bytes, bytes_to_text
import os

class TabSign(QWidget):
    def __init__(self):
        super().__init__()
        self.private_key = None
        self.public_key = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout()

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Escribe o carga el mensaje a firmar / verificar")
        layout.addWidget(QLabel("Mensaje:"))
        layout.addWidget(self.input_text)

        file_btn_layout = QHBoxLayout()
        self.btn_load_file = QPushButton("Cargar archivo de texto")
        self.btn_load_private = QPushButton("Cargar clave privada (.pem)")
        self.btn_load_public = QPushButton("Cargar clave pública (.pem)")
        file_btn_layout.addWidget(self.btn_load_file)
        file_btn_layout.addWidget(self.btn_load_private)
        file_btn_layout.addWidget(self.btn_load_public)
        layout.addLayout(file_btn_layout)

        action_layout = QHBoxLayout()
        self.btn_sign = QPushButton("Firmar con clave privada")
        self.btn_verify = QPushButton("Verificar firma (base64)")
        action_layout.addWidget(self.btn_sign)
        action_layout.addWidget(self.btn_verify)
        layout.addLayout(action_layout)

        layout.addWidget(QLabel("Firma (Base64):"))
        self.output_signature = QTextEdit()
        self.output_signature.setReadOnly(False)  # permitir pegar firma para verificar
        layout.addWidget(self.output_signature)

        layout.addWidget(QLabel("Resultado verificación:"))
        self.lbl_result = QLabel("N/A")
        layout.addWidget(self.lbl_result)

        self.setLayout(layout)

        # conexiones
        self.btn_load_file.clicked.connect(self.load_file)
        self.btn_load_private.clicked.connect(self.load_private)
        self.btn_load_public.clicked.connect(self.load_public)
        self.btn_sign.clicked.connect(self.sign_message)
        self.btn_verify.clicked.connect(self.verify_signature)

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

    def sign_message(self):
        if not self.private_key:
            QMessageBox.warning(self, "Atención", "Carga la clave privada antes de firmar.")
            return
        msg = self.input_text.toPlainText()
        if msg == "":
            QMessageBox.warning(self, "Atención", "Escribe o carga un mensaje para firmar.")
            return
        try:
            signature = sign_with_private(self.private_key, text_to_bytes(msg))
            b64 = bytes_to_base64_str(signature)
            self.output_signature.setPlainText(b64)
            QMessageBox.information(self, "Firmado", "Mensaje firmado correctamente. Copia el Base64 resultante.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al firmar:\n{e}")

    def verify_signature(self):
        if not self.public_key:
            QMessageBox.warning(self, "Atención", "Carga la clave pública antes de verificar.")
            return
        msg = self.input_text.toPlainText()
        if msg == "":
            QMessageBox.warning(self, "Atención", "Escribe o carga el mensaje a verificar.")
            return
        b64sig = self.output_signature.toPlainText().strip()
        if b64sig == "":
            QMessageBox.warning(self, "Atención", "Pega la firma (Base64) en el campo 'Firma (Base64)' para verificar.")
            return
        try:
            signature = base64_str_to_bytes(b64sig)
            ok = verify_with_public(self.public_key, text_to_bytes(msg), signature)
            self.lbl_result.setText("VÁLIDA ✅" if ok else "NO VÁLIDA ❌")
            QMessageBox.information(self, "Verificación", "Verificación completada.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al verificar:\n{e}")
