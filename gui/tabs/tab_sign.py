# gui/tabs/tab_sign.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, 
    QFileDialog, QMessageBox, QGroupBox
)
from crypto.signature_manager import sign_with_private, verify_with_public
from crypto.key_manager import load_private_key_from_pem, load_public_key_from_pem
from utils.message_utils import text_to_bytes, bytes_to_base64_str, base64_str_to_bytes
import os

class TabSign(QWidget):
    def __init__(self):
        super().__init__()
        self.private_key = None
        self.public_key = None
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # ============ PASO 1: CARGAR CLAVES ============
        keys_group = self._create_section("PASO 1: CARGAR CLAVES")
        keys_layout = QVBoxLayout()
        
        keys_h = QHBoxLayout()
        self.btn_load_private = QPushButton("📁 Clave Privada (.pem)")
        self.btn_load_public = QPushButton("📁 Clave Pública (.pem)")
        keys_h.addWidget(self.btn_load_private)
        keys_h.addWidget(self.btn_load_public)
        keys_layout.addLayout(keys_h)
        
        self.lbl_keys_status = QLabel("⏳ Sin claves cargadas")
        self.lbl_keys_status.setStyleSheet("color: #666; font-size: 9pt;")
        keys_layout.addWidget(self.lbl_keys_status)
        keys_group.setLayout(keys_layout)
        main_layout.addWidget(keys_group)

        # ============ PASO 2: FIRMAR ============
        sign_group = self._create_section("PASO 2: FIRMAR UN DOCUMENTO")
        sign_layout = QVBoxLayout()
        
        sign_layout.addWidget(QLabel("📄 Documento o mensaje a firmar:"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Escribe o carga el contenido a firmar...")
        self.input_text.setMaximumHeight(80)
        sign_layout.addWidget(self.input_text)
        
        sign_h = QHBoxLayout()
        self.btn_load_file = QPushButton("📁 Cargar archivo .txt")
        self.btn_sign = QPushButton("✍️ FIRMAR")
        self.btn_sign.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 10pt;")
        self.btn_sign.setMinimumHeight(35)
        sign_h.addWidget(self.btn_load_file)
        sign_h.addWidget(self.btn_sign)
        sign_layout.addLayout(sign_h)
        
        sign_group.setLayout(sign_layout)
        main_layout.addWidget(sign_group)

        # ============ PASO 3: VERIFICAR ============
        verify_group = self._create_section("PASO 3: VERIFICAR UNA FIRMA")
        verify_layout = QVBoxLayout()
        
        verify_layout.addWidget(QLabel("Firma (Base64):"))
        self.input_signature = QTextEdit()
        self.input_signature.setPlaceholderText("Pega la firma en Base64 aquí...")
        self.input_signature.setMaximumHeight(80)
        verify_layout.addWidget(self.input_signature)
        
        verify_h = QHBoxLayout()
        verify_h.addStretch()
        self.btn_verify = QPushButton("VERIFICAR FIRMA")
        self.btn_verify.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 10pt;")
        self.btn_verify.setMinimumHeight(35)
        self.btn_verify.setMinimumWidth(200)
        verify_h.addWidget(self.btn_verify)
        verify_layout.addLayout(verify_h)
        
        verify_group.setLayout(verify_layout)
        main_layout.addWidget(verify_group)

        # ============ RESULTADOS ============
        result_group = self._create_section("RESULTADOS")
        result_layout = QVBoxLayout()
        
        result_layout.addWidget(QLabel("🔐 Tu firma (Base64):"))
        self.output_signature = QTextEdit()
        self.output_signature.setReadOnly(True)
        self.output_signature.setMaximumHeight(70)
        result_layout.addWidget(self.output_signature)
        
        result_layout.addWidget(QLabel("🔍 Estado de verificación:"))
        self.lbl_result = QLabel("⏳ Pendiente")
        self.lbl_result.setStyleSheet("font-size: 11pt; font-weight: bold; color: #666;")
        result_layout.addWidget(self.lbl_result)
        
        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)
        
        main_layout.addStretch()
        self.setLayout(main_layout)

        # Conexiones
        self.btn_load_file.clicked.connect(self.load_file)
        self.btn_load_private.clicked.connect(self.load_private)
        self.btn_load_public.clicked.connect(self.load_public)
        self.btn_sign.clicked.connect(self.sign_message)
        self.btn_verify.clicked.connect(self.verify_signature)

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

    def sign_message(self):
        if not self.private_key:
            QMessageBox.warning(self, "⚠️ Atención", "Carga la clave privada primero")
            return
        msg = self.input_text.toPlainText().strip()
        if not msg:
            QMessageBox.warning(self, "⚠️ Atención", "Escribe un mensaje para firmar")
            return
        try:
            signature = sign_with_private(self.private_key, text_to_bytes(msg))
            b64 = bytes_to_base64_str(signature)
            self.output_signature.setPlainText(b64)
            QMessageBox.information(self, "✅ Listo", "Documento firmado. Cópialo del área de resultados.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")

    def verify_signature(self):
        if not self.public_key:
            QMessageBox.warning(self, "⚠️ Atención", "Carga la clave pública primero")
            return
        msg = self.input_text.toPlainText().strip()
        if not msg:
            QMessageBox.warning(self, "⚠️ Atención", "Escribe el mensaje original para verificar")
            return
        b64sig = self.input_signature.toPlainText().strip()
        if not b64sig:
            QMessageBox.warning(self, "⚠️ Atención", "Pega la firma en Base64")
            return
        try:
            signature = base64_str_to_bytes(b64sig)
            ok = verify_with_public(self.public_key, text_to_bytes(msg), signature)
            self.lbl_result.setText("✅ FIRMA VÁLIDA" if ok else "❌ FIRMA INVÁLIDA")
            self.lbl_result.setStyleSheet(
                "font-size: 11pt; font-weight: bold; color: #107C10;" if ok 
                else "font-size: 11pt; font-weight: bold; color: #D32F2F;"
            )
            QMessageBox.information(self, "✅ Verificación", "Verificación completada.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")