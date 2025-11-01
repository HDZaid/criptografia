# gui/tabs/tab_sign.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, 
    QFileDialog, QMessageBox, QGroupBox, QScrollArea
)
from PyQt5.QtCore import Qt
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

        # ============ PASO 1 Y 2: CARGAR CLAVES LADO A LADO ============
        top_layout = QHBoxLayout()
        top_layout.setSpacing(12)

        # ---- LADO IZQUIERDO: CARGAR CLAVE PRIVADA ----
        private_group = self._create_section("PASO 1: CARGAR CLAVE PRIVADA")
        private_layout = QVBoxLayout()
        private_layout.addWidget(QLabel("Para firmar documentos:"))
        self.btn_load_private = QPushButton("Cargar Clave Privada (.pem)")
        self.btn_load_private.setMinimumHeight(50)
        self.btn_load_private.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 11pt; padding: 12px;")
        private_layout.addWidget(self.btn_load_private)
        private_layout.addStretch()
        private_group.setLayout(private_layout)
        top_layout.addWidget(private_group)

        # ---- LADO DERECHO: CARGAR CLAVE PÚBLICA ----
        public_group = self._create_section("PASO 2: CARGAR CLAVE PÚBLICA")
        public_layout = QVBoxLayout()
        public_layout.addWidget(QLabel("Para verificar firmas:"))
        self.btn_load_public = QPushButton("Cargar Clave Pública (.pem)")
        self.btn_load_public.setMinimumHeight(50)
        self.btn_load_public.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 11pt; padding: 12px;")
        public_layout.addWidget(self.btn_load_public)
        public_layout.addStretch()
        public_group.setLayout(public_layout)
        top_layout.addWidget(public_group)

        main_layout.addLayout(top_layout)

        # ============ ESTADO DE CLAVES ============
        status_group = self._create_section("📊 ESTADO DE CLAVES")
        status_layout = QVBoxLayout()
        self.lbl_keys_status = QLabel("Sin claves cargadas")
        self.lbl_keys_status.setAlignment(Qt.AlignCenter)
        self.lbl_keys_status.setStyleSheet("color: #666; font-size: 10pt; padding: 10px;")
        status_layout.addWidget(self.lbl_keys_status)
        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)

        # ============ SECCIÓN CENTRAL: FIRMAR Y VERIFICAR LADO A LADO ============
        center_layout = QHBoxLayout()
        center_layout.setSpacing(12)

        # ---- LADO IZQUIERDO: FIRMAR ----
        sign_group = self._create_section("PASO 3: FIRMAR UN DOCUMENTO")
        sign_layout = QVBoxLayout()
        
        sign_layout.addWidget(QLabel("Documento o mensaje a firmar:"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Escribe o carga el contenido a firmar...")
        self.input_text.setMinimumHeight(100)
        sign_layout.addWidget(self.input_text)
        
        sign_btn_layout = QVBoxLayout()
        self.btn_load_file = QPushButton("Cargar archivo .txt")
        self.btn_load_file.setMinimumHeight(35)
        self.btn_sign = QPushButton("FIRMAR DOCUMENTO")
        self.btn_sign.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 11pt; padding: 12px;")
        self.btn_sign.setMinimumHeight(45)
        sign_btn_layout.addWidget(self.btn_load_file)
        sign_btn_layout.addWidget(self.btn_sign)
        sign_layout.addLayout(sign_btn_layout)
        
        sign_group.setLayout(sign_layout)
        center_layout.addWidget(sign_group)

        # ---- LADO DERECHO: VERIFICAR ----
        verify_group = self._create_section("PASO 4: VERIFICAR UNA FIRMA")
        verify_layout = QVBoxLayout()
        
        verify_layout.addWidget(QLabel("Firma (Base64):"))
        self.input_signature = QTextEdit()
        self.input_signature.setPlaceholderText("Pega la firma en Base64 aquí...")
        self.input_signature.setMinimumHeight(100)
        verify_layout.addWidget(self.input_signature)
        
        verify_btn_layout = QVBoxLayout()
        verify_spacer = QLabel("")  # Espaciador para alineación
        self.btn_verify = QPushButton("VERIFICAR FIRMA")
        self.btn_verify.setStyleSheet("background-color: #107C10; font-weight: bold; font-size: 11pt; padding: 12px;")
        self.btn_verify.setMinimumHeight(45)
        verify_btn_layout.addWidget(verify_spacer)
        verify_btn_layout.addWidget(self.btn_verify)
        verify_layout.addLayout(verify_btn_layout)
        
        verify_group.setLayout(verify_layout)
        center_layout.addWidget(verify_group)

        main_layout.addLayout(center_layout, 1)

        # ============ RESULTADOS ============
        result_group = self._create_section("📊 RESULTADOS")
        result_layout = QVBoxLayout()
        
        # Contenedor con dos columnas para resultados
        result_container = QHBoxLayout()
        result_container.setSpacing(12)

        # Resultado de firma
        signature_col = QVBoxLayout()
        signature_col.addWidget(QLabel("🔐 Tu firma (Base64):"))
        self.output_signature = QTextEdit()
        self.output_signature.setReadOnly(True)
        self.output_signature.setMinimumHeight(80)
        signature_col.addWidget(self.output_signature)
        result_container.addLayout(signature_col)

        # Resultado de verificación
        verify_col = QVBoxLayout()
        verify_col.addWidget(QLabel("🔍 Estado de verificación:"))
        self.lbl_result = QLabel("⏳ Pendiente")
        self.lbl_result.setAlignment(Qt.AlignCenter)
        self.lbl_result.setStyleSheet("font-size: 14pt; font-weight: bold; color: #666; padding: 20px;")
        verify_col.addWidget(self.lbl_result)
        result_container.addLayout(verify_col)

        result_layout.addLayout(result_container)
        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)
        
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
            self.lbl_keys_status.setText(f"Clave privada: {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")

    def load_public(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave pública", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self.public_key = load_public_key_from_pem(f.read())
            self.lbl_keys_status.setText(f"Clave pública: {os.path.basename(path)}")
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
            QMessageBox.information(self, "Listo", "Documento firmado. Cópialo del área de resultados.")
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
            if ok:
                self.lbl_result.setText("FIRMA VÁLIDA")
                self.lbl_result.setStyleSheet("font-size: 14pt; font-weight: bold; color: #107C10; padding: 20px;")
            else:
                self.lbl_result.setText("FIRMA INVÁLIDA")
                self.lbl_result.setStyleSheet("font-size: 14pt; font-weight: bold; color: #D32F2F; padding: 20px;")
            QMessageBox.information(self, "Verificación", "Verificación completada.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error:\n{e}")