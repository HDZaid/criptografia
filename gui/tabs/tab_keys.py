# gui/tabs/tab_keys.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QFileDialog, 
    QMessageBox, QTextEdit, QGroupBox, QScrollArea
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from crypto.key_manager import (
    generate_rsa_keypair, private_key_to_pem, public_key_to_pem, 
    load_private_key_from_pem, load_public_key_from_pem
)
from utils.file_utils import write_bytes_file
import os

class TabKeys(QWidget):
    def __init__(self):
        super().__init__()
        self.private_key = None
        self.public_key = None
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # ============ SECCIÓN 1 Y 2: GENERAR Y GUARDAR LADO A LADO ============
        top_layout = QHBoxLayout()
        top_layout.setSpacing(12)

        # ---- LADO IZQUIERDO: GENERAR CLAVES ----
        gen_group = self._create_section(
            "📝 PASO 1: GENERAR PAR DE CLAVES",
            "Crea un nuevo par de claves RSA (pública y privada)"
        )
        gen_layout = QVBoxLayout()
        gen_layout.addWidget(QLabel("Genera un nuevo par de claves RSA 2048"))
        self.btn_generate = QPushButton("Generar Claves RSA 2048")
        self.btn_generate.setMinimumHeight(50)
        self.btn_generate.setStyleSheet("""
            QPushButton {
                background-color: #107C10;
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #0B5E0B;
            }
            QPushButton:pressed {
                background-color: #084B08;
            }
        """)
        gen_layout.addWidget(self.btn_generate)
        gen_layout.addStretch()
        gen_group.setLayout(gen_layout)
        top_layout.addWidget(gen_group)

        # ---- LADO DERECHO: GUARDAR CLAVES ----
        save_group = self._create_section(
            "💾 PASO 2: GUARDAR CLAVES",
            "Guarda las claves generadas en archivos .pem"
        )
        save_layout = QVBoxLayout()
        save_layout.addWidget(QLabel("Guarda las claves en archivos .pem"))
        self.btn_save = QPushButton("Guardar Claves en Carpeta")
        self.btn_save.setMinimumHeight(50)
        self.btn_save.setStyleSheet("""
            QPushButton {
                background-color: #107C10;
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #0B5E0B;
            }
            QPushButton:pressed {
                background-color: #084B08;
            }
        """)
        save_layout.addWidget(self.btn_save)
        save_layout.addStretch()
        save_group.setLayout(save_layout)
        top_layout.addWidget(save_group)

        main_layout.addLayout(top_layout)

        # ============ SECCIÓN 3: CARGAR CLAVES ============
        load_group = self._create_section(
            "📂 PASO 3: CARGAR CLAVES EXISTENTES",
            "Carga claves .pem que ya tengas guardadas"
        )
        load_layout = QVBoxLayout()
        load_layout.addWidget(QLabel("Carga claves que ya tengas en tu computadora:"))
        
        # Botones en dos columnas
        btn_row = QHBoxLayout()
        self.btn_load_private = QPushButton("📁 Cargar Clave Privada")
        self.btn_load_private.setMinimumHeight(40)
        self.btn_load_public = QPushButton("📁 Cargar Clave Pública")
        self.btn_load_public.setMinimumHeight(40)
        btn_row.addWidget(self.btn_load_private)
        btn_row.addWidget(self.btn_load_public)
        load_layout.addLayout(btn_row)
        load_group.setLayout(load_layout)
        main_layout.addWidget(load_group)

        # ============ SECCIÓN 4: ESTADO Y RESULTADOS ============
        result_layout = QHBoxLayout()
        result_layout.setSpacing(12)

        # ---- ESTADO ----
        status_group = self._create_section(
            "ESTADO ACTUAL",
            "Muestra el estado de las claves"
        )
        status_layout = QVBoxLayout()
        self.lbl_status = QLabel("⏳ Sin claves generadas")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setAlignment(Qt.AlignCenter)
        self.lbl_status.setStyleSheet("font-size: 11pt; color: #1A1A1A; font-weight: bold; padding: 20px;")
        status_layout.addWidget(self.lbl_status)
        status_group.setLayout(status_layout)
        result_layout.addWidget(status_group)

        # ---- INFORMACIÓN ----
        preview_group = self._create_section(
            "INFORMACIÓN",
            "Detalles sobre el proceso"
        )
        preview_layout = QVBoxLayout()
        self.text_preview = QTextEdit()
        self.text_preview.setReadOnly(True)
        self.text_preview.setMinimumHeight(120)
        self.text_preview.setPlainText(
            "1. Genera un par de claves RSA\n"
            "2. Guarda las claves en archivos .pem\n"
            "3. O carga claves existentes\n\n"
            "Estas claves se usarán en:\n"
            "• Cifrar/Descifrar\n"
            "• Firmar Digitalmente"
        )
        preview_layout.addWidget(self.text_preview)
        preview_group.setLayout(preview_layout)
        result_layout.addWidget(preview_group)

        main_layout.addLayout(result_layout, 1)
        main_layout.addStretch()
        self.setLayout(main_layout)

        # Conexiones
        self.btn_generate.clicked.connect(self.generate_keys)
        self.btn_save.clicked.connect(self.save_keys_dialog)
        self.btn_load_private.clicked.connect(self.load_private_dialog)
        self.btn_load_public.clicked.connect(self.load_public_dialog)

    def _create_section(self, title, subtitle):
        group = QGroupBox(title)
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
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

    def generate_keys(self):
        try:
            priv, pub = generate_rsa_keypair(2048)
            self.private_key = priv
            self.public_key = pub
            self.lbl_status.setText("✅ Claves Generadas\n(RSA 2048)")
            self.text_preview.setPlainText(
                "✅ Claves RSA 2048 generadas correctamente\n\n"
                "Próximos pasos:\n"
                "1. Haz clic en 'Guardar Claves en Carpeta'\n"
                "2. O ve a las pestañas de Cifrar/Descifrar y Firmar"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudieron generar las claves:\n{e}")

    def save_keys_dialog(self):
        if not self.private_key or not self.public_key:
            QMessageBox.warning(self, "Atención", "Genera claves primero en 'PASO 1'")
            return
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta para guardar")
        if not folder:
            return
        try:
            priv_pem = private_key_to_pem(self.private_key)
            pub_pem = public_key_to_pem(self.public_key)
            private_path = os.path.join(folder, "private_key.pem")
            public_path = os.path.join(folder, "public_key.pem")
            write_bytes_file(private_path, priv_pem)
            write_bytes_file(public_path, pub_pem)
            self.lbl_status.setText("✅ Claves Guardadas")
            self.text_preview.setPlainText(f"✅ Claves guardadas exitosamente en:\n\n{folder}")
            QMessageBox.information(self, "✅ Guardado", f"Claves guardadas en:\n{folder}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al guardar:\n{e}")

    def load_private_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave privada", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            priv = load_private_key_from_pem(data)
            self.private_key = priv
            self.lbl_status.setText(f"✅ Clave Privada\nCargada")
            self.text_preview.setPlainText(f"✅ Archivo: {os.path.basename(path)}\n\n"
                                          "La clave privada está lista para:\n"
                                          "• Descifrar mensajes\n"
                                          "• Firmar documentos")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al cargar:\n{e}")

    def load_public_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave pública", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            pub = load_public_key_from_pem(data)
            self.public_key = pub
            self.lbl_status.setText(f"✅ Clave Pública\nCargada")
            self.text_preview.setPlainText(f"✅ Archivo: {os.path.basename(path)}\n\n"
                                          "La clave pública está lista para:\n"
                                          "• Cifrar mensajes\n"
                                          "• Verificar firmas")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al cargar:\n{e}")

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key