# gui/tabs/tab_keys.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QFileDialog, QMessageBox, QTextEdit
)
from crypto.key_manager import generate_rsa_keypair, private_key_to_pem, public_key_to_pem, load_private_key_from_pem, load_public_key_from_pem
from utils.message_utils import bytes_to_text, bytes_to_base64_str
from utils.file_utils import write_bytes_file
import os

class TabKeys(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.private_key = None
        self.public_key = None

    def _init_ui(self):
        layout = QVBoxLayout()

        # Botones principales
        btn_layout = QHBoxLayout()
        self.btn_generate = QPushButton("Generar par de claves RSA")
        self.btn_save = QPushButton("Guardar claves (.pem)")
        self.btn_load_private = QPushButton("Cargar clave privada (.pem)")
        self.btn_load_public = QPushButton("Cargar clave pública (.pem)")

        btn_layout.addWidget(self.btn_generate)
        btn_layout.addWidget(self.btn_save)
        btn_layout.addWidget(self.btn_load_private)
        btn_layout.addWidget(self.btn_load_public)

        layout.addLayout(btn_layout)

        # Labels / Text preview
        self.lbl_status = QLabel("Estado: sin claves generadas")
        layout.addWidget(self.lbl_status)

        self.text_preview = QTextEdit()
        self.text_preview.setReadOnly(True)
        layout.addWidget(self.text_preview)

        self.setLayout(layout)

        # Conexiones
        self.btn_generate.clicked.connect(self.generate_keys)
        self.btn_save.clicked.connect(self.save_keys_dialog)
        self.btn_load_private.clicked.connect(self.load_private_dialog)
        self.btn_load_public.clicked.connect(self.load_public_dialog)

    def generate_keys(self):
        try:
            priv, pub = generate_rsa_keypair(2048)
            self.private_key = priv
            self.public_key = pub
            self.lbl_status.setText("Estado: claves generadas (RSA 2048)")
            self.text_preview.setPlainText("Claves generadas. Guarda las claves en archivos .pem para usarlas en cifrado/firmas.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudieron generar las claves:\n{e}")

    def save_keys_dialog(self):
        if not self.private_key or not self.public_key:
            QMessageBox.warning(self, "Atención", "No hay claves para guardar. Genera o carga claves primero.")
            return
        # Pedir carpeta
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta para guardar claves")
        if not folder:
            return
        try:
            priv_pem = private_key_to_pem(self.private_key)
            pub_pem = public_key_to_pem(self.public_key)
            private_path = os.path.join(folder, "private_key.pem")
            public_path = os.path.join(folder, "public_key.pem")
            write_bytes_file(private_path, priv_pem)
            write_bytes_file(public_path, pub_pem)
            QMessageBox.information(self, "Guardado", f"Claves guardadas en:\n{private_path}\n{public_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudieron guardar las claves:\n{e}")

    def load_private_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave privada", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            priv = load_private_key_from_pem(data)
            self.private_key = priv
            self.lbl_status.setText(f"Estado: clave privada cargada ({os.path.basename(path)})")
            self.text_preview.setPlainText("Clave privada cargada. Puedes usarla para descifrar y firmar.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar la clave privada:\n{e}")

    def load_public_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar clave pública", filter="PEM Files (*.pem);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            pub = load_public_key_from_pem(data)
            self.public_key = pub
            self.lbl_status.setText(f"Estado: clave pública cargada ({os.path.basename(path)})")
            self.text_preview.setPlainText("Clave pública cargada. Puedes usarla para cifrar y verificar firmas.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar la clave pública:\n{e}")

    # Métodos públicos para que otras pestañas consulten claves (opcional)
    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key
