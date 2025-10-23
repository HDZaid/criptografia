# gui/main_window.py
from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout
from gui.tabs.tab_keys import TabKeys
from gui.tabs.tab_encrypt import TabEncrypt
from gui.tabs.tab_sign import TabSign

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Herramienta Criptográfica - PyQt5")
        self.resize(900, 600)
        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        layout = QVBoxLayout()
        central.setLayout(layout)

        self.tabs = QTabWidget()
        # Crear instancias de pestañas
        self.tab_keys = TabKeys()
        self.tab_encrypt = TabEncrypt()
        self.tab_sign = TabSign()

        # Conectar si se necesita compartir estado (por ejemplo claves)
        # Vamos a exponer métodos en cada pestaña para set/get claves.
        # Añadir pestañas
        self.tabs.addTab(self.tab_keys, "Gestión de claves")
        self.tabs.addTab(self.tab_encrypt, "Cifrar / Descifrar")
        self.tabs.addTab(self.tab_sign, "Firma digital")

        layout.addWidget(self.tabs)
        self.setCentralWidget(central)

        # Si se quiere sincronizar: conectar señales simples (opcional).
        # Por simplicidad: las pestañas leerán archivos PEM por su cuenta o usarán la carpeta data.
