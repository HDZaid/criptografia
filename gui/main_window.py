from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from gui.tabs.tab_keys import TabKeys
from gui.tabs.tab_encrypt import TabEncrypt
from gui.tabs.tab_sign import TabSign

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.colors = {
            'bg_dark': '#F2F2F7',      # Fondo principal gris muy claro
            'bg_light': '#FFFFFF',     # Fondo de widgets
            'accent': '#0078D7',       # Azul Microsoft / Windows
            'accent_hover': '#0096FF', # Azul claro
            'text_primary': '#1A1A1A', # Texto principal oscuro
            'text_secondary': '#4E4E4E', # Texto gris medio
            'danger': '#D32F2F',       # Rojo fuerte para alertas
        }
        
        self.setWindowTitle("Herramienta Criptografica")
        self.resize(1350, 850)
        self.setMinimumSize(1000, 550)
        
        self._apply_theme()
        self._init_ui()
        self.center_window()

    def center_window(self):
        frame = self.frameGeometry()
        center = self.screen().availableGeometry().center()
        frame.moveCenter(center)
        self.move(frame.topLeft())

    def _apply_theme(self):
        c = self.colors
        stylesheet = f"""
            QMainWindow {{
                background-color: {c['bg_dark']};
            }}

            QTabWidget::pane {{
                border: none;
                background-color: {c['bg_light']};
            }}

            QTabBar::tab {{
                background-color: {c['bg_dark']};
                color: {c['text_secondary']};
                padding: 12px 26px;      
                font-size: 12pt;          
                min-width: 180px;          
                margin-right: 2px;
                font-weight: 500;
                border-bottom: 2px solid transparent;
                border-radius: 4px 4px 0 0;
            }}

            QTabBar::tab:selected {{
                background-color: {c['bg_light']};
                color: {c['accent']};
                border-bottom: 3px solid {c['accent']};
            }}

            QTabBar::tab:hover:!selected {{
                color: {c['accent_hover']};
            }}

            QWidget {{
                background-color: {c['bg_light']};
                color: {c['text_primary']};
            }}

            QLabel {{
                color: {c['text_primary']};
            }}

            QPushButton {{
                background-color: {c['accent']};
                color: #FFFFFF;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 10pt;
            }}

            QPushButton:hover {{
                background-color: {c['accent_hover']};
            }}

            QPushButton:pressed {{
                background-color: {c['danger']};

            }}

            QPushButton:checked {{
            background-color: {c['accent_hover']};
            color: #000000;
            border: 2px solid {c['accent']};
            }}

            QLineEdit, QTextEdit {{
                background-color: #FFFFFF;
                color: {c['text_primary']};
                border: 1px solid {c['accent']};
                border-radius: 6px;
                padding: 6px;
                font-size: 10pt;
            }}

            QLineEdit:focus, QTextEdit:focus {{
                border: 2px solid {c['accent_hover']};
                background-color: #FFFFFF;
            }}

            QComboBox {{
                background-color: #FFFFFF;
                color: {c['text_primary']};
                border: 1px solid {c['accent']};
                border-radius: 6px;
                padding: 6px;
            }}

            QComboBox:focus {{
                border: 2px solid {c['accent_hover']};
            }}

            QComboBox QAbstractItemView {{
                background-color: #FFFFFF;
                color: {c['text_primary']};
                selection-background-color: {c['accent']};
            }}

            QMessageBox {{
                background-color: {c['bg_light']};
            }}

            QMessageBox QLabel {{
                color: {c['text_primary']};
            }}

            QGroupBox {{
                color: {c['text_primary']};
                border: 2px solid {c['accent']};
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }}

            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }}
        """
        self.setStyleSheet(stylesheet)

    def _init_ui(self):
        central = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        central.setLayout(layout)

        # Header
        header = self._create_header()
        layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tab_keys = TabKeys()
        self.tab_encrypt = TabEncrypt()
        self.tab_sign = TabSign()

        self.tabs.addTab(self.tab_keys, "Gestión de claves")
        self.tabs.addTab(self.tab_encrypt, "Cifrar / Descifrar")
        self.tabs.addTab(self.tab_sign, "Firma digital")

        self.tabs.setElideMode(Qt.ElideNone)       # No recorta texto
        self.tabs.setUsesScrollButtons(True)       # Si son muchos tabs, agrega flechas
        self.tabs.setDocumentMode(True)            # Diseño más moderno
        self.tabs.setMovable(True)                 # Permite reorganizar las pestañas

        layout.addWidget(self.tabs)
        self.setCentralWidget(central)

    def _create_header(self):
        c = self.colors
        header = QWidget()
        header.setStyleSheet(f"""
            QWidget {{
                background-color: {c['bg_dark']};
                border-bottom: 2px solid {c['accent']};
            }}
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(2)

        # Título centrado
        title = QLabel("Herramienta Criptográfica")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"""
            color: {c['accent']};
            font-weight: bold;
            text-decoration: none;
        """)
        layout.addWidget(title)
        header.setLayout(layout)
        return header