# utils/file_utils.py
from pathlib import Path

def read_text_file(path: str, encoding: str = 'utf-8') -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {path}")
    return p.read_text(encoding=encoding)

def write_text_file(path: str, text: str, encoding: str = 'utf-8'):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding=encoding)

def write_bytes_file(path: str, data: bytes):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

def read_bytes_file(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {path}")
    return p.read_bytes(path)
