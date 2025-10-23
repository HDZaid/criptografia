# utils/message_utils.py
import base64

def bytes_to_base64_str(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def base64_str_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def text_to_bytes(s: str, encoding: str = 'utf-8') -> bytes:
    return s.encode(encoding)

def bytes_to_text(b: bytes, encoding: str = 'utf-8') -> str:
    return b.decode(encoding)
