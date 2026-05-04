
"""
                                BLOWFISH original
===================================Cifra texto=======================================
en el terminal se debe instalar en la consola "pip install pycryptodome" para el uso.
=====================================================================================
"""

import sys
import base64
import hashlib
import struct
from getpass import getpass

try:
    from Crypto.Cipher import Blowfish
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("\n[ERROR] Instala la dependencia con:\n    pip install pycryptodome\n")
    sys.exit(1)


# ──────────────────────────────────────────────
#  NÚCLEO BLOWFISH
# ──────────────────────────────────────────────

def derivar_clave(password: str, salt: bytes) -> bytes:
    """Deriva una clave de 32 bytes desde una contraseña usando SHA-256 + salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)
 
 
def cifrar(datos: bytes, password: str) -> bytes:
    """
    Cifra datos arbitrarios con Blowfish (modo CBC + padding PKCS7).
    Formato del paquete cifrado:
        [4 bytes: longitud del salt] + [salt (16 bytes)] + [IV (8 bytes)] + [datos cifrados]
    """
    salt = get_random_bytes(16)
    clave = derivar_clave(password, salt)
    iv = get_random_bytes(8)                         # Blowfish usa bloques de 8 bytes
    cipher = Blowfish.new(clave, Blowfish.MODE_CBC, iv)
    datos_padded = pad(datos, Blowfish.block_size)
    cifrado = cipher.encrypt(datos_padded)
 
    paquete = struct.pack(">I", 16) + salt + iv + cifrado
    return paquete
 
 
def descifrar(paquete: bytes, password: str) -> bytes:
    """Invierte el proceso de cifrado y devuelve los datos originales."""
    offset = 0
    salt_len = struct.unpack(">I", paquete[offset:offset+4])[0]
    offset += 4
 
    salt = paquete[offset:offset+salt_len]
    offset += salt_len
 
    iv = paquete[offset:offset+8]
    offset += 8
 
    datos_cifrados = paquete[offset:]
 
    clave = derivar_clave(password, salt)
    cipher = Blowfish.new(clave, Blowfish.MODE_CBC, iv)
    datos_padded = cipher.decrypt(datos_cifrados)
    return unpad(datos_padded, Blowfish.block_size)


# ──────────────────────────────────────────────
#  CIFRADO / DESCIFRADO DE TEXTO
# ──────────────────────────────────────────────

def cifrar_texto(texto: str, password: str) -> str:
    """Cifra un texto y devuelve el resultado en Base64."""
    paquete = cifrar(texto.encode("utf-8"), password)
    return base64.b64encode(paquete).decode("ascii")


def descifrar_texto(texto_b64: str, password: str) -> str:
    """Descifra un texto cifrado en Base64 y devuelve el texto original."""
    paquete = base64.b64decode(texto_b64.encode("ascii"))
    return descifrar(paquete, password).decode("utf-8")


# ──────────────────────────────────────────────
#  INTERFAZ
# ──────────────────────────────────────────────

def banner():
    print("\n Algoritmo: Blowfish CBC + PBKDF2-SHA256 \n")


def main():
    banner()
    while True:
        print("  [1] Cifrar texto")
        print("  [2] Descifrar texto")
        print("  [0] Salir")
        opcion = input("\n  Elige opción: ").strip()

        if opcion == "1":
            print("\n── CIFRAR ────────────────────────────────────────")
            texto    = input("  Texto a cifrar: ")
            password = getpass("  Contraseña: ")
            resultado = cifrar_texto(texto, password)
            print("\n  Texto cifrado (Base64):\n")
            for i in range(0, len(resultado), 64):
                print("  " + resultado[i:i+64])
            print()

        elif opcion == "2":
            print("\n── DESCIFRAR ─────────────────────────────────────")
            print("  Pega el texto cifrado y presiona Enter dos veces:")
            lineas = []
            while True:
                linea = input()
                if linea == "":
                    break
                lineas.append(linea.strip())
            cifrado_b64 = "".join(lineas)
            password = getpass("  Contraseña: ")
            try:
                resultado = descifrar_texto(cifrado_b64, password)
                print(f"\n  Texto descifrado:\n  {resultado}\n")
            except Exception:
                print("\n  Error: contraseña incorrecta o datos corruptos.\n")

        elif opcion == "0":
            print("\n  Hasta luego. Mantén tus datos seguros \n")
            break
        else:
            print("  Opción no válida.\n")


if __name__ == "__main__":
    main()