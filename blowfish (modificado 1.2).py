"""
                                BLOWFISH modificado
===================Cifra texto, imágenes, documentos y contraseñas/ubicación=====================
en el terminal se debe instalar en la consola "pip install pycryptodome" para el uso.
=================================================================================================
"""
 
import os
import re
import sys
import json
import base64
import hashlib
import struct
from getpass import getpass
from datetime import datetime
 
try:
    from Crypto.Cipher import Blowfish
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("\n[ERROR] Instala la dependencia con:\n    pip install pycryptodome\n")
    sys.exit(1)
 
# ──────────────────────────────────────────────
#  EXTENSIONES SOPORTADAS
# ──────────────────────────────────────────────
 
EXTENSIONES_DOCUMENTO = {
    ".pdf":  "PDF",
    ".doc":  "Word (antiguo)",
    ".docx": "Word",
    ".xls":  "Excel (antiguo)",
    ".xlsx": "Excel",
    ".ppt":  "PowerPoint (antiguo)",
    ".pptx": "PowerPoint",
    ".odt":  "OpenDocument Texto",
    ".ods":  "OpenDocument Hoja de cálculo",
    ".odp":  "OpenDocument Presentación",
    ".txt":  "Texto plano",
    ".csv":  "CSV",
    ".xml":  "XML",
    ".json": "JSON",
    ".zip":  "ZIP",
    ".rar":  "RAR",
}
 
# ──────────────────────────────────────────────
#  VALIDACIÓN DE CONTRASEÑA MAESTRA
# ──────────────────────────────────────────────
 
REGLAS_PASSWORD = {
    "longitud":          (r".{8,}",           "Al menos 8 caracteres"),
    "mayuscula":         (r"[A-Z]",            "Al menos una letra MAYÚSCULA"),
    "minuscula":         (r"[a-z]",            "Al menos una letra minúscula"),
    "numero":            (r"[0-9]",            "Al menos un número"),
    "caracter_especial": (r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]",
                          "Al menos un carácter especial (!@#$%^&*...)"),
}
 
def validar_password(password: str) -> tuple[bool, list[str]]:
    errores = []
    for clave, (patron, mensaje) in REGLAS_PASSWORD.items():
        if not re.search(patron, password):
            errores.append(f"  ✗ {mensaje}")
    return (len(errores) == 0, errores)
 
 
def pedir_password_nueva(prompt: str = "  Contraseña maestra") -> str:
    print("\n  ── Requisitos de contraseña ──────────────────────")
    for _, (_, msg) in REGLAS_PASSWORD.items():
        print(f"     • {msg}")
    print("  ──────────────────────────────────────────────────")
 
    while True:
        password = input(f"\n{prompt}: ")
        valida, errores = validar_password(password)
        if valida:
            confirmacion = input(f"{prompt} (confirmar): ")
            if password == confirmacion:
                print("  ✔ Contraseña aceptada.\n")
                return password
            else:
                print("\n  ✗ Las contraseñas no coinciden. Intenta de nuevo.")
        else:
            print("\n  Contraseña inválida. Requisitos incumplidos:")
            for e in errores:
                print(e)
 
 
def pedir_password_existente(prompt: str = "  Contraseña maestra") -> str:
    while True:
        password = input(f"{prompt}: ")
        if password:
            return password
        print("  ✗ La contraseña no puede estar vacía.")
 
 
# ──────────────────────────────────────────────
#  NÚCLEO BLOWFISH
# ──────────────────────────────────────────────
 
def derivar_clave(password: str, salt: bytes) -> bytes:
    """Deriva una clave de 32 bytes desde una contraseña usando SHA-256 + salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)
 
 
def cifrar(datos: bytes, password: str) -> bytes:
    """
    Cifra datos arbitrarios con Blowfish (modo CBC + padding PKCS7).
    Formato: [4 bytes: longitud del salt] + [salt (16 bytes)] + [IV (8 bytes)] + [datos cifrados]
    """
    salt = get_random_bytes(16)
    clave = derivar_clave(password, salt)
    iv = get_random_bytes(8)
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
#  1. CIFRADO DE TEXTO
# ──────────────────────────────────────────────
 
def cifrar_texto(texto: str, password: str) -> str:
    datos = texto.encode("utf-8")
    paquete = cifrar(datos, password)
    return base64.b64encode(paquete).decode("ascii")
 
 
def descifrar_texto(texto_b64: str, password: str) -> str:
    paquete = base64.b64decode(texto_b64.encode("ascii"))
    datos = descifrar(paquete, password)
    return datos.decode("utf-8")
 
 
# ──────────────────────────────────────────────
#  2. CIFRADO DE IMÁGENES
# ──────────────────────────────────────────────
 
def cifrar_imagen(ruta_entrada: str, ruta_salida: str, password: str) -> None:
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No se encontró el archivo: {ruta_entrada}")
    with open(ruta_entrada, "rb") as f:
        datos_imagen = f.read()
    ext = os.path.splitext(ruta_entrada)[1].encode("utf-8")
    ext_padded = ext.ljust(10)[:10]
    datos_con_meta = ext_padded + datos_imagen
    paquete = cifrar(datos_con_meta, password)
    with open(ruta_salida, "wb") as f:
        f.write(paquete)
    print(f"  Imagen cifrada guardada en: {ruta_salida}")
 
 
def descifrar_imagen(ruta_cifrada: str, ruta_salida: str, password: str) -> None:
    with open(ruta_cifrada, "rb") as f:
        paquete = f.read()
    datos_con_meta = descifrar(paquete, password)
    ext = datos_con_meta[:10].rstrip().decode("utf-8")
    datos_imagen = datos_con_meta[10:]
    if not os.path.splitext(ruta_salida)[1]:
        ruta_salida = ruta_salida + ext
    with open(ruta_salida, "wb") as f:
        f.write(datos_imagen)
    print(f" Imagen descifrada guardada en: {ruta_salida}")
 
 
# ──────────────────────────────────────────────
#  3. CIFRADO DE DOCUMENTOS  
# ──────────────────────────────────────────────
 
def cifrar_documento(ruta_entrada: str, ruta_salida: str, password: str) -> None:
    """
    Cifra cualquier documento (PDF, Word, Excel, PowerPoint, etc.) con Blowfish.
    
    El paquete cifrado contiene:
        [10 bytes: extensión original] + [bytes del archivo]
    
    El archivo cifrado lleva extensión .bfdoc para indicar que está cifrado.
    """
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No se encontró el archivo: {ruta_entrada}")
 
    ext = os.path.splitext(ruta_entrada)[1].lower()
    tipo = EXTENSIONES_DOCUMENTO.get(ext, "Archivo genérico")
 
    with open(ruta_entrada, "rb") as f:
        datos_doc = f.read()
 
    tam_mb = len(datos_doc) / (1024 * 1024)
    print(f"  Tipo detectado : {tipo} ({ext})")
    print(f"  Tamaño         : {tam_mb:.2f} MB  ({len(datos_doc):,} bytes)")
    print(f"  Cifrando...    ", end="", flush=True)
 
    # Guardar extensión (10 bytes fijos) + contenido del archivo
    ext_bytes = ext.encode("utf-8").ljust(10)[:10]
    datos_con_meta = ext_bytes + datos_doc
 
    paquete = cifrar(datos_con_meta, password)
 
    with open(ruta_salida, "wb") as f:
        f.write(paquete)
 
    tam_cifrado = os.path.getsize(ruta_salida) / (1024 * 1024)
    print(f"listo.")
    print(f"  Documento cifrado guardado en : {ruta_salida}")
    print(f"  Tamaño cifrado                : {tam_cifrado:.2f} MB")
 
 
def descifrar_documento(ruta_cifrada: str, ruta_salida: str, password: str) -> None:
    """
    Descifra un documento previamente cifrado con cifrar_documento.
    Restaura la extensión original si no se especificó en ruta_salida.
    """
    if not os.path.isfile(ruta_cifrada):
        raise FileNotFoundError(f"No se encontró el archivo: {ruta_cifrada}")
 
    print(f"  Descifrando... ", end="", flush=True)
 
    with open(ruta_cifrada, "rb") as f:
        paquete = f.read()
 
    datos_con_meta = descifrar(paquete, password)
 
    # Recuperar extensión original
    ext = datos_con_meta[:10].rstrip(b"\x20").decode("utf-8")
    datos_doc = datos_con_meta[10:]
 
    # Si la ruta de salida no tiene extensión, la añadimos automáticamente
    if not os.path.splitext(ruta_salida)[1]:
        ruta_salida = ruta_salida + ext
 
    with open(ruta_salida, "wb") as f:
        f.write(datos_doc)
 
    tipo = EXTENSIONES_DOCUMENTO.get(ext, "Archivo genérico")
    tam_mb = len(datos_doc) / (1024 * 1024)
    print(f"listo.")
    print(f"  Tipo restaurado : {tipo} ({ext})")
    print(f"  Tamaño original : {tam_mb:.2f} MB")
    print(f"  Guardado en     : {ruta_salida}")
 
 
# ──────────────────────────────────────────────
#  4. CIFRADO DE CONTRASEÑAS Y UBICACIÓN
# ──────────────────────────────────────────────
 
def cifrar_credenciales(datos: dict, password: str) -> str:
    datos["_timestamp"] = datetime.utcnow().isoformat() + "Z"
    json_bytes = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    paquete = cifrar(json_bytes, password)
    return base64.b64encode(paquete).decode("ascii")
 
 
def descifrar_credenciales(cifrado_b64: str, password: str) -> dict:
    paquete = base64.b64decode(cifrado_b64.encode("ascii"))
    json_bytes = descifrar(paquete, password)
    return json.loads(json_bytes.decode("utf-8"))
 
 
def guardar_credenciales_archivo(cifrado_b64: str, ruta: str) -> None:
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump({"blowfish_payload": cifrado_b64}, f, indent=2)
    print(f" Credenciales cifradas guardadas en: {ruta}")
 
 
def cargar_credenciales_archivo(ruta: str) -> str:
    with open(ruta, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["blowfish_payload"]
 
 
# ──────────────────────────────────────────────
#  INTERFAZ DE LÍNEA DE COMANDOS =======================================================================================================
# ──────────────────────────────────────────────
 
def banner():
    print("\n BLOWFISH - Algoritmo: Blowfish CBC + PBKDF2-SHA256 \n")
    exts = "  ".join(EXTENSIONES_DOCUMENTO.keys())
    print(f"  Documentos soportados: {exts}\n")
 
 
def menu_principal():
    print("  ¿Qué deseas cifrar?")
    print("  [1] Texto")
    print("  [2] Imagen")
    print("  [3] Documento (PDF, Word, Excel, PowerPoint...)")
    print("  [4] Contraseña / Ubicación GPS")
    print("  [0] Salir")
    return input("\n  Elige opción: ").strip()
 
# ──────────────────────────────────────────────
#  FLUJO 1 — Texto 
# ──────────────────────────────────────────────
 
def flujo_texto():
    print("\n── TEXTO ─────────────────────────────────────────")
    print(" [C] Cifrar  |  [D] Descifrar")
    accion = input("  Acción: ").strip().upper()
 
    if accion == "C":
        password = pedir_password_nueva("  Contraseña maestra")
        texto = input("  Escribe el texto a cifrar:\n  > ")
        resultado = cifrar_texto(texto, password)
        print(f"\n  Texto cifrado (copia este bloque):\n")
        for i in range(0, len(resultado), 64):
            print("  " + resultado[i:i+64])
        guardar = input("\n  ¿Guardar en archivo? (s/n): ").strip().lower()
        if guardar == "s":
            ruta = input("  Nombre del archivo [cifrado.txt]: ").strip() or "cifrado.txt"
            with open(ruta, "w") as f:
                f.write(resultado)
            print(f"  Guardado en {ruta}")
 
    elif accion == "D":
        password = pedir_password_existente("  Contraseña maestra")
        op = input("  ¿Tienes archivo? (s/n): ").strip().lower()
        if op == "s":
            ruta = input("  Ruta del archivo: ").strip()
            try:
                with open(ruta, "r") as f:
                    cifrado_b64 = f.read().strip()
            except FileNotFoundError:
                print(" Archivo no encontrado")
                return
        elif op == "n":
            print("  Pega el texto cifrado (Base64), luego presiona Enter dos veces:")
            lineas = []
            while True:
                linea = input()
                if linea == "":
                    break
                lineas.append(linea.strip())
            cifrado_b64 = "".join(lineas)
        else:
            print("  Opción no válida")
            return
        try:
            resultado = descifrar_texto(cifrado_b64, password)
            print(f"\n  Texto descifrado:\n  {resultado}")
        except Exception:
            print("\n Error: contraseña incorrecta o datos corruptos.")
    else:
        print("  Opción no válida.")
 
# ──────────────────────────────────────────────
#  FLUJO 2 — Imagen 
# ──────────────────────────────────────────────
 
def flujo_imagen():
    print("\n── IMAGEN ────────────────────────────────────────")
    print("  [C] Cifrar  |  [D] Descifrar")
    accion = input("  Acción: ").strip().upper()
 
    if accion == "C":
        password = pedir_password_nueva("  Contraseña maestra")
        entrada = input("  Ruta de la imagen original (ej: foto.jpg): ").strip()
        salida  = input("  Ruta del archivo cifrado   (ej: foto.bf):  ").strip()
        if not salida:
            salida = os.path.splitext(entrada)[0] + ".bf"
        try:
            cifrar_imagen(entrada, salida, password)
        except FileNotFoundError as e:
            print(f" {e}")
        except Exception as e:
            print(f" Error al cifrar: {e}")
 
    elif accion == "D":
        password = pedir_password_existente("  Contraseña maestra")
        entrada = input("  Ruta del archivo cifrado      (ej: foto.bf):     ").strip()
        salida  = input("  Ruta de salida sin extensión  (ej: foto_dec):    ").strip()
        if not salida:
            salida = os.path.splitext(entrada)[0] + "_descifrado"
        try:
            descifrar_imagen(entrada, salida, password)
        except Exception:
            print("\n Error: contraseña incorrecta o archivo corrupto.")
    else:
        print("  Opción no válida.")
 
 
# ──────────────────────────────────────────────
#  FLUJO 3 — Documento  
# ──────────────────────────────────────────────
 
def flujo_documento():
    print("\n── DOCUMENTO ─────────────────────────────────────")
    exts_lista = ", ".join(EXTENSIONES_DOCUMENTO.keys())
    print(f"  Formatos soportados: {exts_lista}")
    print("  [C] Cifrar  |  [D] Descifrar")
    accion = input("  Acción: ").strip().upper()
 
    if accion == "C":
        password = pedir_password_nueva("  Contraseña maestra")
        entrada = input("  Ruta del documento original  (ej: informe.pdf): ").strip()
 
        # Sugerir nombre de salida automáticamente
        nombre_base = os.path.splitext(entrada)[0]
        salida_sugerida = nombre_base + ".bfdoc"
        salida = input(f"  Ruta del archivo cifrado     [{salida_sugerida}]: ").strip()
        if not salida:
            salida = salida_sugerida
 
        try:
            cifrar_documento(entrada, salida, password)
        except FileNotFoundError as e:
            print(f"\n  ✗ {e}")
        except Exception as e:
            print(f"\n  ✗ Error al cifrar: {e}")
 
    elif accion == "D":
        password = pedir_password_existente("  Contraseña maestra")
        entrada = input("  Ruta del archivo cifrado     (ej: informe.bfdoc): ").strip()
 
        nombre_base = os.path.splitext(entrada)[0]
        salida_sugerida = nombre_base + "_descifrado"
        salida = input(f"  Ruta de salida (sin extensión) [{salida_sugerida}]: ").strip()
        if not salida:
            salida = salida_sugerida
 
        try:
            descifrar_documento(entrada, salida, password)
        except FileNotFoundError as e:
            print(f"\n  ✗ {e}")
        except Exception:
            print("\n  ✗ Error: contraseña incorrecta o archivo corrupto.")
 
    else:
        print("  Opción no válida.")
 
 
# ──────────────────────────────────────────────
#  FLUJO 4 — Contraseña / Ubicación GPS
# ──────────────────────────────────────────────
 
def flujo_credenciales():
    print("\n── CONTRASEÑA / UBICACIÓN GPS ────────────────────")
    print("  [1] Cifrar contraseña")
    print("  [2] Cifrar ubicación GPS")
    print("  [3] Descifrar archivo de credenciales")
    sub = input("  Opción: ").strip()
 
    if sub == "1":
        password = pedir_password_nueva("  Contraseña maestra (para el cifrado)")
        datos = {}
        datos["sitio"]      = input("  Sitio web / aplicación: ").strip()
        datos["usuario"]    = input("  Usuario / email: ").strip()
        datos["contraseña"] = input("  Contraseña a guardar: ")
        datos["notas"]      = input("  Notas adicionales (opcional): ").strip()
        cifrado = cifrar_credenciales(datos, password)
        ruta = input("  Nombre del archivo de salida [credencial.json]: ").strip() or "credencial.json"
        guardar_credenciales_archivo(cifrado, ruta)
 
    elif sub == "2":
        password = pedir_password_nueva("  Contraseña maestra (para el cifrado)")
        datos = {}
        datos["tipo"]        = "ubicacion_gps"
        datos["latitud"]     = input("  Latitud  (ej: 19.4326): ").strip()
        datos["longitud"]    = input("  Longitud (ej: -99.1332): ").strip()
        datos["descripcion"] = input("  Descripción del lugar: ").strip()
        datos["notas"]       = input("  Notas adicionales (opcional): ").strip()
        cifrado = cifrar_credenciales(datos, password)
        ruta = input("  Nombre del archivo de salida [ubicacion.json]: ").strip() or "ubicacion.json"
        guardar_credenciales_archivo(cifrado, ruta)
 
    elif sub == "3":
        password = pedir_password_existente("  Contraseña maestra (para el cifrado)")
        ruta = input("  Ruta del archivo cifrado (.json): ").strip()
        try:
            cifrado_b64 = cargar_credenciales_archivo(ruta)
            datos = descifrar_credenciales(cifrado_b64, password)
            print("\n  Datos descifrados:")
            for k, v in datos.items():
                if k != "_timestamp":
                    print(f"    {k:15}: {v}")
            print(f"    {'cifrado el':15}: {datos.get('_timestamp', '?')}")
        except FileNotFoundError:
            print(f"  Archivo no encontrado: {ruta}")
        except Exception:
            print("\n  Error: contraseña incorrecta o archivo corrupto.")
    else:
        print("  Opción no válida.")
 
 
def main():
    banner()
    while True:
        opcion = menu_principal()
        if opcion == "1":
            flujo_texto()               # ← Se implemento texto
        elif opcion == "2":
            flujo_imagen()              # ← Se implemento las imagenes
        elif opcion == "3":
            flujo_documento()           # ← Se implemento los documentos
        elif opcion == "4":
            flujo_credenciales()        # ← Se implemento los documentoslas credenciales
            print("\n  Hasta luego. Mantén tus datos seguros.\n")
            break
        else:
            print("  Opción no válida, intenta de nuevo.")
        print()
 
 
if __name__ == "__main__":
    main()
 