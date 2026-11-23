#!/usr/bin/env python3
"""
Detector de formatos de codificación, hashes y claves criptográficas.
Analiza una cadena de texto o el contenido de un archivo e imprime el tipo probable.
"""

import base64
import binascii
import os
import re
import sys


def es_hex(texto: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", texto))


def es_base64(texto: str) -> bool:
    if len(texto) < 4 or len(texto) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", texto):
        return False
    try:
        decodificado = base64.b64decode(texto, validate=True)
        return len(decodificado) > 0
    except (binascii.Error, ValueError):
        return False


def es_base64_url(texto: str) -> bool:
    if len(texto) < 4:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", texto):
        return False
    # Evitar falsos positivos con texto plano alfabético simple
    if texto.isalnum() and not any(c in texto for c in "-_"):
        return False
    try:
        padding = "=" * ((4 - len(texto) % 4) % 4)
        decodificado = base64.urlsafe_b64decode(texto + padding)
        return len(decodificado) > 0
    except (binascii.Error, ValueError):
        return False


def es_base32(texto: str) -> bool:
    if len(texto) < 8 or len(texto) % 8 != 0:
        return False
    if not re.fullmatch(r"[A-Z2-7]+={0,6}", texto):
        return False
    try:
        base64.b32decode(texto)
        return True
    except (binascii.Error, ValueError):
        return False


def es_base58(texto: str) -> bool:
    return len(texto) >= 16 and bool(
        re.fullmatch(r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+", texto)
    )


def detectar_tipo(entrada: str) -> str:
    dato = entrada.strip()
    if not dato:
        return "Entrada vacía"

    # 1. Cabeceras estándar (PEM, PGP, JWT, SSH)
    if dato.startswith("-----BEGIN "):
        primera_linea = dato.splitlines()[0]
        return f"Formato PEM ({primera_linea.replace('-----', '').strip()})"

    if dato.startswith("ssh-rsa ") or dato.startswith("ssh-ed25519 ") or dato.startswith("ecdsa-sha2-"):
        return "Clave pública OpenSSH"

    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", dato):
        return "JWT (JSON Web Token - Base64URL)"

    # 2. Hashes estructurados / con prefijo
    if re.match(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", dato):
        return "Hash bcrypt"
    if dato.startswith("$argon2id$"):
        return "Hash Argon2id"
    if dato.startswith("$argon2i$"):
        return "Hash Argon2i"
    if dato.startswith("$argon2d$"):
        return "Hash Argon2d"
    if dato.startswith("$6$"):
        return "Hash SHA-512 crypt (Unix)"
    if dato.startswith("$5$"):
        return "Hash SHA-256 crypt (Unix)"
    if dato.startswith("$1$"):
        return "Hash MD5 crypt (Unix)"
    if re.match(r"^\$pbkdf2-sha256\$", dato):
        return "Hash PBKDF2-SHA256"
    if re.match(r"^\{SSHA\}", dato, re.IGNORECASE):
        return "Hash SSHA (Salted SHA-1)"
    if re.match(r"^\{SHA\}", dato, re.IGNORECASE):
        return "Hash SHA-1 (LDAP)"
    if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", dato):
        return "Hash SHA-256 (con prefijo)"
    if re.fullmatch(r"sha1:[0-9a-fA-F]{40}", dato):
        return "Hash SHA-1 (con prefijo)"
    if re.fullmatch(r"md5:[0-9a-fA-F]{32}", dato):
        return "Hash MD5 (con prefijo)"

    # 3. Cadenas hexadecimales (hashes por longitud o datos hex)
    if es_hex(dato):
        longitud = len(dato)
        mapa_hashes = {
            8: "Hash CRC32 (Hexadecimal)",
            32: "Hash MD5 / NTLM (128 bits, Hexadecimal)",
            40: "Hash SHA-1 / RIPEMD-160 (160 bits, Hexadecimal)",
            56: "Hash SHA-224 / SHA3-224 (224 bits, Hexadecimal)",
            64: "Hash SHA-256 / SHA3-256 / BLAKE2s (256 bits, Hexadecimal)",
            96: "Hash SHA-384 / SHA3-384 (384 bits, Hexadecimal)",
            128: "Hash SHA-512 / SHA3-512 / BLAKE2b / Whirlpool (512 bits, Hexadecimal)",
        }
        if longitud in mapa_hashes:
            return mapa_hashes[longitud]
        if longitud % 2 == 0:
            return f"Codificación Hexadecimal (Base16, {longitud // 2} bytes)"

    # 4. Codificaciones Base32 / Base64 / Base64URL / Base58
    if es_base32(dato):
        return "Codificación Base32"

    if es_base64(dato):
        # Comprobar si corresponde a un hash binario codificado en Base64
        raw = base64.b64decode(dato)
        mapa_b64_hash = {
            16: "Codificación Base64 (posible hash MD5 de 128 bits)",
            20: "Codificación Base64 (posible hash SHA-1 de 160 bits)",
            32: "Codificación Base64 (posible hash SHA-256 de 256 bits)",
            48: "Codificación Base64 (posible hash SHA-384 de 384 bits)",
            64: "Codificación Base64 (posible hash SHA-512 de 512 bits)",
        }
        return mapa_b64_hash.get(len(raw), "Codificación Base64")

    if es_base64_url(dato):
        return "Codificación Base64URL"

    if es_base58(dato):
        return "Codificación Base58 (posible dirección o clave)"

    # 5. Binario o URL-encoded
    if re.fullmatch(r"[01\s]+", dato) and len(dato.replace(" ", "")) % 8 == 0:
        return "Codificación Binaria (ASCII/Bytes)"

    if "%" in dato and re.search(r"%[0-9a-fA-F]{2}", dato):
        return "Codificación URL (Percent-encoding)"

    return "Texto plano o cifrado binario/desconocido sin cabecera"


def main():
    if len(sys.argv) > 1:
        objetivo = sys.argv[1]
        if os.path.isfile(objetivo):
            with open(objetivo, "r", encoding="utf-8", errors="replace") as f:
                contenido = f.read()
            print(detectar_tipo(contenido))
        else:
            print(detectar_tipo(objetivo))
    else:
        entrada = input("Introduce el texto o ruta de archivo: ").strip()
        if os.path.isfile(entrada):
            with open(entrada, "r", encoding="utf-8", errors="replace") as f:
                entrada = f.read()
        print(detectar_tipo(entrada))


if __name__ == "__main__":
    main()
