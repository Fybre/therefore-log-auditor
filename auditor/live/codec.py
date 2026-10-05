"""Therefore XML login codec, verified against paired SOAP/CryptoAPI captures.

The password encoding for non-ASCII characters remains unverified.
"""

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"


def encode_buffer(data: bytes) -> str:
    """Encode a little-endian unsigned integer using Therefore's radix 64."""
    value = int.from_bytes(data, "little")
    digits = []
    while value:
        value, digit = divmod(value, 64)
        digits.append(ALPHABET[digit])
    # Keep the width of the original buffer, including leading zero radix digits.
    width = (len(data) * 8 + 5) // 6
    return ("".join(reversed(digits)) or "0").rjust(width, "0")


def decode_buffer(encoded: str, length: int | None = None) -> bytes:
    value = 0
    for digit in encoded:
        value = value * 64 + ALPHABET.index(digit)
    size = length if length is not None else max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(size, "little")


def make_ascii_login_proof(challenge: str, password: str, public_key: str) -> str:
    """Requires cryptography; uses verified ASCII credential path and RSA v1.5."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    blob = decode_buffer(public_key, 276)
    if blob[:8] != bytes.fromhex("0602000000a40000") or blob[8:12] != b"RSA1":
        raise ValueError("Expected a CryptoAPI RSA PUBLICKEYBLOB")
    bits = int.from_bytes(blob[12:16], "little")
    exponent = int.from_bytes(blob[16:20], "little")
    modulus = int.from_bytes(blob[20:20 + bits // 8], "little")
    key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    plaintext = (challenge + password).encode("ascii") + b"\x00"
    # cryptography returns big-endian RSA ciphertext; CryptoAPI returns little-endian.
    ciphertext = key.encrypt(plaintext, padding.PKCS1v15())[::-1]
    return "str:" + encode_buffer(ciphertext)
