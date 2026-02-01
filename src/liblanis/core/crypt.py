"""Functions and classes to interact with encrypted data from Lanis."""

import base64
from hashlib import md5
from random import randint
import re

import httpx
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad

# Lanis uses jCryption, an old unmaintained js encryption library, which uses the deprecated CryptoJS library.
# CryptoJS uses an old deprecated key derivation function from OpenSSL.
# This is a python implementation of OpenSSL's EVP_BytesToKey,
# which derives itself from the PBKDF1 standard and uses MD5 as a hash algorithm.
# https://github.com/sytelus/CryptoJS/blob/master/components/evpkdf.js
# https://www.openssl.org/docs/man3.1/man3/EVP_BytesToKey.html
# NOTE: This is deprecated and should only be used for compatibility.
# https://stackoverflow.com/questions/36762098/how-to-decrypt-password-from-javascript-cryptojs-aes-encryptpassword-passphras
def openssl_evp_pbkdf(password: bytes, salt: bytes, output: int) -> bytes:
    """
    A python implementation of OpenSSl's deprecated password-based key derivation function: EVP_BytesToKey.

    :param password: The data to derive the key and iv from.
    :param salt: Needs to be 8 bytes long.
    :param output: Desired length of the derived key and iv.
    :return: Derived key and iv in a byte array.
    """

    # extended from https://gist.github.com/gsakkis/4546068
    if len(salt) != 8:
        raise ValueError("Salt must be 8 bytes")

    password += salt
    key = md5(password).digest()
    final_key = key

    while len(final_key) < output:
        key = md5(key + password).digest()
        final_key += key

    return final_key[:output]


def decrypt(encrypted: str, secret: bytes) -> str:
    """
    Decrypts data with a given valid secret.
    It uses AES-256 in CBC mode. PKCS #7 is used as the padding standard and for key derivation a
    deprecated password-based key derivation function from OpenSSL will be used.

    :param encrypted: The encrypted data to decrypt.
    :param secret: A secret which was previously established with Lanis.
    :return: Decrypted data.
    """

    encrypted = base64.b64decode(encrypted)

    encrypted_content = encrypted[16:]
    salt = encrypted[8:16]

    derived_key_iv = openssl_evp_pbkdf(secret, salt, 32 + 16)
    derived_key = derived_key_iv[:32]
    derived_iv = derived_key_iv[32:]

    aes = AES.new(derived_key, AES.MODE_CBC, derived_iv)

    decrypted = unpad(aes.decrypt(encrypted_content), AES.block_size).decode()

    return decrypted


def encrypt(decrypted: str, secret: bytes) -> str:
    """
    Encrypts data with a given valid secret.
    It uses AES-256 in CBC mode. PKCS #7 is used as the padding standard and for key derivation a
    deprecated password-based key derivation function from OpenSSL will be used.

    :param decrypted: The decrypted data to encrypt.
    :param secret: A secret which was previously established with Lanis.
    :return: Encrypted data.
    """

    decrypted = decrypted.encode()

    salt = Random.new().read(8)

    derived_key_iv = openssl_evp_pbkdf(secret, salt, 32 + 16)
    derived_key = derived_key_iv[:32]
    derived_iv = derived_key_iv[32:]

    aes = AES.new(derived_key, AES.MODE_CBC, derived_iv)

    encrypted = base64.b64encode(
        b"Salted__" + salt + aes.encrypt(pad(decrypted, AES.block_size))
    ).decode()

    return encrypted


def get_lanis_public_key(request: httpx.Client) -> str:
    """
    Get the public key of Lanis.

    :param request: A httpx client.
    :return: The public key.
    """

    response = request.get("https://start.schulportal.hessen.de/ajax.php", params={"f": "rsaPublicKey"})

    public_key = response.json()["publickey"]

    return public_key


def encrypt_key(public_key: str, secret: bytes) -> str:
    """
    Encrypt the public key of lanis with a secret which will be established with Lanis.

    :param public_key: Lanis public key.
    :param secret: To be establishes secret.
    :return: Encrypted public key of lanis with the secret.
    """

    rsa = PKCS1_v1_5.new(RSA.import_key(public_key))

    return base64.b64encode(rsa.encrypt(secret)).decode()


def handshake(request: httpx.Client, encrypted_key: str) -> str:
    """
    Try to establish a wanted secret with Lanis.

    :param request: A httpx client.
    :param encrypted_key: A public key encrypted with the to be established secret.
    :return: A challenge.
    """

    response = request.post(
        "https://start.schulportal.hessen.de/ajax.php",
        params={"f": "rsaHandshake", "s": str(randint(0, 2000))},
        data={"key": encrypted_key},
    )

    return response.json()["challenge"]


class Crypt:
    handshake_successful = False

    secret: bytes

    def __init__(self, request: httpx.Client) -> None:
        self.request = request

        self._initialise()

    def _generate_secret(self) -> bytes:
        # Lanis uses this string (UUID) which has 184 bits (46 chars):
        #     xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx-xxxxxx3xx
        # and replaces x and y with a (pseudo-)random number.
        # We can just generate random chars because it doesn't matter.
        # And it is even cryptographically safe, not like Lanis.

        return base64.b64encode(Random.get_random_bytes(46))

    def _check_for_equal_encryption(self, challenge: str) -> bool:
        _challenge = self.decrypt(challenge).encode() == self.secret

        return _challenge

    def encrypt(self, decrypted: str) -> str:
        if not self.handshake_successful:
            raise RuntimeError("Encryption hasn't been established with Lanis yet.")

        return encrypt(decrypted, self.secret)

    def decrypt(self, encrypted: str) -> str:
        return decrypt(encrypted, self.secret)

    def decrypt_encoded_tags(self, html: str) -> str:
        replaced_html = re.sub(
            r"<encoded>(.*?)</encoded>",
            lambda match: self.decrypt(match.group(1)),
            html,)

        return replaced_html

    def _initialise(self) -> None:
        self.secret = self._generate_secret()

        encrypted_key = encrypt_key(get_lanis_public_key(self.request), self.secret)

        challenge = handshake(self.request, encrypted_key)

        if self._check_for_equal_encryption(challenge):
            self.handshake_successful = True
            print("crypt handshake successful")

        self.handshake_successful = False
