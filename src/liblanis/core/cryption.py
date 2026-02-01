"""
Functions and classes to interact with encrypted data from Lanis.
Basically a minimal translation of a subset of jCryption into python to decrypt/encrypt data from Lanis.

SECURITY NOTICE
===============

Lanis uses jCryption - an old unmaintained js encryption library which uses the deprecated CryptoJS library.
Due to the old age of these libraries various insecure and exploitable algorithms and standards are used.
AES is used in CBC mode which isn't recommended anymore. At least a key size of 256 bits is (probably) used because
it's the standard key size of CryptoJS. As a KDF (Key Derivation Function) an old non-standardised PBKDF (password-based KDF)
from OpenSSL is used which derives itself from the PBKDF #1 standard which is also old and vulnerable. The PBKDF also
uses MD5 as a hashing algorithm which is well-known today to be really vulnerable. The public key also still uses
PKCS #1 version 1.5 which is incredibly old and known to be vulnerable.

WHY?
====

Back in the days an SSL certificate was expensive but Lanis was handling with sensitive student data.
So Lanis was needed to somehow securely transmit this data (probably due to government pressure or by itself).
Let's Encrypt didn't exist back then, but they didn't want to spend a lot of money "just" for an SSL certificate.
Their solution was to use jCryption which encrypts the transmitted data and uses a handshake process to establish
an encryption/decryption key for the client. The problem is this only provides a basic-level of security. This
method is prone to man-in-the-middle attacks because the public key can't be verified but back then this was better than nothing.

Today Lanis uses a certificate from Let's Encrypt (wow!) and this encryption is now utterly useless because SSL
replaces its use case and does it 100 times better. Now it's just unnecessary dangling there probably
because no one wants to remove it in fear of breaking the whole established system and why remove something if it's working?

(I can't prove if this was Lanis motive, maybe they were just incompetent and failed to recognise that SSL already solves this.)

Sources
=======

Lanis uses jCryption: https://start.schulportal.hessen.de/libs/jcryption/jquery.jcryption.3.1.0.js

Lanis' encryption process: https://start.schulportal.hessen.de/js/createAEStoken.js

jCryption archive: https://code.google.com/archive/p/jcryption/

CryptoJS archive: https://github.com/sytelus/CryptoJS/

StackOverflow post on the effectiveness of jCryption: https://stackoverflow.com/questions/8235166/jcryption-cram-are-a-good-alternative-to-ssl

General effectiveness of 2nd layer encryption on an HTTPS site: https://security.stackexchange.com/questions/280184/do-i-need-a-2nd-layer-of-encryption-through-secured-site-https-ssl-tls
"""

import base64
from hashlib import md5
from random import randint
import re

import httpx
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad


def openssl_evp_pbkdf(password: bytes, salt: bytes, output: int) -> bytes:
    """
    A python implementation of OpenSSl's deprecated non-standardised password-based key derivation function: EVP_BytesToKey.
    CryptoJS the base library of jCryption uses this as its KDF.

    SECURITY NOTICE
    ===============

    Uses MD5 as a hashing algorithm which is also incredibly vulnerable and derives itself from the deprecated and vulnerable PBKDF #1 standard.
    This function shouldn't be used in an environment where security is needed and should only be used for compatibility.

    SOURCES
    =======

    CryptoJS port of EVP_BytesToKey: https://github.com/sytelus/CryptoJS/blob/master/components/evpkdf.js

    OpenSSL documentation of EVP_BytesToKey: https://www.openssl.org/docs/man3.1/man3/EVP_BytesToKey.html

    Source of this code: https://stackoverflow.com/questions/36762098/how-to-decrypt-password-from-javascript-cryptojs-aes-encryptpassword-passphras/36780727#36780727

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

    Read the top level README for potential security risks.

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

    Read the top level README for potential security risks.

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
    Encrypt the public key of Lanis with a secret which will be established with Lanis.

    Read the top level README for potential security risks.

    :param public_key: Lanis public key.
    :param secret: To be establishes secret.
    :return: Encrypted public key of lanis with the secret.
    """

    rsa = PKCS1_v1_5.new(RSA.import_key(public_key))

    return base64.b64encode(rsa.encrypt(secret)).decode()


def handshake(request: httpx.Client, encrypted_key: str) -> str:
    """
    Try to establish a secret with Lanis.

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


class Cryption:
    """
    A client to establish a secret with Lanis to decrypt/encrypt data.
    Read the top level README for potential security risks.

    :param request: An authenticated httpx client.
    """

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

        # 64 bytes or 256 bits because it's the standard key size of CryptoJS and secure.
        return base64.b64encode(Random.get_random_bytes(64))

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
