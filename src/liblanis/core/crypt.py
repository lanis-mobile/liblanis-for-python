"""This script has the Cryptor class for decrypting the messages."""

import base64
from hashlib import md5
from random import randint
import re

import httpx
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad


class Crypt:
    handshake_successful = False

    secret: bytes

    def __init__(self, request: httpx.Client) -> None:
        self.request = request

        self._initialise()

    def _bytes_to_key(self, data: bytes, salt: bytes, output: int = 48) -> bytes:
        # extended from https://gist.github.com/gsakkis/4546068
        assert len(salt) == 8, len(salt)
        data += salt
        key = md5(data).digest()
        final_key = key
        while len(final_key) < output:
            key = md5(key + data).digest()
            final_key += key
        return final_key[:output]

    def _generate_key(self) -> bytes:
        return base64.b64encode(Random.get_random_bytes(46))

    def _handshake(self, encrypted_key: str) -> str:
        response = self.request.post(
            "https://start.schulportal.hessen.de/ajax.php",
            params={"f": "rsaHandshake", "s": str(randint(0, 2000))},
            data={"key": encrypted_key},
        )

        return response.json()["challenge"]

    def _check_for_equal_encryption(self, challenge: str) -> bool:
        _challenge = self.decrypt(challenge).encode() == self.secret

        return _challenge

    def _get_public_key(self) -> str:
        response = self.request.get("https://start.schulportal.hessen.de/ajax.php", params={"f": "rsaPublicKey"})

        public_key = response.json()["publickey"]

        return public_key

    def _encrypt_key(self, public_key: str) -> str:
        rsa = PKCS1_v1_5.new(RSA.import_key(public_key))

        return base64.b64encode(rsa.encrypt(self.secret)).decode()

    def encrypt(self, decrypted: str) -> str:
        if not self.handshake_successful:
            print("crypt handshake not successful")
            return None

        decrypted = decrypted.encode()

        salt = Random.new().read(8)

        derived_key_iv = self._bytes_to_key(self.secret, salt, 32 + 16)
        derived_key = derived_key_iv[:32]
        derived_iv = derived_key_iv[32:]

        aes = AES.new(derived_key, AES.MODE_CBC, derived_iv)

        encrypted = base64.b64encode(
            b"Salted__" + salt + aes.encrypt(pad(decrypted, AES.block_size))
        ).decode()

        return encrypted

    def decrypt(self, encrypted: str) -> str:
        encrypted = base64.b64decode(encrypted)

        encrypted_content = encrypted[16:]
        salt = encrypted[8:16]

        derived_key_iv = self._bytes_to_key(self.secret, salt, 32 + 16)
        derived_key = derived_key_iv[:32]
        derived_iv = derived_key_iv[32:]

        aes = AES.new(derived_key, AES.MODE_CBC, derived_iv)

        decrypted = unpad(aes.decrypt(encrypted_content), AES.block_size).decode()

        return decrypted

    def decrypt_encoded_tags(self, html: str) -> str:
        replaced_html = re.sub(
            r"<encoded>(.*?)</encoded>",
            lambda match: self.decrypt(match.group(1)),
            html,)

        return replaced_html

    def _initialise(self) -> None:
        self.secret = self._generate_key()

        encrypted_key = self._encrypt_key(self._get_public_key())

        challenge = self._handshake(encrypted_key)

        if self._check_for_equal_encryption(challenge):
            self.handshake_successful = True
            print("crypt handshake successful")

        self.handshake_successful = False
