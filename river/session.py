"""Compile-scoped local signer and encrypted operator CA storage."""

import base64
import getpass
import os
from pathlib import Path
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .common import atomic, decode, encode, read, run

SECONDS = 900


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class Signer:
    def __init__(self, keys=None, seconds=SECONDS):
        if not 0 < seconds <= SECONDS:
            raise ValueError("Session must last between 0 and 900 seconds")
        self.keys = keys if keys is not None else {}
        self.deadline = clock() + seconds

    def check(self):
        if clock() >= self.deadline:
            self.keys.clear()
            raise ValueError("Operator session expired; unlock again")

    def native(self, *args):
        self.check()
        fd = os.memfd_create("river-ca", os.MFD_CLOEXEC)
        try:
            os.write(fd, self.keys["ca"].encode())
            return run(
                "nebula-cert",
                "sign",
                "-ca-key",
                f"/proc/self/fd/{fd}",
                *args,
                pass_fds=(fd,),
            )
        finally:
            os.close(fd)


def password(path=None, confirm=False):
    value = (
        Path(path).read_text().rstrip("\n")
        if path
        else getpass.getpass(
            "Choose a new passphrase to encrypt operator signing keys: "
            if confirm
            else "Enter your existing operator signing-key passphrase: "
        )
    )
    if not value:
        raise ValueError("An empty authority passphrase is not allowed")
    if confirm and not path and value != getpass.getpass("Repeat new passphrase: "):
        raise ValueError("Passphrases differ")
    return value


def cipher(secret, salt):
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(secret.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def seal(store, signer, secret):
    salt = os.urandom(16)
    atomic(
        store / "authority.keys",
        encode(
            {
                "schema": 1,
                "salt": base64.b64encode(salt).decode(),
                "ciphertext": cipher(secret, salt)
                .encrypt(encode(signer.keys))
                .decode(),
            }
        ),
    )


def unseal(store, secret):
    value = read(store / "authority.keys")
    if set(value) != {"schema", "salt", "ciphertext"} or value["schema"] != 1:
        raise ValueError("Invalid authority key bundle")
    salt = base64.b64decode(value["salt"], validate=True)
    if len(salt) != 16:
        raise ValueError("Invalid authority salt")
    try:
        return decode(cipher(secret, salt).decrypt(value["ciphertext"].encode()))
    except InvalidToken:
        raise ValueError("Wrong passphrase or damaged authority key bundle") from None
