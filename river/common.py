"""Small local-file operations; no network authority or machine discovery."""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

LIMIT = 1024 * 1024
NODE_STORE = Path("/var/lib/river")


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("River store must be private and owned by the current user")
    return path


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def decode(data):
    if len(data) > LIMIT:
        raise ValueError("Document exceeds 1 MiB")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate field: {key}")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def read(path):
    with Path(path).open("rb") as stream:
        return decode(stream.read(LIMIT + 1))


def atomic(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".pending-")
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextlib.contextmanager
def locked(store):
    store = private_directory(store)
    with (store / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield store


def run(*args, input=None, timeout=30, pass_fds=()):
    return subprocess.run(
        [str(arg) for arg in args],
        input=input,
        capture_output=True,
        check=True,
        timeout=timeout,
        pass_fds=pass_fds,
    ).stdout


def certificate(path):
    return decode(run("nebula-cert", "print", "-json", "-path", path))[0]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def same_identity(previous, candidate):
    return all(
        previous[k] == candidate[k] for k in ("publicKey", "curve", "version")
    ) and all(
        previous["details"][k] == candidate["details"][k]
        for k in ("name", "networks", "unsafeNetworks", "groups", "issuer", "isCa")
    )


def diagnostic(error):
    detail = getattr(error, "stderr", b"")
    return str(error) + (": " + detail.decode(errors="replace") if detail else "")
