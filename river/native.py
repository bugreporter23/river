"""Preflight and restart native Nebula; record local application observations."""

import subprocess
import time
from pathlib import Path
import tempfile

from .common import NODE_STORE, atomic, digest, encode, read, run


def preflight(store, config):
    with tempfile.TemporaryDirectory(prefix="river-preflight-") as temporary:
        candidate = Path(temporary) / "config.json"
        atomic(candidate, encode(config))
        run("nebula", "-test", "-config", candidate)


def apply(store, config, revision, owned_prefix=None, *, disconnect=False):
    service_store(store)
    data = encode(config)
    config_digest = digest(data)
    applied = read(store / "applied.json") if (store / "applied.json").exists() else {}
    last = read(store / "apply.json") if (store / "apply.json").exists() else {}
    mode = "unchanged"
    if (
        disconnect
        or applied.get("config_digest") != config_digest
        or last.get("pending")
        or not active()
    ):
        atomic(store / "apply.json", encode({"pending": True}))
        preflight(store, config)
        atomic(store / "active.json", data)
        run("systemctl", "restart", "river-nebula.service")
        mode = "restart"
        for _ in range(50):
            if (
                active()
                and subprocess.run(
                    ["ip", "link", "show", config["tun"]["dev"]],
                    capture_output=True,
                    timeout=5,
                ).returncode
                == 0
            ):
                break
            time.sleep(0.1)
        else:
            raise ValueError("Nebula did not become active with its tunnel interface")
    atomic(
        store / "applied.json",
        encode(
            {
                "revision": revision,
                "invocation_id": run(
                    "systemctl",
                    "show",
                    "river-nebula.service",
                    "-p",
                    "InvocationID",
                    "--value",
                )
                .decode()
                .strip(),
                "connections_reset": mode == "restart"
                or applied.get("connections_reset", False),
                "config_digest": config_digest,
                "routing": {
                    "interface": config["tun"]["dev"],
                    "owned_prefix": owned_prefix,
                    "routes": config["tun"]["unsafe_routes"],
                },
            }
        ),
    )
    atomic(store / "apply.json", encode({"pending": False, "operation": mode}))


def active():
    return (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", "river-nebula.service"],
            capture_output=True,
            timeout=5,
        ).returncode
        == 0
    )


def interface_exists(name):
    return (
        subprocess.run(
            ["ip", "link", "show", name], capture_output=True, timeout=5
        ).returncode
        == 0
    )


def service_store(store):
    if store.resolve() != NODE_STORE:
        raise ValueError("The installed node service uses /var/lib/river")


def status(store):
    service_store(store)
    return {
        "applied": read(store / "applied.json")
        if (store / "applied.json").exists()
        else None,
        "last_apply": read(store / "apply.json")
        if (store / "apply.json").exists()
        else None,
        "service_active": active(),
    }
