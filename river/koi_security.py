"""River Koi projection lifecycle: server pins, manager targets and live checks."""

import hashlib
import json
from pathlib import Path
import subprocess

from .koi import STATE, atomic, run
from . import koi as remote


def service_evidence(name):
    if run("systemctl", "is-active", name, capture=True).strip() != "active":
        raise ValueError(name + " did not activate")
    evidence = {
        "pid": run(
            "systemctl", "show", name, "-p", "MainPID", "--value", capture=True
        ).strip(),
        "invocation": run(
            "systemctl", "show", name, "-p", "InvocationID", "--value", capture=True
        ).strip(),
    }
    if (
        not evidence["pid"].isdecimal()
        or int(evidence["pid"]) <= 0
        or not evidence["invocation"]
    ):
        raise ValueError(name + " has no running process evidence")
    return evidence


def rules_digest():
    rules = json.loads(
        run("nft", "--json", "list", "table", "inet", "river_koi", capture=True)
    )

    def stable(value):
        if isinstance(value, dict):
            return {
                k: stable(v)
                for k, v in value.items()
                if k not in ("handle", "metainfo")
            }
        if isinstance(value, list):
            return [
                stable(v)
                for v in value
                if not (isinstance(v, dict) and "metainfo" in v)
            ]
        return value

    return hashlib.sha256(
        json.dumps(stable(rules), sort_keys=True).encode()
    ).hexdigest()


def hashes():
    files = [
        remote.CONFIG,
        STATE / "guard.nft",
        remote.DNS / "dnsmasq.conf",
        STATE / "sshd.conf",
        STATE / "management-principals",
        STATE / "sudoers.d/manager",
        remote.RESOLVER,
        remote.RESOLVER_ENABLED,
    ]
    return {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.exists()
    }


def stop_management():
    old = subprocess.run(
        [
            "systemctl",
            "show",
            "river-koi-ssh.service",
            "-p",
            "ControlGroup",
            "--value",
        ],
        text=True,
        capture_output=True,
    ).stdout.strip()
    run("systemctl", "stop", "river-koi-ssh.service")
    if old:
        procs = Path("/sys/fs/cgroup" + old) / "cgroup.procs"
        if procs.exists() and procs.read_text().strip():
            raise ValueError("Dedicated management sessions survived service stop")


def withdraw():
    stop_management()
    run(
        "systemctl",
        "stop",
        "river-koi-export.timer",
        "river-koi-export.service",
        "river-koi-dns.service",
    )
    remote.withdraw()


def composition_inputs(bundle):
    directory = bundle["directory"]
    own = directory["peers"][bundle["name"]]
    return {
        "implementation": str(Path(__file__).resolve().parent),
        "name": bundle["name"],
        "network": {k: directory[k] for k in ("fabric", "network", "interface", "mtu")},
        "own": {k: own[k] for k in ("address", "routed_prefix", "role")},
        "dns": {
            name: peer["address"]
            for name, peer in directory["peers"].items()
            if "manager" in own["role"]
            and "provider" in peer["role"]
            and name != bundle["name"]
        },
        "exports": sorted(
            peer["routed_prefix"]
            for peer in directory["peers"].values()
            if peer["routed_prefix"]
        ),
    }


def same_composition(previous, current):
    return {k: v for k, v in previous.items() if k != "exports"} == {
        k: v for k, v in current.items() if k != "exports"
    } and set(current["exports"]) <= set(previous["exports"])


def node(phase, bundle):
    receipt = STATE / "security-applied.json"
    inputs = (
        composition_inputs(bundle) if not bundle.get("disabled") and bundle else None
    )
    expected = json.loads(receipt.read_text()) if receipt.exists() else None
    unchanged = (
        inputs is not None
        and expected is not None
        and same_composition(expected["inputs"], inputs)
        and not bundle["replacement"]
    )
    if phase in ("prepare", "activate") and unchanged:
        try:
            node("check", {})
        except (ValueError, OSError, subprocess.CalledProcessError):
            unchanged = False
            if phase == "activate":
                remote.prepare_node(bundle)
    if phase == "prepare":
        if not unchanged:
            remote.prepare_node(bundle)
        return {"prepared": True}
    if phase == "activate":
        rejection = hashlib.sha256(bundle["authorization"]["krl"].encode()).hexdigest()
        if unchanged:
            node("check", {})
            services = expected["services"]
            if rejection != expected["management_rejection"]:
                stop_management()
                if "ssh" in services:
                    run("systemctl", "start", "river-koi-ssh.service")
                    services["ssh"] = service_evidence("river-koi-ssh.service")
        else:
            stop_management()
            remote.activate(bundle["directory"], bundle["authorization"])
            settings = json.loads(remote.CONFIG.read_text())
            services = {"dns": service_evidence("river-koi-dns.service")}
            if "provider" in settings["role"]:
                services["ssh"] = service_evidence("river-koi-ssh.service")
        atomic(
            receipt,
            json.dumps(
                {
                    "hashes": hashes(),
                    "services": services,
                    "sessions_reset": True,
                    "rules": rules_digest(),
                    "inputs": inputs,
                    "management_rejection": rejection,
                }
            )
            + "\n",
        )
        retained_targets = STATE / "targets-applied.json"
        if retained_targets.exists():
            previous = json.loads(retained_targets.read_text())["payload"]
            peers = bundle["directory"]["peers"]
            manager = "manager" in peers[bundle["name"]]["role"]
            project(
                {
                    "manager": manager,
                    "pins": {
                        name: key
                        for name, key in previous["pins"].items()
                        if manager
                        and name in peers
                        and "provider" in peers[name]["role"]
                        and name != bundle["name"]
                    },
                },
                force=True,
            )
    if phase in ("disable", "check-disabled"):
        if phase == "disable":
            withdraw()
        for unit in ("river-koi-ssh.service", "river-koi-dns.service"):
            if (
                subprocess.run(
                    ["systemctl", "is-active", "--quiet", unit], capture_output=True
                ).returncode
                == 0
            ):
                raise ValueError("Retired composition service remains active")
        return {"verified": True, "retired": True, "sessions_reset": True}
    expected = json.loads(receipt.read_text())
    if inputs is not None and not same_composition(expected["inputs"], inputs):
        raise ValueError("Composition does not implement the delivered River facts")
    if (
        inputs is not None
        and expected["management_rejection"]
        != hashlib.sha256(bundle["authorization"]["krl"].encode()).hexdigest()
    ):
        raise ValueError("Management session retirement has not been applied")
    if hashes() != expected["hashes"]:
        raise ValueError("Composition artifacts differ from activated state")
    for role, service in expected["services"].items():
        if (
            service_evidence(
                "river-koi-" + ("ssh" if role == "ssh" else "dns") + ".service"
            )
            != service
        ):
            raise ValueError("Composition service process changed since activation")
    settings = json.loads(remote.CONFIG.read_text())
    if "provider" in settings["role"]:
        run("sshd", "-t", "-f", STATE / "sshd.conf")
    if rules_digest() != expected["rules"]:
        raise ValueError("Kernel forwarding rules differ from activated composition")
    return {
        "verified": True,
        "sessions_reset": expected["sessions_reset"],
        "files": expected["hashes"],
        "services": expected["services"],
    }


def call(peer, command, payload=None):
    from . import transport
    from .common import encode

    return transport.command(
        peer["target"],
        command,
        encode(payload) if payload is not None else None,
        peer.get("ssh_config"),
    ).decode()


def complete(payload):
    peers = payload["peers"]
    state = Path(payload["store"]) / "composition.json"
    previous = (
        json.loads(state.read_text()) if state.exists() else {"pins": {}, "nodes": {}}
    )
    pins = {}
    pin_errors = {}
    observations = {}
    for name, peer in peers.items():
        if "provider" in peer["role"]:
            generation = payload["generations"][name]
            old = previous["pins"].get(name)
            try:
                if old and old["generation"] == generation:
                    pins[name] = old["key"]
                    if (
                        payload["mode"] == "check" or old["target"] != peer["target"]
                    ) and json.loads(call(peer, "river koi server-key"))[
                        "server_key"
                    ] != old["key"]:
                        raise ValueError(
                            "Provider application pin drift; explicit replacement required"
                        )
                else:
                    if payload["mode"] == "check":
                        raise ValueError("Provider pin is not prepared")
                    pins[name] = json.loads(call(peer, "river koi server-key"))[
                        "server_key"
                    ]
                observations[name] = {
                    "key": pins[name],
                    "target": peer["target"],
                    "generation": generation,
                }
            except Exception as error:
                pin_errors[name] = str(error)
    hosts = {}
    for name in payload["recipients"]:
        if name not in peers:
            hosts[name] = {
                "verified": payload["results"]
                .get(name, {})
                .get("transport_verified", False),
                "retired": True,
            }
            continue
        peer = peers[name]
        if name in pin_errors:
            hosts[name] = {"verified": False, "error": pin_errors[name]}
            continue
        if "manager" in peer["role"] and pin_errors:
            hosts[name] = {
                "verified": False,
                "error": "Provider pin verification pending",
                "providers": pin_errors,
            }
            continue
        if not payload["results"].get(name, {}).get("transport_verified"):
            hosts[name] = {
                "verified": False,
                "error": "River installation/activation pending",
            }
            continue
        if peer["role"] == "lighthouse":
            hosts[name] = {"verified": True, "native_only": True}
            continue
        selected = (
            {n: key for n, key in pins.items() if n != name}
            if "manager" in peer["role"]
            else {}
        )
        command = (
            "river koi check-targets"
            if payload["mode"] == "check"
            else "river koi project"
        )
        try:
            result = json.loads(
                call(
                    peer,
                    command,
                    {"pins": selected, "manager": "manager" in peer["role"]},
                )
            )
            hosts[name] = result
        except Exception as error:
            hosts[name] = {"verified": False, "error": str(error)}
    if payload["mode"] != "check":
        retained = {
            n: pin
            for n, pin in previous["pins"].items()
            if n in peers and "provider" in peers[n]["role"]
        }
        atomic(
            state, json.dumps({"pins": retained | observations, "nodes": hosts}) + "\n"
        )
    return {"hosts": hosts}


def project(payload, check=False, *, force=False):
    receipt = STATE / "targets-applied.json"
    previous = json.loads(receipt.read_text()) if receipt.exists() else None
    if not check:
        node("check", {})
    if not check and (
        force
        or previous is None
        or previous["payload"] != payload
        or previous["hashes"] != hashes()
    ):
        if payload["manager"]:
            remote.targets(payload["pins"])
        else:
            remote.admin_targets({})
        applied = json.loads((STATE / "security-applied.json").read_text())
        applied["hashes"] = hashes()
        atomic(STATE / "security-applied.json", json.dumps(applied) + "\n")
        atomic(receipt, json.dumps({"payload": payload, "hashes": hashes()}) + "\n")
    if payload["manager"]:
        remote.targets(payload["pins"], check=True)
    else:
        remote.admin_targets({}, check=True)
    expected = json.loads(receipt.read_text())
    if expected["payload"] != payload or expected["hashes"] != hashes():
        raise ValueError("Provider targets/pins differ from operator projection")
    return node("check", {})
