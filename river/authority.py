"""Single local writer. Native issuance and domain decisions live here."""

import ipaddress
from pathlib import Path
import tempfile
import uuid

from . import facts, policy
from .common import LIMIT, atomic, certificate, encode, read, run


def load(store):
    state = read(store / "fleet.json")
    if state.get("format") != 2 or type(state.get("format")) is not int:
        raise ValueError(
            "Unsupported/incomplete issuance history; an explicit authority transition is required"
        )
    policy.fields(
        state, "format issued history policy security artifacts management_ca"
    )
    policy.validate(state["policy"])
    if not isinstance(state["issued"], dict) or not isinstance(state["history"], list):
        raise ValueError("Invalid authority identities")
    security = state["security"]
    for field in (
        "lifetimes",
        "krl",
        "disabled",
        "revoked_keys",
        "issuer_retire_after",
    ):
        if field not in security:
            raise ValueError("Incomplete authority security history")
    records = {}
    required = {
        "name",
        "role",
        "fingerprint",
        "public_key",
        "certificate",
        "identity",
        "management_key",
        "management_certificate",
        "operation",
        "status",
    }
    for entry in state["history"]:
        if not required <= entry.keys() or entry["status"] not in (
            "issued",
            "superseded",
            "revoked",
        ):
            raise ValueError(
                "Incomplete public issuance history; explicit authority transition required"
            )
        records[(entry["name"], entry["operation"])] = entry
    for name, member in state["issued"].items():
        record = records.get((name, member.get("operation")))
        if record is None or any(record[k] != member[k] for k in required - {"status"}):
            raise ValueError(
                "Current credential is missing from retained issuance history"
            )
        if member["native"] != (member["role"] == "lighthouse"):
            raise ValueError("Deployment backend contradicts the issued role")
        if member["name"] != name or set(
            member["identity"]["details"]["groups"]
        ) != policy.capabilities(member["role"]):
            raise ValueError("Authority capabilities contradict the issued certificate")
    return state


def show(store):
    state = load(store)
    return {**state["policy"], "issued": state["issued"]}


def backup(store, destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in (
        "map.json",
        "authority.keys",
        "fleet.json",
        "ca.crt",
        "management-ca.pub",
        "operation.json",
        "composition.json",
    ):
        if not (store / name).exists():
            continue
        atomic(destination / name, (store / name).read_bytes())
    if (store / "operations").exists():
        (destination / "operations").mkdir(mode=0o700)
        for path in (store / "operations").glob("*.json"):
            atomic(destination / "operations" / path.name, path.read_bytes())
    return {"backup": str(destination)}


def save(store, state):
    data = encode(state)
    if len(data) > LIMIT:
        raise ValueError("Authority checkpoint exceeds the prototype's 1 MiB bound")
    atomic(store / "fleet.json", data)


def commit(store, state, signer):
    policy.validate(state["policy"])
    signer.check()
    save(store, state)
    return {"revision": state["policy"]["revision"], "fleet_applied": "not observed"}


def initialize(store, network, endpoints, signer, issuer_days=365, secret=None):
    if any(
        path.name
        not in {
            "lock",
            "map.json",
            "operation.json",
            "operations",
            "authority.keys",
            "ca.crt",
            "management-ca.pub",
        }
        for path in store.iterdir()
    ):
        raise ValueError("Authority directory must be empty; reset is explicit")
    network = ipaddress.IPv4Network(network)
    if network.num_addresses < 8:
        raise ValueError("Need at least eight addresses")
    if not 1 <= len(endpoints) <= 4:
        raise ValueError("Expected one to four named lighthouses")
    if not (store / "authority.keys").exists():
        with tempfile.TemporaryDirectory(dir="/dev/shm") as temporary:
            key = Path(temporary) / "ca.key"
            run(
                "nebula-cert",
                "ca",
                "-name",
                "river",
                "-duration",
                str(issuer_days * 24) + "h",
                "-out-key",
                key,
                "-out-crt",
                store / "ca.crt",
            )
            signer.keys["ca"] = key.read_text()
            management = Path(temporary) / "management"
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", management)
            signer.keys["management"] = management.read_text()
            atomic(
                store / "management-ca.pub", management.with_suffix(".pub").read_bytes()
            )
        if secret is None:
            raise ValueError("Initial authority requires an encryption passphrase")
        from . import session

        session.seal(store, signer, secret)
    from .credentials import krl
    import base64

    state = {
        "format": 2,
        "security": {
            "lifetimes": {
                "leaf_days": 180,
                "renew_days": 30,
                "issuer_days": issuer_days,
            },
            "krl": base64.b64encode(krl([])).decode(),
            "disabled": {},
            "revoked_keys": [],
            "issuer_retire_after": certificate(store / "ca.crt")["details"]["notAfter"],
        },
        "artifacts": {},
        "management_ca": (store / "management-ca.pub").read_text().strip(),
        "issued": {},
        "history": [],
        "policy": {
            "schema": 1,
            "fabric": str(uuid.uuid4()),
            "revision": 1,
            "network": str(network),
            "lighthouses": {
                policy.name(name): {
                    "address": str(network[index]),
                    "endpoint": endpoint,
                }
                for index, (name, endpoint) in enumerate(endpoints.items(), 1)
            },
            "routers": {},
            "revoked": [],
            "profiles": {
                role: {"firewall": {"inbound": [], "outbound": []}}
                for role in sorted(policy.ROLES)
            },
        },
    }
    return commit(store, state, signer)


def bundle(state, ca, name):
    issued = state["issued"][name]
    if issued["fingerprint"] in state["policy"]["revoked"]:
        raise ValueError("Cannot configure a revoked identity")
    directory = facts.directory(state, name)
    network_policy = {**state["policy"], "routers": facts.routers(directory)}
    return {
        "format": 1,
        "name": name,
        "revision": state["policy"]["revision"],
        "prefix": issued["routed_prefix"],
        "directory": directory,
        "policy": network_policy,
        "authorization": facts.authorization(state, name),
        "config": policy.plan(
            network_policy,
            issued["identity"],
            ca,
            issued["certificate"],
            issued["key_path"],
        ),
    }
