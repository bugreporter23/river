"""Public network facts for consumers; delivered through administrator SSH."""

import ipaddress
from datetime import datetime
import uuid

from . import policy

INTERFACE = policy.INTERFACE
MTU = policy.MTU


def directory(state, own=None):
    network = state["policy"]
    return {
        "schema": 2,
        "fabric": network["fabric"],
        "revision": network["revision"],
        "network": network["network"],
        "interface": INTERFACE,
        "mtu": MTU,
        "peers": {
            name: {
                "public_key": member["identity"]["publicKey"],
                "certificate": member["fingerprint"],
                "not_after": member["identity"]["details"]["notAfter"],
                "role": member["role"],
                "address": str(ipaddress.IPv4Interface(member["address"]).ip),
                "routed_prefix": member["routed_prefix"],
            }
            for name, member in sorted(state["issued"].items())
            if member["fingerprint"] not in network["revoked"]
            and name not in state["security"]["disabled"]
            and (own is None or name == own or member["role"] != "manager")
        },
    }


def routers(directory):
    return {
        name: {"prefix": peer["routed_prefix"], "via": peer["address"]}
        for name, peer in directory["peers"].items()
        if peer["routed_prefix"] is not None
    }


def validate(directory, identity, revision, prefix, config):
    policy.fields(directory, "schema fabric revision network interface mtu peers")
    if (
        type(directory["schema"]) is not int
        or directory["schema"] != 2
        or type(directory["revision"]) is not int
        or directory["revision"] != revision
        or str(uuid.UUID(directory["fabric"])) != directory["fabric"]
        or directory["interface"] != INTERFACE
        or type(directory["mtu"]) is not int
        or directory["mtu"] != MTU
    ):
        raise ValueError("Invalid network facts header")
    network = ipaddress.IPv4Network(directory["network"])
    peers = directory["peers"]
    if not isinstance(peers, dict) or len(peers) > 4096:
        raise ValueError("Invalid peer directory")
    addresses = set()
    lighthouses = {}
    for name, peer in peers.items():
        policy.name(name)
        policy.fields(
            peer, "public_key certificate not_after role address routed_prefix"
        )
        policy.fingerprint(peer["public_key"])
        policy.fingerprint(peer["certificate"])
        address = ipaddress.IPv4Address(peer["address"])
        if (
            str(address) != peer["address"]
            or address not in network
            or address in {network.network_address, network.broadcast_address}
            or address in addresses
            or peer["role"] not in policy.ROLES
            or not isinstance(peer["not_after"], str)
            or peer["certificate"] in config["pki"]["blocklist"]
        ):
            raise ValueError("Invalid, duplicate or revoked peer facts")
        if ("provider" in policy.capabilities(peer["role"])) != (
            peer["routed_prefix"] is not None
        ):
            raise ValueError("Provider facts require a routed prefix")
        addresses.add(address)
        if peer["role"] == "lighthouse":
            lighthouses[name] = {"address": peer["address"]}
    policy.validate_routers(routers(directory), network, lighthouses)
    details = identity["details"]
    own = peers.get(details["name"])
    if (
        own is None
        or own
        != {
            "public_key": identity["publicKey"],
            "certificate": identity["fingerprint"],
            "not_after": own["not_after"] if own else None,
            "role": "provider-manager"
            if set(details["groups"]) == {"provider", "manager"}
            else next(iter(details["groups"]), None),
            "address": str(ipaddress.IPv4Interface(details["networks"][0]).ip),
            "routed_prefix": prefix,
        }
        or datetime.fromisoformat(own["not_after"])
        != datetime.fromisoformat(details["notAfter"])
        or str(ipaddress.IPv4Interface(details["networks"][0]).network) != str(network)
    ):
        raise ValueError("Network facts disagree with the local certificate")
    expected = (
        [
            {"route": router["prefix"], "via": router["via"], "mtu": MTU}
            for name, router in sorted(routers(directory).items())
            if name != details["name"]
        ]
        if own["role"] != "lighthouse"
        else []
    )
    if config["tun"]["unsafe_routes"] != expected or config["tun"]["mtu"] != MTU:
        raise ValueError("Network facts disagree with native routes")


def authorization(state, name):
    member = state["issued"][name]
    return {
        "schema": 2,
        "fabric": state["policy"]["fabric"],
        "revision": state["policy"]["revision"],
        "ca": state["management_ca"],
        "revoked_keys": state["security"]["revoked_keys"],
        "krl": state["security"]["krl"],
        "credential": member["management_certificate"],
        "identity_file": member["management_path"],
    }
