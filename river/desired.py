"""Compile the operator's editable fleet map into native credentials and policy."""

import ipaddress

from . import policy, transport
from .common import atomic, encode


def initialize(store):
    path = store / "map.json"
    if path.exists() or (store / "fleet.json").exists():
        raise ValueError("Operator database already exists")
    atomic(path, encode({"schema": 2, "network": "10.77.0.0/24", "peers": {}}))
    return {"map": str(path), "next": "Edit the fleet map, then run river plan"}


def validate(source):
    if not isinstance(source, dict) or not {"schema", "network", "peers"} <= set(
        source
    ) <= {"schema", "network", "peers", "lifetimes"}:
        raise ValueError("Expected schema, network, peers and optional lifetimes")
    lifetimes = source.get(
        "lifetimes", {"leaf_days": 180, "renew_days": 30, "issuer_days": 365}
    )
    policy.fields(lifetimes, "leaf_days renew_days issuer_days")
    if (
        not all(type(v) is int and v > 0 for v in lifetimes.values())
        or not lifetimes["renew_days"]
        < lifetimes["leaf_days"]
        < lifetimes["issuer_days"]
    ):
        raise ValueError("Expected renewal threshold < leaf lifetime < issuer lifetime")
    if type(source["schema"]) is not int or source["schema"] != 2:
        raise ValueError("Unsupported operator map schema; expected schema 2")
    network = ipaddress.IPv4Network(source["network"])
    if str(network) != source["network"] or network.num_addresses < 8:
        raise ValueError(
            "Choose a canonical overlay network with at least eight addresses"
        )
    peers = source["peers"]
    if not isinstance(peers, dict) or not 1 <= len(peers) <= 256:
        raise ValueError("Expected one to 256 operator-defined peers")
    addresses, lighthouses, routers = set(), {}, {}
    for name, peer in peers.items():
        policy.name(name)
        if not isinstance(peer, dict) or not (
            {"role", "address", "target"}
            <= set(peer)
            <= {
                "role",
                "address",
                "target",
                "endpoint",
                "routed_prefix",
                "ssh_config",
            }
        ):
            raise ValueError(
                "Peer requires role, address and target; unknown map fields are refused"
            )
        caps = policy.capabilities(peer["role"])
        address = ipaddress.IPv4Address(peer["address"])
        if (
            str(address) != peer["address"]
            or address not in network
            or address in {network.network_address, network.broadcast_address}
            or address in addresses
        ):
            raise ValueError("Invalid or duplicate operator-assigned overlay address")
        addresses.add(address)
        transport.validate_target(peer["target"])
        if "ssh_config" in peer and not isinstance(peer["ssh_config"], str):
            raise ValueError("SSH configuration must be a file path")
        if ("endpoint" in peer) != (peer["role"] == "lighthouse"):
            raise ValueError("Only lighthouses require a public endpoint")
        if "endpoint" in peer:
            lighthouses[name] = {
                "address": peer["address"],
                "endpoint": peer["endpoint"],
            }
        if ("routed_prefix" in peer) != ("provider" in caps):
            raise ValueError("Only providers require a routed prefix")
        if "routed_prefix" in peer:
            if policy.routed_prefix(peer["routed_prefix"]).prefixlen != 24:
                raise ValueError("Provider exported guest prefixes must be /24")
            routers[name] = {"prefix": peer["routed_prefix"], "via": peer["address"]}
    policy.validate(
        {
            "schema": 1,
            "fabric": "validation",
            "revision": 1,
            "network": source["network"],
            "lighthouses": lighthouses,
            "routers": routers,
            "revoked": [],
            "profiles": {
                role: {"firewall": {"inbound": [], "outbound": []}}
                for role in policy.ROLES
            },
        }
    )
    return source
