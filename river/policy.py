"""Operator-owned allocations and native Nebula configuration."""

import ipaddress
import re

ROLES = {"provider", "manager", "provider-manager", "lighthouse"}


def capabilities(role):
    if role not in ROLES:
        raise ValueError("Unknown machine role")
    return set(role.split("-"))


def compiled_firewall(role, address, prefix):
    inbound, outbound = [], []
    caps = capabilities(role)
    if "manager" in caps:
        outbound.append(
            {
                "port": "any",
                "proto": "any",
                "group": "provider",
                "local_cidr": f"{address}/32",
            }
        )
    if "provider" in caps:
        inbound.append(
            {"port": "any", "proto": "any", "group": "manager", "local_cidr": prefix}
        )
        for port, proto in ((2222, "tcp"), (53, "tcp"), (53, "udp")):
            inbound.append(
                {
                    "port": port,
                    "proto": proto,
                    "group": "manager",
                    "local_cidr": f"{address}/32",
                }
            )
    return {"inbound": inbound, "outbound": outbound}


INTERFACE = "river"
MTU = 1280


def routed_prefix(value):
    """A fixed private guest allocation, never an overlay or default route."""
    network = ipaddress.IPv4Network(value)
    private = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if str(network) != value or not any(
        network.subnet_of(ipaddress.IPv4Network(p)) for p in private
    ):
        raise ValueError("Routed prefix must be a canonical RFC1918 IPv4 network")
    return network


def validate_routers(routers, network, lighthouses):
    if not isinstance(routers, dict) or len(routers) > 256:
        raise ValueError("Expected at most 256 fixed routers")
    prefixes, addresses = [], set()
    for host_name, router in routers.items():
        name(host_name)
        fields(router, "prefix via")
        prefix = routed_prefix(router["prefix"])
        address = ipaddress.IPv4Address(router["via"])
        if (
            host_name in lighthouses
            or address not in network
            or address in {network.network_address, network.broadcast_address}
            or str(address) in {lh["address"] for lh in lighthouses.values()}
            or address in addresses
            or prefix.overlaps(network)
            or any(prefix.overlaps(p) for p in prefixes)
        ):
            raise ValueError("Invalid, overlapping or duplicate router allocation")
        addresses.add(address)
        prefixes.append(prefix)


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected.split()):
        raise ValueError(f"Expected exactly these fields: {expected}")


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value):
        raise ValueError("Invalid node name")
    return value


def fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Invalid certificate fingerprint")


def validate_profiles(profiles):
    fields(profiles, " ".join(sorted(ROLES)))
    for role, profile in profiles.items():
        if (
            not isinstance(profile, dict)
            or not {"firewall"} <= set(profile) <= {"firewall", "relay"}
            or profile["firewall"] != {"inbound": [], "outbound": []}
        ):
            raise ValueError(
                "River compiles capability policy; custom firewall profiles are unsupported"
            )
        if "relay" in profile:
            relay = profile["relay"]
            if (
                not isinstance(relay, dict)
                or not set(relay) <= {"am_relay", "use_relays", "relays"}
                or (relay.get("am_relay") and role != "lighthouse")
            ):
                raise ValueError(
                    "Expected native relay settings; only lighthouses may relay"
                )


def validate(value):
    fields(
        value,
        "schema fabric revision network lighthouses routers revoked profiles",
    )
    if value["schema"] != 1 or type(value["schema"]) is not int:
        raise ValueError("Wrong schema or fabric")
    if type(value["revision"]) is not int or value["revision"] < 1:
        raise ValueError("Invalid application revision")
    network = ipaddress.IPv4Network(value["network"])
    lighthouses = value["lighthouses"]
    if not isinstance(lighthouses, dict) or not 0 <= len(lighthouses) <= 4:
        raise ValueError("Expected one to four named lighthouses")
    addresses = set()
    for host_name, lighthouse in lighthouses.items():
        name(host_name)
        fields(lighthouse, "address endpoint")
        address = ipaddress.IPv4Address(lighthouse["address"])
        if (
            address not in network
            or address in {network.network_address, network.broadcast_address}
            or address in addresses
        ):
            raise ValueError("Invalid or duplicate lighthouse address")
        addresses.add(address)
        host, port = lighthouse["endpoint"].rsplit(":", 1)
        ipaddress.IPv4Address(host)
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid lighthouse UDP endpoint")
    validate_routers(value["routers"], network, lighthouses)
    if not isinstance(value["revoked"], list) or len(value["revoked"]) > 4096:
        raise ValueError("Invalid blocklist")
    for item in value["revoked"]:
        fingerprint(item)
    validate_profiles(value["profiles"])
    return value


def plan(policy, identity, ca, cert, key_path):
    """Certificate groups select native configuration; Nebula owns admission."""
    details = identity["details"]
    if len(details["networks"]) != 1:
        raise ValueError("Expected one native overlay address")
    address = ipaddress.IPv4Interface(details["networks"][0])
    if str(address.network) != policy["network"]:
        raise ValueError("Native certificate and policy networks differ")
    groups = set(details["groups"])
    lighthouses = list(policy["lighthouses"].values())
    is_lighthouse = str(address.ip) in {lh["address"] for lh in lighthouses}
    role = (
        "provider-manager"
        if groups == {"provider", "manager"}
        else next(iter(groups), None)
    )
    if role not in ROLES or groups != capabilities(role):
        raise ValueError("Expected exact configured native capabilities")
    router = policy["routers"].get(details["name"])
    expected = [router["prefix"]] if router else []
    if (details["unsafeNetworks"] or []) != expected or (
        router
        and ("provider" not in capabilities(role) or router["via"] != str(address.ip))
    ):
        raise ValueError("Native routed identity and operator allocation disagree")
    if (role == "lighthouse") != is_lighthouse:
        raise ValueError("Native role and lighthouse topology disagree")
    if ("provider" in capabilities(role)) != bool(router):
        raise ValueError("Provider capability requires a routed prefix")
    profile = {
        **policy["profiles"][role],
        "firewall": compiled_firewall(
            role, str(address.ip), expected[0] if expected else None
        ),
    }
    return {
        "pki": {
            "ca": ca,
            "cert": cert,
            "key": str(key_path),
            "blocklist": policy["revoked"],
            "disconnect_invalid": True,
        },
        "static_host_map": {lh["address"]: [lh["endpoint"]] for lh in lighthouses},
        "lighthouse": {
            "am_lighthouse": is_lighthouse,
            "interval": 5,
            "hosts": [] if is_lighthouse else [lh["address"] for lh in lighthouses],
        },
        "listen": {"host": "0.0.0.0", "port": 4242},
        "punchy": {"punch": True},
        "tun": {
            "dev": INTERFACE,
            "mtu": MTU,
            "unsafe_routes": [
                {"route": r["prefix"], "via": r["via"], "mtu": MTU}
                for host, r in sorted(policy["routers"].items())
                if host != details["name"]
            ]
            if role != "lighthouse"
            else [],
        },
        "logging": {"level": "info", "format": "json"},
        **profile,
    }
