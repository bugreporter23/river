"""River exposes independent local Koi through fleet addresses and manager authority."""

import ipaddress
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from .common import NODE_STORE, atomic as write_atomic, read

STATE = NODE_STORE / "koi"
DNS = Path("/run/river-koi-dns")


def atomic(path, value, mode=0o600):
    write_atomic(path, value.encode(), mode)


def run(*command, capture=False, **kwargs):
    print("Running " + " ".join(map(str, command)), file=sys.stderr, flush=True)
    result = subprocess.run(
        list(map(str, command)),
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else sys.stderr,
        **kwargs,
    )
    return result.stdout if capture else None


CONFIG = STATE / "network.json"
RESOLVER = STATE / "resolver-interface"
RESOLVER_ENABLED = Path("/etc/river/koi-resolver")
ROUTE_PROTOCOL = "99"


def management_key(name, *, create=False):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError(
            "River Koi projection directory must be private and root-owned"
        )
    key = STATE / (name + ".key")
    public = key.with_suffix(".key.pub")
    if create and not key.exists() and not public.exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
        key.chmod(0o600)
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("River projection private key must be private and root-owned")
    return key


def facts():
    accepted = read(NODE_STORE / "desired.json")
    return accepted["directory"], accepted["authorization"]


def zone(value):
    if not re.fullmatch(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+", value):
        raise ValueError("Choose a lowercase private DNS domain")
    return value


def local_network():
    facts = json.loads(run("koi", "--host", "local", "network", "--json", capture=True))
    prefix = ipaddress.IPv4Network(facts["prefix"])
    if facts["mode"] != "local" or prefix.prefixlen != 24 or not facts["present"]:
        raise ValueError("Provider requires an existing local Koi /24 network")
    return facts


def translated(address, source, destination):
    ip = ipaddress.IPv4Address(address)
    source, destination = (
        ipaddress.IPv4Network(source),
        ipaddress.IPv4Network(destination),
    )
    if source.prefixlen != 24 or destination.prefixlen != 24 or ip not in source:
        raise ValueError("Guest address does not match the /24 translation")
    offset = int(ip) - int(source.network_address)
    if not 1 < offset < 255:
        raise ValueError("Guest address is reserved for network, bridge or broadcast")
    return str(ipaddress.IPv4Address(int(destination.network_address) + offset))


def project_guests(value, settings):
    def project(item):
        if not isinstance(item, dict) or "address" not in item:
            return item
        result = dict(item)
        result["address"] = translated(
            item["address"], settings["local_prefix"], settings["prefix"]
        )
        if "host" in result:
            guest = result["host"].split(".")[-1]
            result["host"] = f"{guest}.{settings['name']}.{settings['zone']}"
        return result

    return (
        [project(item) for item in value] if isinstance(value, list) else project(value)
    )


def manage():
    settings = json.loads(CONFIG.read_text())
    if "provider" not in settings["role"]:
        raise ValueError("This node is not an enrolled provider")
    request = sys.stdin.buffer.readline(65537)
    if len(request) > 65536:
        raise ValueError("Management request too large")
    reply = subprocess.run(
        ["koi-admin", "local"],
        input=request,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if reply.returncode:
        sys.stdout.buffer.write(reply.stdout)
        sys.stderr.buffer.write(reply.stderr)
        raise SystemExit(reply.returncode)
    response = json.loads(reply.stdout)
    if response["ok"]:
        response["result"] = project_guests(response["result"], settings)
    print(json.dumps(response))


def prepare_node(bundle):
    validated = {
        "directory": bundle["directory"],
        "name": bundle["name"],
        "authorization": bundle["authorization"],
    }
    directory = validated["directory"]
    own = directory["peers"][validated["name"]]
    settings = {
        "name": validated["name"],
        "zone": zone(
            json.loads(CONFIG.read_text())["zone"] if CONFIG.exists() else "vms.test"
        ),
        "interface": directory["interface"],
        "address": own["address"],
        "prefix": own["routed_prefix"],
        "mtu": directory["mtu"],
        "role": own["role"],
        "overlay": directory["network"],
    }
    if "provider" in own["role"]:
        local = local_network()
        exported = ipaddress.IPv4Network(settings["prefix"])
        local_prefix = ipaddress.IPv4Network(local["prefix"])
        if exported.prefixlen != 24:
            raise ValueError("Guest export requires a River /24 allocation")
        if local_prefix.overlaps(ipaddress.IPv4Network(directory["network"])) or any(
            local_prefix.overlaps(ipaddress.IPv4Network(peer["routed_prefix"]))
            for peer in directory["peers"].values()
            if peer["routed_prefix"]
        ):
            raise ValueError(
                "River address space overlaps Koi's local network; choose a different River export"
            )
        settings.update(local_prefix=str(local_prefix), bridge=local["interface"])
        management_key("server", create=True)
    if CONFIG.exists():
        previous = json.loads(CONFIG.read_text())
        if previous.get("prefix") and previous["prefix"] != settings["prefix"]:
            remove_route(previous)
    atomic(CONFIG, json.dumps(settings) + "\n")
    run("systemctl", "start", "river-koi-network.service")
    configure(settings, directory, validated["authorization"])
    apply_guard()


def render_guard(settings, access):
    interface = settings["interface"]
    own_address = settings["address"]
    provider = "provider" in settings["role"]
    source = settings["overlay"]
    rules = []
    if provider:
        rules += [
            f'iifname "{interface}" ip saddr {source} ip daddr {own_address} tcp dport {{ 53, 2222 }} accept',
            f'iifname "{interface}" ip saddr {source} ip daddr {own_address} udp dport 53 accept',
        ]
    guard = (
        "table inet river_koi {\n chain input { type filter hook input priority -10; policy accept;\n  ct state established,related accept\n  "
        + "\n  ".join(rules)
        + f'\n  iifname "{interface}" tcp dport {{ 53, 2222 }} drop\n  iifname "{interface}" udp dport 53 drop\n }}\n chain forward {{ type filter hook forward priority -10; policy accept;\n  '
    )
    if provider:
        guard += f'iifname "{interface}" oifname "{settings["bridge"]}" ip saddr {source} ip daddr {settings["local_prefix"]} ct original ip daddr {settings["prefix"]} accept\n  iifname "{settings["bridge"]}" oifname "{interface}" ct state established,related accept\n  '
    guard += f'iifname "{interface}" drop\n  oifname "{interface}" drop\n }}\n'
    if provider:
        local, exported = settings["local_prefix"], settings["prefix"]
        bridge = settings["bridge"]
        guard += f""" chain prerouting {{ type nat hook prerouting priority dstnat - 10; policy accept;
  iifname "{interface}" ip daddr {exported} dnat ip prefix to ip daddr map {{ {exported} : {local} }}
 }}
 chain output {{ type nat hook output priority dstnat - 10; policy accept;
  ip daddr {exported} dnat ip prefix to ip daddr map {{ {exported} : {local} }}
 }}
 chain postrouting {{ type nat hook postrouting priority srcnat - 10; policy accept;
  iifname "{bridge}" oifname "{interface}" ip saddr {local} snat ip prefix to ip saddr map {{ {local} : {exported} }}
 }}
"""
    guard += "}\n"
    return guard


def configure(settings, directory, access):
    own_address = settings["address"]
    provider = "provider" in settings["role"]
    atomic(STATE / "guard.nft", render_guard(settings, access))
    run("nft", "--check", "--file", STATE / "guard.nft")
    if provider:
        command = shutil.which("river")
        if command is None:
            raise ValueError("Composition management entry point is unavailable")
        command = str(Path(command).resolve())
        atomic(
            STATE / "sudoers.d/manager",
            f"koi-manager ALL=(root) NOPASSWD: {command} koi manage\n",
        )
        run("visudo", "-cf", STATE / "sudoers.d/manager")
        atomic(STATE / "management-principals", "river-manager\n", 0o644)
        ssh = f"""Port 2222
ListenAddress {own_address}
HostKey {STATE}/server.key
PidFile /run/river-koi-sshd.pid
AuthorizedKeysFile none
TrustedUserCAKeys /var/lib/river/management-ca.pub
AuthorizedPrincipalsFile {STATE}/management-principals
RevokedKeys /var/lib/river/revoked.krl
AllowUsers koi-manager
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitRootLogin no
PermitTTY no
PermitUserRC no
DisableForwarding yes
ForceCommand /run/wrappers/bin/sudo -n {command} koi manage
"""
        atomic(STATE / "sshd.conf", ssh)
        run("sshd", "-t", "-f", STATE / "sshd.conf")
    else:
        for path in (
            STATE / "sshd.conf",
            STATE / "management-principals",
            STATE / "sudoers.d/manager",
        ):
            path.unlink(missing_ok=True)
    data = DNS
    data.mkdir(parents=True, exist_ok=True)
    data.chmod(0o755)
    hosts = data / "hosts"
    if not hosts.exists():
        atomic(hosts, "", 0o644)
    domain = settings["zone"]
    dns = f"port=53\nlisten-address=127.0.0.55,{own_address}\nbind-dynamic\nno-hosts\nno-resolv\nlocal=/{domain}/\n"
    if provider:
        dns += f"local=/{settings['name']}.{domain}/\naddn-hosts={hosts}\n"
    if "manager" in settings["role"]:
        for name, peer in directory["peers"].items():
            if "provider" in peer["role"] and name != settings["name"]:
                dns += f"server=/{name}.{domain}/{peer['address']}\n"
    atomic(data / "dnsmasq.conf", dns, 0o644)


def projection_routes(settings):
    return json.loads(
        run(
            "ip",
            "-Numeric",
            "-json",
            "route",
            "show",
            "exact",
            settings["prefix"],
            capture=True,
        )
    )


def install_route(settings):
    if any(
        route.get("dev") != settings["bridge"]
        or str(route.get("protocol")) != ROUTE_PROTOCOL
        for route in projection_routes(settings)
    ):
        raise ValueError("River export conflicts with an existing host route")
    run(
        "ip",
        "route",
        "replace",
        settings["prefix"],
        "dev",
        settings["bridge"],
        "proto",
        ROUTE_PROTOCOL,
    )


def remove_route(settings):
    if "provider" not in settings["role"]:
        return
    for route in projection_routes(settings):
        if (
            route.get("dev") == settings["bridge"]
            and str(route.get("protocol")) == ROUTE_PROTOCOL
        ):
            run(
                "ip",
                "route",
                "del",
                settings["prefix"],
                "dev",
                settings["bridge"],
                "proto",
                ROUTE_PROTOCOL,
            )


def remove_resolver():
    if RESOLVER.exists():
        interface = RESOLVER.read_text().strip()
        links = json.loads(run("ip", "-json", "link", "show", capture=True))
        if any(link["ifname"] == interface for link in links):
            run("resolvectl", "revert", interface)
        RESOLVER.unlink()


def withdraw():
    if CONFIG.exists():
        remove_route(json.loads(CONFIG.read_text()))
    remove_resolver()
    tables = json.loads(run("nft", "--json", "list", "tables", capture=True))[
        "nftables"
    ]
    if any(
        item.get("table", {}).get("family") == "inet"
        and item["table"]["name"] == "river_koi"
        for item in tables
    ):
        run("nft", "delete", "table", "inet", "river_koi")
    if (STATE / "targets-applied.json").exists():
        run(
            "koi-host",
            "admin-targets",
            "withdraw",
            "--identity-directory",
            NODE_STORE / "keys",
            capture=True,
        )
    (STATE / "sudoers.d/manager").unlink(missing_ok=True)
    (STATE / "security-applied.json").unlink(missing_ok=True)
    if DNS.exists():
        shutil.rmtree(DNS)


def apply_guard():
    listed = subprocess.run(
        ["nft", "list", "table", "inet", "river_koi"], capture_output=True
    )
    if listed.returncode == 0:
        rules = "delete table inet river_koi\n" + (STATE / "guard.nft").read_text()
    else:
        rules = (STATE / "guard.nft").read_text()
    run("nft", "-f", "-", input=rules)


def activate(directory=None, access=None):
    settings = json.loads(CONFIG.read_text())
    if directory is None:
        directory, access = facts()
    peer = directory["peers"].get(settings["name"])
    if (
        peer is None
        or peer["address"] != settings["address"]
        or peer["routed_prefix"] != settings["prefix"]
        or peer["role"] != settings["role"]
    ):
        raise ValueError("Delivered network facts differ from enrolled plumbing")
    if "provider" in settings["role"]:
        local = local_network()
        if (
            local["prefix"] != settings["local_prefix"]
            or local["interface"] != settings["bridge"]
        ):
            raise ValueError(
                "Local Koi network changed; inspect the address projection"
            )
        install_route(settings)
    configure(settings, directory, access)
    apply_guard()
    run("systemctl", "start", "river-koi-network.service")
    run("systemctl", "restart", "river-koi-dns.service")
    if RESOLVER_ENABLED.exists():
        interface = settings["interface"]
        atomic(RESOLVER, interface + "\n")
        run("resolvectl", "dns", interface, settings["address"])
        run("resolvectl", "domain", interface, "~" + settings["zone"])
        run("resolvectl", "default-route", interface, "no")
    else:
        remove_resolver()
    if "provider" in settings["role"]:
        run(
            "systemctl",
            "restart",
            "river-koi-ssh.service",
            "river-koi-export.timer",
        )
    else:
        run(
            "systemctl",
            "stop",
            "river-koi-ssh.service",
            "river-koi-export.timer",
        )


def export_dns():
    settings = json.loads(CONFIG.read_text())
    inventory = json.loads(
        run("koi", "--host", "local", "list", "--json", capture=True)
    )
    lines = []
    for guest in inventory:
        address = guest.get("address")
        name = guest["name"]
        if address and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
            ip = translated(address, settings["local_prefix"], settings["prefix"])
            lines.append(f"{ip} {name}.{settings['name']}.{settings['zone']}")
    atomic(DNS / "hosts", "\n".join(lines) + "\n", 0o644)
    run("systemctl", "reload", "river-koi-dns.service")


def targets(pins, *, check=False):
    settings = json.loads(CONFIG.read_text())
    if "manager" not in settings["role"]:
        raise ValueError("This machine has no manager capability")
    directory, access = facts()
    identity = Path(access["identity_file"])
    info = identity.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("River management private key must be private and root-owned")
    providers = {
        name: peer
        for name, peer in directory["peers"].items()
        if "provider" in peer["role"] and name != settings["name"]
    }
    if not isinstance(pins, dict) or not set(pins) <= set(providers):
        raise ValueError("Server-key selections must name approved remote providers")
    config = {}
    for name in sorted(pins):
        peer = providers[name]
        key = pins[name]
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?", key):
            raise ValueError(
                "Expected an Ed25519 server key from the trusted enrollment channel"
            )
        run("ssh-keygen", "-lf", "/dev/stdin", input=key + "\n", capture=True)
        config[name] = {
            "host": peer["address"],
            "port": 2222,
            "identityFile": str(identity),
            "serverKey": key,
        }
    admin_targets(config, check=check)


def admin_targets(targets, *, check=False):
    result = json.loads(
        run(
            "koi-host",
            "admin-targets",
            "check" if check else "apply",
            input=json.dumps(targets),
            capture=True,
        )
    )
    if result.get("verified") is not True:
        raise ValueError("Koi admin target projection did not verify")
