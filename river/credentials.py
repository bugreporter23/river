"""Native public credential history; private issuers remain compile-scoped."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile

from . import authority, policy
from .common import certificate, run


def now():
    return datetime.now(timezone.utc)


def date(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def retire(state, name):
    import base64

    for entry in state["history"]:
        if entry["name"] == name:
            entry["status"] = "revoked"
            state["policy"]["revoked"] = sorted(
                set(state["policy"]["revoked"]) | {entry["fingerprint"]}
            )
            if entry["management_key"]:
                state["security"]["revoked_keys"] = sorted(
                    set(state["security"]["revoked_keys"]) | {entry["management_key"]}
                )
    state["security"]["krl"] = base64.b64encode(
        krl(state["security"]["revoked_keys"])
    ).decode()


def sign(store, state, name, peer, prepared, signer, operation, days):
    issuer_deadline = date(state["security"]["issuer_retire_after"])
    validity = min(timedelta(days=days), issuer_deadline - now()) - timedelta(
        seconds=len(state["history"]) + 1
    )
    if validity <= timedelta(days=1):
        raise ValueError("Issuer expiry requires separate authority rollover")
    with tempfile.TemporaryDirectory(dir=store) as temporary:
        temporary = Path(temporary)
        public = temporary / "network.pub"
        public.write_text(prepared["network_public"])
        cert = temporary / "host.crt"
        address = f"{peer['address']}/{__import__('ipaddress').IPv4Network(state['policy']['network']).prefixlen}"
        signer.native(
            "-ca-crt",
            store / "ca.crt",
            "-name",
            name,
            "-networks",
            address,
            "-groups",
            ",".join(sorted(policy.capabilities(peer["role"]))),
            "-unsafe-networks",
            peer.get("routed_prefix", ""),
            "-duration",
            str(int(validity.total_seconds())) + "s",
            "-in-pub",
            public,
            "-out-crt",
            cert,
        )
        info = certificate(cert)
        if info["fingerprint"] in state["policy"]["revoked"]:
            raise ValueError(
                "Native issuance reproduced a retired certificate; no credential released"
            )
        management_certificate = None
        if prepared["management_public"]:
            public = temporary / "manager.pub"
            public.write_text(prepared["management_public"] + "\n")
            fd = os.memfd_create("river-management-ca", os.MFD_CLOEXEC)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, signer.keys["management"].encode())
                signer.check()
                run(
                    "ssh-keygen",
                    "-q",
                    "-s",
                    f"/proc/self/fd/{fd}",
                    "-I",
                    name + ":" + operation,
                    "-z",
                    str(len(state["history"]) + 1),
                    "-n",
                    "river-manager",
                    "-O",
                    "clear",
                    "-V",
                    "-1m:+" + str(int(validity.total_seconds())) + "s",
                    public,
                    pass_fds=(fd,),
                )
            finally:
                os.close(fd)
            management_certificate = (
                (temporary / "manager-cert.pub").read_text().strip()
            )
        member = {
            "name": name,
            "role": peer["role"],
            "address": address,
            "routed_prefix": peer.get("routed_prefix"),
            "fingerprint": info["fingerprint"],
            "public_key": prepared["network_public"],
            "certificate": cert.read_text(),
            "identity": info,
            "native": peer["role"] == "lighthouse",
            "target": peer["target"],
            "ssh_config": peer.get("ssh_config"),
            "key_path": prepared["network_path"],
            "management_path": prepared["management_path"],
            "management_key": prepared["management_public"],
            "management_certificate": management_certificate,
            "operation": operation,
        }
    previous = state["issued"].get(name)
    if previous:
        for entry in state["history"]:
            if (
                entry["fingerprint"] == previous["fingerprint"]
                and entry["status"] == "issued"
            ):
                entry["status"] = "superseded"
    state["issued"][name] = member
    state["history"].append({**member, "status": "issued"})
    authority.save(store, state)
    return member


def krl(public_keys):
    with tempfile.TemporaryDirectory() as temporary:
        keys, output = Path(temporary) / "keys", Path(temporary) / "revoked.krl"
        keys.write_text("\n".join(public_keys) + "\n")
        run("ssh-keygen", "-k", "-f", output, keys)
        return output.read_bytes()


def check_krl(path, public_keys):
    results = []
    import subprocess

    for key in public_keys:
        with tempfile.NamedTemporaryFile(mode="w") as public:
            public.write(key + "\n")
            public.flush()
            result = subprocess.run(
                ["ssh-keygen", "-Q", "-f", str(path), public.name],
                text=True,
                capture_output=True,
            )
        if result.returncode != 1 or "REVOKED" not in result.stdout or result.stderr:
            raise ValueError(
                "KRL query failed to establish revocation: "
                + result.stdout
                + result.stderr
            )
        results.append("revoked")
    return results
