"""Install native configuration supplied over the operator's authenticated channel."""

import base64
import os

from . import facts, native, policy
from .common import (
    atomic,
    certificate,
    diagnostic,
    digest,
    encode,
    read,
    run,
)


def accepted_version(store, bundle, *, installing=False):
    versions = {}
    for name in ("desired", "retired"):
        path = store / (name + ".json")
        if not path.exists():
            continue
        previous = read(path)
        versions[name] = previous
        if (
            previous["anchor"]["sequence"] > bundle["anchor"]["sequence"]
            or previous["anchor"]["issued"] > bundle["anchor"]["issued"]
        ):
            raise ValueError("Operator history is older than installed authority")
        if bundle["revision"] < previous["revision"] or (
            bundle["revision"] == previous["revision"] and bundle != previous
        ):
            raise ValueError("Stale or conflicting accepted River revision")
    retired = versions.get("retired")
    if (
        installing
        and retired
        and retired["revision"] >= versions.get("desired", {}).get("revision", 0)
        and bundle["replacement"] is not True
    ):
        raise ValueError(
            "Retired River authority requires explicit operator replacement"
        )


def install(store, bundle, *, validate_only=False):
    native.service_store(store)
    policy.fields(
        bundle,
        "format name revision prefix directory policy authorization config replacement anchor",
    )
    if type(bundle["format"]) is not int or bundle["format"] != 2:
        raise ValueError("Unsupported River enrollment format")
    policy.name(bundle["name"])
    if type(bundle["revision"]) is not int or bundle["revision"] < 1:
        raise ValueError("Invalid operator revision")
    accepted_version(store, bundle, installing=True)
    config = bundle["config"]
    if (
        not __import__("pathlib")
        .Path(config["pki"]["key"])
        .is_relative_to(store / "keys")
        or config["tun"]["dev"] != facts.INTERFACE
    ):
        raise ValueError(
            "Configuration must use this service's private identity and interface"
        )
    atomic(store / "candidate.crt", config["pki"]["cert"].encode())
    atomic(store / "candidate-ca.crt", config["pki"]["ca"].encode())
    info = certificate(store / "candidate.crt")
    if info["details"]["name"] != bundle["name"]:
        raise ValueError("Certificate name mismatch")
    public = "".join(
        line
        for line in __import__("pathlib")
        .Path(config["pki"]["key"])
        .with_suffix(".pub")
        .read_text()
        .splitlines()
        if not line.startswith("---")
    )
    if base64.b64decode(public).hex() != info["publicKey"]:
        raise ValueError("Certificate does not match the node's existing private key")
    prefix = bundle["prefix"]
    if prefix is not None:
        policy.routed_prefix(prefix)
    if (info["details"]["unsafeNetworks"] or []) != ([prefix] if prefix else []):
        raise ValueError("Native certificate and owned prefix differ")
    if info["fingerprint"] in config["pki"]["blocklist"]:
        raise ValueError("Cannot install a revoked identity")
    facts.validate(bundle["directory"], info, bundle["revision"], prefix, config)
    network_policy = policy.validate(bundle["policy"])
    if (
        network_policy["fabric"] != bundle["directory"]["fabric"]
        or network_policy["revision"] != bundle["revision"]
        or network_policy["routers"] != facts.routers(bundle["directory"])
    ):
        raise ValueError("Contradictory delivered policy")
    expected_config = policy.plan(
        network_policy,
        info,
        config["pki"]["ca"],
        config["pki"]["cert"],
        config["pki"]["key"],
    )
    if expected_config != config:
        raise ValueError("Configuration differs from compiled capability policy")
    access = bundle["authorization"]
    policy.fields(
        access, "schema fabric revision ca revoked_keys credential identity_file krl"
    )
    if (
        access["schema"] != 2
        or access["fabric"] != network_policy["fabric"]
        or access["revision"] != bundle["revision"]
    ):
        raise ValueError("Contradictory management authority artifact")
    if (store / "desired.json").exists():
        previous = read(store / "desired.json")
        if bundle["directory"]["fabric"] != previous["directory"]["fabric"]:
            raise ValueError("Network fabric changed; reset must be explicit")
    if (store / "node.json").exists():
        pinned = read(store / "node.json")
        if pinned != {
            "format": 1,
            "name": bundle["name"],
            "ca": digest(config["pki"]["ca"].encode()),
        } or (
            certificate(store / "host.crt")["publicKey"] != info["publicKey"]
            and not bundle["replacement"]
        ):
            raise ValueError(
                "Node identity or authority changed; reset must be explicit"
            )
    run(
        "nebula-cert",
        "verify",
        "-ca",
        store / "candidate-ca.crt",
        "-crt",
        store / "candidate.crt",
    )
    native.preflight(store, config)
    if validate_only:
        return {
            "name": bundle["name"],
            "directory": bundle["directory"],
            "authorization": bundle["authorization"],
        }
    atomic(store / "management-ca.pub", (access["ca"] + "\n").encode())
    atomic(store / "revoked.krl", base64.b64decode(access["krl"], validate=True))
    if access["credential"]:
        atomic(
            __import__("pathlib").Path(access["identity_file"] + "-cert.pub"),
            (access["credential"] + "\n").encode(),
        )
    atomic(store / "ca.crt", config["pki"]["ca"].encode())
    atomic(store / "host.crt", config["pki"]["cert"].encode())
    atomic(
        store / "node.json",
        encode(
            {
                "format": 1,
                "name": bundle["name"],
                "ca": digest(config["pki"]["ca"].encode()),
            }
        ),
    )
    atomic(store / "desired.json", encode(bundle))
    try:
        native.apply(
            store,
            config,
            bundle["revision"],
            prefix,
            disconnect=bundle["replacement"] or bool(config["pki"]["blocklist"]),
        )
    except Exception as error:
        atomic(
            store / "apply.json", encode({"pending": True, "error": diagnostic(error)})
        )
        raise
    try:
        composition("prepare", bundle)
        composition("activate", bundle)
    except Exception as error:
        atomic(
            store / "apply.json",
            encode({"pending": True, "composition_error": diagnostic(error)}),
        )
    return {
        "configured": bundle["name"],
        "revision": bundle["revision"],
        "applied": True,
        "evidence": check(store, bundle),
    }


def status(store):
    runtime = native.status(store)
    desired = (
        read(store / "desired.json") if (store / "desired.json").exists() else None
    )
    applied = runtime["applied"]
    pending = (
        desired is None
        or applied is None
        or digest(encode(desired["config"])) != applied["config_digest"]
        or bool((runtime["last_apply"] or {}).get("pending"))
    )
    result = {
        "desired": desired["revision"] if desired else None,
        "applied": applied["revision"] if applied else None,
        "pending": pending,
        "service_active": runtime["service_active"],
        "last_apply": runtime["last_apply"],
        "applied_routing": applied.get("routing") if applied else None,
    }
    try:
        result["deadlines"] = {
            "certificate": certificate(store / "host.crt")["details"]["notAfter"],
            "ca": certificate(store / "ca.crt")["details"]["notAfter"],
        }
    except Exception as error:
        result["deadline_error"] = str(error)
    return result


def peers(store):
    """Read the last delivered directory without probing services or the network."""
    native.service_store(store)
    desired = read(store / "desired.json")
    return desired["directory"]


def authorization(store):
    native.service_store(store)
    return read(store / "desired.json")["authorization"]


def prepare(store, request):
    """Operation-scoped key generation, delegated only through maintenance access."""
    from pathlib import Path
    import uuid

    native.service_store(store)
    if os.geteuid() != 0:
        raise ValueError("Preparing a node identity requires root maintenance access")
    operation = str(uuid.UUID(request["operation"]))
    directory = store / "keys" / operation
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    result = {}
    for kind, previous in (
        ("network", request["network_key"]),
        ("management", request["management_key"]),
    ):
        if kind == "management" and not request["manager"]:
            result.update(management_path=None, management_public=None)
            continue
        key = (
            Path(previous)
            if previous
            else directory / ("network.key" if kind == "network" else "manager")
        )
        if not key.is_relative_to(store / "keys"):
            raise ValueError("Prepared keys must belong to this node's River key store")
        public = (
            key.with_suffix(".pub") if kind == "network" else Path(str(key) + ".pub")
        )
        if not key.exists() and not public.exists():
            if kind == "network":
                run("nebula-cert", "keygen", "-out-key", key, "-out-pub", public)
            else:
                run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
            key.chmod(0o600)
        if not key.exists() or not public.exists():
            raise ValueError("Incomplete prepared keypair; inspect before retry")
        result[kind + "_path"] = str(key)
        result[kind + "_public"] = public.read_text().strip()
    return result


def composition(phase, bundle):
    from pathlib import Path
    from . import koi_security

    if not Path("/etc/river/koi-enabled").exists():
        raise ValueError("Enable River's Koi projection on provider/manager nodes")
    return koi_security.node(phase, bundle)


def check(store, bundle):
    import base64
    from .credentials import check_krl

    if bundle.get("disabled"):
        return disable(store, bundle, check_only=True)
    accepted_version(store, bundle, installing=True)
    installed = read(store / "desired.json")
    if (
        installed["anchor"]["sequence"] > bundle["anchor"]["sequence"]
        or installed["anchor"]["issued"] > bundle["anchor"]["issued"]
    ):
        raise ValueError("Operator history is older than installed authority")
    if installed != bundle or read(store / "active.json") != bundle["config"]:
        raise ValueError("Persistent node artifacts differ from the prepared operation")
    if (store / "management-ca.pub").read_text().strip() != bundle["authorization"][
        "ca"
    ]:
        raise ValueError("Management issuer differs from prepared trust")
    if (store / "revoked.krl").read_bytes() != base64.b64decode(
        bundle["authorization"]["krl"], validate=True
    ):
        raise ValueError(
            "Persistent management KRL differs from prepared rejection state"
        )
    access = bundle["authorization"]
    if access["credential"]:
        from pathlib import Path

        key = Path(access["identity_file"])
        if (
            key.with_name(key.name + "-cert.pub").read_text().strip()
            != access["credential"]
        ):
            raise ValueError(
                "Installed manager certificate differs from approved authority"
            )
        run("ssh-keygen", "-l", "-f", str(key) + "-cert.pub")
    revocations = check_krl(
        store / "revoked.krl", bundle["authorization"]["revoked_keys"]
    )
    native.preflight(store, bundle["config"])
    instance = (
        run(
            "systemctl", "show", "river-nebula.service", "-p", "InvocationID", "--value"
        )
        .decode()
        .strip()
    )
    applied = read(store / "applied.json")
    if (
        not native.interface_exists("river")
        or not native.active()
        or not instance
        or instance != applied["invocation_id"]
    ):
        raise ValueError("Nebula activation evidence differs from its current process")
    pid = (
        run("systemctl", "show", "river-nebula.service", "-p", "MainPID", "--value")
        .decode()
        .strip()
    )
    from pathlib import Path

    command = Path("/proc") / pid / "cmdline"
    if str(store / "active.json").encode() not in command.read_bytes().split(b"\0"):
        raise ValueError("Running Nebula does not use the installed configuration")
    try:
        composed = composition("check", bundle)
        last = read(store / "apply.json")
        if last.get("composition_error"):
            composed = {"verified": False, "error": last["composition_error"]}
    except Exception as error:
        composed = {"verified": False, "error": diagnostic(error)}
    return {
        "installed": True,
        "activated": True,
        "checked": True,
        "old_connections_handled": bool(applied["connections_reset"]),
        "pid": pid,
        "invocation_id": instance,
        "revocation_check": {
            "nebula_fingerprints": bundle["config"]["pki"]["blocklist"],
            "ssh_keys": revocations,
        },
        "anchor": bundle["anchor"],
        "composition": composed,
    }


def disable(store, request, *, check_only=False):
    native.service_store(store)
    accepted_version(store, request)
    if not check_only:
        atomic(store / "retired.json", encode(request))
        (store / "active.json").unlink(missing_ok=True)
        run("systemctl", "stop", "river-nebula.service")
        composition("disable", request)
    if (
        native.active()
        or (store / "active.json").exists()
        or read(store / "retired.json") != request
    ):
        raise ValueError("Retired node still has active River authority")
    return {
        "installed": True,
        "activated": True,
        "checked": True,
        "old_connections_handled": True,
        "retired": True,
        "composition": composition("check-disabled", request),
    }
