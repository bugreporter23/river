"""One retained operator operation, serial application and timestamped evidence."""

import copy
from datetime import timedelta
import json
import uuid

from . import authority, credentials, desired, policy, session, transport
from .common import atomic, decode, diagnostic, digest, encode, locked, read


def stamp():
    return credentials.now().isoformat()


def composition_verified(evidence):
    return evidence.get("composition", {}).get("verified", True) is True


def save_operation(store, operation):
    atomic(store / "operation.json", encode(operation))
    atomic(store / "operations" / (operation["id"] + ".json"), encode(operation))


def state_hash(state):
    return (
        digest(
            encode({key: value for key, value in state.items() if key != "artifacts"})
        )
        if state
        else None
    )


def amend_locators(store, operation, source, state):
    def claims(value):
        value = copy.deepcopy(value)
        for peer in value["peers"].values():
            peer.pop("target", None)
            peer.pop("ssh_config", None)
        return value

    if claims(source) != claims(operation["source"]):
        raise ValueError(
            "An unfinished security operation exists; only maintenance target/ssh_config amendments may be planned before resuming river apply"
        )
    amendments = []
    for name, peer in source["peers"].items():
        before = {
            key: operation["source"]["peers"][name].get(key)
            for key in ("target", "ssh_config")
        }
        after = {key: peer.get(key) for key in ("target", "ssh_config")}
        if before != after:
            amendments.append(
                {"name": name, "before": before, "after": after, "time": stamp()}
            )
            if name in operation["results"]:
                operation["results"][name].update(
                    verified=False, transport_verified=False, locator_pending=True
                )
    operation.setdefault("maintenance_amendments", []).extend(amendments)
    operation["source"] = source
    operation["map_hash"] = digest(encode(source))
    save_operation(store, operation)
    return summary(operation, state)


def prepare(store, kind="map", name=None, target=None):
    with locked(store):
        source = desired.validate(read(store / "map.json"))
        state = authority.load(store) if (store / "fleet.json").exists() else None
        previous = (
            read(store / "operation.json")
            if (store / "operation.json").exists()
            else None
        )
        if previous and previous["phase"] != "complete" and kind != "compromise":
            if kind == "map" and (
                previous["kind"] == "compromise"
                or previous["phase"] != "prepared"
                or source == previous["source"]
            ):
                return amend_locators(store, previous, source, state)
            if previous["kind"] == "compromise" or previous["phase"] != "prepared":
                raise ValueError(
                    "An unfinished operation exists; resume river apply before preparing another"
                )
        if kind in ("compromise", "replace") and (
            state is None or name not in state["issued"]
        ):
            raise ValueError("Unknown issued node")
        if kind == "compromise":
            state["security"]["disabled"][name] = {
                "reason": "suspected compromise",
                "time": stamp(),
            }
            credentials.retire(state, name)
            authority.save(store, state)
        if kind == "replace":
            if name not in source["peers"]:
                raise ValueError(
                    "Restore the replacement's approved claims in map.json first"
                )
            transport.validate_target(target)
            source["peers"][name]["target"] = target
            atomic(store / "map.json", encode(source))
        disabled = state["security"]["disabled"] if state else {}
        effective = {
            n: p
            for n, p in source["peers"].items()
            if n not in disabled or (kind == "replace" and n == name)
        }
        lifetimes = source.get(
            "lifetimes", {"leaf_days": 180, "renew_days": 30, "issuer_days": 365}
        )
        if (
            state
            and lifetimes["issuer_days"]
            != state["security"]["lifetimes"]["issuer_days"]
        ):
            raise ValueError(
                "Issuer lifetime changes require separate authority rollover"
            )
        if (
            kind == "renew"
            and state
            and credentials.date(state["security"]["issuer_retire_after"])
            <= credentials.now() + timedelta(days=lifetimes["renew_days"])
        ):
            raise ValueError(
                "Issuer is approaching expiry; ordinary leaf renewal cannot extend its trust"
            )
        changes, fleet_scope = [], state is None
        current = state["issued"] if state else {}
        for n, member in current.items():
            if (
                n not in effective
                and member["fingerprint"] not in state["policy"]["revoked"]
            ):
                changes.append({"name": n, "action": "remove"})
                fleet_scope = True
        for n, peer in effective.items():
            member = current.get(n)
            claims = {
                "role": peer["role"],
                "address": peer["address"],
                "routed_prefix": peer.get("routed_prefix"),
            }
            old = (
                None
                if member is None
                else {
                    "role": member["role"],
                    "address": member["address"].split("/")[0],
                    "routed_prefix": member["routed_prefix"],
                }
            )
            due = member and credentials.date(
                member["identity"]["details"]["notAfter"]
            ) <= credentials.now() + timedelta(days=lifetimes["renew_days"])
            if kind == "replace" and n == name:
                action = "replace"
                fleet_scope = True
            elif member is None:
                action = "add"
                fleet_scope |= peer["role"] != "manager"
            elif claims != old or source["network"] != str(
                __import__("ipaddress").IPv4Interface(member["address"]).network
            ):
                action = "claims"
                promotion = old["role"] == "provider" and claims == {
                    **old,
                    "role": "provider-manager",
                }
                fleet_scope |= not promotion
            elif kind == "renew" and due:
                action = "renew"
            else:
                continue
            changes.append(
                {
                    "name": n,
                    "action": action,
                    "claims": claims,
                    "retire": action == "replace"
                    or (action == "claims" and not promotion),
                }
            )
        if state and any(
            effective[n].get("endpoint")
            != state["policy"]["lighthouses"].get(n, {}).get("endpoint")
            for n in effective
            if effective[n]["role"] == "lighthouse"
        ):
            fleet_scope = True
        if state and any(
            not set(state["policy"]["revoked"])
            <= set(
                state["artifacts"]
                .get(n, {})
                .get("config", {})
                .get("pki", {})
                .get("blocklist", [])
            )
            or state["artifacts"].get(n, {}).get("authorization", {}).get("krl")
            != state["security"]["krl"]
            for n in effective
            if n in current
        ):
            fleet_scope = True
        if kind == "compromise":
            fleet_scope = True
        recipients = (
            set(effective)
            if fleet_scope
            else {c["name"] for c in changes if c["action"] != "remove"}
        )
        retired = {n for n in current if n not in effective and n not in disabled}
        recipients |= retired
        if previous and previous["phase"] != "complete" and kind == "compromise":
            recipients |= set(previous["recipients"]) - set(disabled)
        operation = {
            "format": 1,
            "id": str(uuid.uuid4()),
            "kind": kind,
            "name": name,
            "phase": "prepared",
            "prepared_at": stamp(),
            "source": source,
            "map_hash": digest(encode(source)),
            "base_state": state_hash(state),
            "scope": "fleet" if fleet_scope else "node-only",
            "changes": changes,
            "recipients": sorted(recipients),
            "retired": sorted(retired),
            "artifacts": {},
            "results": {},
            "composition": {},
            "disruption": "Changed Nebula services restart; composed updates close dedicated management sessions",
            "remote_changes": False,
            "healthy_keys_rotated": 0,
            "issuer_keys_changed": 0,
        }
        save_operation(store, operation)
        return summary(operation, state)


def canonical(bundle):
    value = copy.deepcopy(bundle)
    value.pop("anchor", None)
    value.pop("replacement", None)
    for part in (
        value,
        value.get("directory", {}),
        value.get("policy", {}),
        value.get("authorization", {}),
    ):
        part.pop("revision", None)
    for n, peer in value.get("directory", {}).get("peers", {}).items():
        if n != value["name"]:
            for field in ("certificate", "public_key", "not_after"):
                peer.pop(field, None)
            if peer["role"] == "provider-manager":
                peer["role"] = "provider"
    return digest(encode(value))


def materialize(store, operation, state, signer):
    source = operation["source"]
    effective = {
        n: p
        for n, p in source["peers"].items()
        if n not in state["security"]["disabled"]
        or (operation["kind"] == "replace" and n == operation["name"])
    }
    if operation["phase"] == "prepared":
        if state["security"].get("pending_operation") != operation["id"]:
            state["policy"]["revision"] += 1
            state["security"]["pending_operation"] = operation["id"]
        operation["sequence"] = state["policy"]["revision"]
        state["security"]["lifetimes"] = source.get(
            "lifetimes", {"leaf_days": 180, "renew_days": 30, "issuer_days": 365}
        )
        state["policy"].update(
            network=source["network"],
            lighthouses={
                n: {"address": p["address"], "endpoint": p["endpoint"]}
                for n, p in effective.items()
                if p["role"] == "lighthouse"
            },
            routers={
                n: {"prefix": p["routed_prefix"], "via": p["address"]}
                for n, p in effective.items()
                if "routed_prefix" in p
            },
        )
        for change in operation["changes"]:
            if change["action"] == "remove" or change.get("retire"):
                credentials.retire(state, change["name"])
                if change["action"] == "remove":
                    state["security"]["disabled"][change["name"]] = {
                        "reason": "removed",
                        "time": stamp(),
                    }
        operation["phase"] = "materializing"
        authority.save(store, state)
        save_operation(store, operation)
    for change in operation["changes"]:
        if change["action"] == "remove":
            continue
        n, peer = change["name"], effective[change["name"]]
        old = state["issued"].get(n)
        if old and old["operation"] == operation["id"]:
            continue
        if signer is None:
            raise ValueError("Signing is required for pending credential issuance")
        request = {
            "operation": operation["id"],
            "network_key": old["key_path"]
            if old and change["action"] != "replace"
            else None,
            "management_key": old["management_path"]
            if old
            and change["action"] != "replace"
            and old["management_key"] not in state["security"]["revoked_keys"]
            else None,
            "manager": "manager" in policy.capabilities(peer["role"]),
        }
        prepared = decode(transport.prepare(peer, request))
        member = credentials.sign(
            store,
            state,
            n,
            peer,
            prepared,
            signer,
            operation["id"],
            source.get("lifetimes", {}).get("leaf_days", 180),
        )
        if operation["kind"] == "replace" and n == operation["name"]:
            state["security"]["disabled"].pop(n, None)
            authority.save(store, state)
        operation["last_issued"] = member["fingerprint"]
        save_operation(store, operation)
    for n, peer in effective.items():
        state["issued"][n].update(
            target=peer["target"], ssh_config=peer.get("ssh_config")
        )
    anchor = {
        "sequence": state["policy"]["revision"],
        "issued": len(state["history"]),
        "history": digest(encode(state["history"])),
    }
    for n in operation["recipients"]:
        if n in operation["retired"]:
            operation["artifacts"][n] = {
                "disabled": True,
                "anchor": anchor,
                "revision": state["artifacts"].get(n, {}).get("revision", 0) + 1,
            }
            state["artifacts"][n] = operation["artifacts"][n]
            continue
        candidate = authority.bundle(state, (store / "ca.crt").read_text(), n)
        candidate.update(
            format=2,
            replacement=any(
                c["name"] == n and c["action"] == "replace"
                for c in operation["changes"]
            ),
            anchor=anchor,
        )
        old = state["artifacts"].get(n)
        if old and canonical(old) == canonical(candidate):
            candidate = old
        else:
            revision = old["revision"] + 1 if old else 1
            for part in (
                candidate,
                candidate["directory"],
                candidate["policy"],
                candidate["authorization"],
            ):
                part["revision"] = revision
            state["artifacts"][n] = candidate
        operation["artifacts"][n] = candidate
    authority.save(store, state)
    operation["phase"] = "applying"
    save_operation(store, operation)


def complete_composition(store, operation, state, check_only=False):
    from . import koi_security

    payload = {
        "store": str(store),
        "operation": operation["id"],
        "mode": "check" if check_only else "apply",
        "recipients": operation["recipients"],
        "peers": {
            n: p
            for n, p in operation["source"]["peers"].items()
            if n not in state["security"]["disabled"]
        },
        "results": operation["results"],
        "revocations": state["security"]["revoked_keys"],
        "generations": {n: m["key_path"] for n, m in state["issued"].items()},
    }
    response = koi_security.complete(payload)
    operation["composition"] = response["hosts"]
    operation.pop("completion_error", None)
    for n in operation["recipients"]:
        row = operation["results"].setdefault(n, {})
        row["composition_pending"] = not response["hosts"].get(n, {}).get(
            "verified", False
        ) or not composition_verified(row.get("evidence", {}))
        row["verified"] = (
            row.get("transport_verified", False)
            and composition_verified(row.get("evidence", {}))
            and not row["composition_pending"]
        )


def apply(store, *, password_file=None, yes=False):
    with locked(store):
        operation = read(store / "operation.json")
        if digest(encode(read(store / "map.json"))) != operation["map_hash"]:
            raise ValueError("Desired map changed; prepare an updated plan")
        state = authority.load(store) if (store / "fleet.json").exists() else None
        if (
            operation["phase"] == "prepared"
            and state_hash(state) != operation["base_state"]
            and (state or {}).get("security", {}).get("pending_operation")
            != operation["id"]
        ):
            raise ValueError("Authority changed; the saved plan is stale")
        if state and operation["phase"] != "prepared":
            if state["security"].get("pending_operation") != operation["id"]:
                raise ValueError(
                    "Saved operation has been superseded by newer authority"
                )
            for n, artifact in operation["artifacts"].items():
                if artifact.get("disabled"):
                    continue
                if n in state["security"]["disabled"] or not set(
                    state["policy"]["revoked"]
                ) <= set(artifact["config"]["pki"]["blocklist"]):
                    raise ValueError("Saved operation would restore retired authority")
        if not yes:
            print(json.dumps(summary(operation, state)), file=__import__("sys").stderr)
            if input("Apply this security update? Type apply: ") != "apply":
                return {
                    "ok": False,
                    "phase": operation["phase"],
                    "intent_retained": True,
                }
        signer = None
        try:
            issuing = state is None or any(
                c["action"] != "remove"
                and (state["issued"].get(c["name"]) or {}).get("operation")
                != operation["id"]
                for c in operation["changes"]
            )
            if issuing:
                secret = session.password(password_file, confirm=state is None)
                signer = session.Signer(
                    session.unseal(store, secret)
                    if (store / "authority.keys").exists()
                    else {}
                )
                if state is None:
                    authority.initialize(
                        store,
                        operation["source"]["network"],
                        {
                            n: p["endpoint"]
                            for n, p in operation["source"]["peers"].items()
                            if p["role"] == "lighthouse"
                        },
                        signer,
                        operation["source"]
                        .get("lifetimes", {})
                        .get("issuer_days", 365),
                        secret=secret,
                    )
                    state = authority.load(store)
                    state["security"]["lifetimes"] = operation["source"].get(
                        "lifetimes",
                        {"leaf_days": 180, "renew_days": 30, "issuer_days": 365},
                    )
                    state["security"]["pending_operation"] = operation["id"]
                    authority.save(store, state)
                    operation["base_state"] = state_hash(state)
                    save_operation(store, operation)
                secret = None
            if operation["phase"] in ("prepared", "materializing"):
                materialize(store, operation, state, signer)
        finally:
            if signer:
                signer.keys.clear()
        for n, peer in operation["source"]["peers"].items():
            if n in state["issued"]:
                state["issued"][n].update(
                    target=peer["target"], ssh_config=peer.get("ssh_config")
                )
        authority.save(store, state)
        for n in operation["recipients"]:
            expected = operation["artifacts"][n]
            member = state["issued"][n]
            old = operation["results"].get(n, {})
            try:
                if old.get("transport_verified") and composition_verified(
                    old.get("evidence", {})
                ):
                    evidence = decode(transport.inspect(member, expected))
                    if not composition_verified(evidence):
                        evidence = decode(transport.deliver(member, expected))
                else:
                    evidence = decode(transport.deliver(member, expected))
                if not all(
                    evidence.get(k) is True
                    for k in (
                        "installed",
                        "activated",
                        "checked",
                        "old_connections_handled",
                    )
                ):
                    raise ValueError(
                        "Required activation/session evidence is incomplete"
                    )
                operation["results"][n] = {
                    "verified": composition_verified(evidence),
                    "transport_verified": True,
                    "composition_pending": not composition_verified(evidence),
                    "time": stamp(),
                    "artifact": digest(encode(expected)),
                    "evidence": evidence,
                }
            except Exception as error:
                operation["results"][n] = {
                    "verified": False,
                    "transport_verified": False,
                    "time": stamp(),
                    "error": diagnostic(error),
                }
            save_operation(store, operation)
        try:
            complete_composition(store, operation, state)
        except Exception as error:
            operation["completion_error"] = diagnostic(error)
        good = (
            all(
                operation["results"].get(n, {}).get("verified")
                for n in operation["recipients"]
            )
            and "completion_error" not in operation
        )
        operation["phase"] = "complete" if good else "partial"
        save_operation(store, operation)
        return summary(operation, state)


def summary(operation, state):
    return {
        "ok": operation["phase"] == "complete",
        "operation": operation["id"],
        "kind": operation["kind"],
        "phase": operation["phase"],
        "scope": operation["scope"],
        "changes": operation["changes"],
        "required": operation["recipients"],
        "hosts": operation["results"],
        "composition": operation["composition"],
        "maintenance_amendments": operation.get("maintenance_amendments", []),
        "untrusted": state["security"]["disabled"] if state else {},
        "disruption": operation["disruption"],
        "healthy_keys_rotated": 0,
        "issuer_keys_changed": 0,
        "recovery": "separate trusted replacement"
        if operation["kind"] == "compromise"
        else None,
        "completion_error": operation.get("completion_error"),
    }


def status(store, *, check=False):
    with locked(store):
        state = authority.load(store) if (store / "fleet.json").exists() else None
        operation = (
            read(store / "operation.json")
            if (store / "operation.json").exists()
            else None
        )
        if check and operation and state and operation["artifacts"]:
            for n in operation["recipients"]:
                try:
                    evidence = decode(
                        transport.inspect(state["issued"][n], operation["artifacts"][n])
                    )
                    operation["results"][n] = {
                        "verified": all(
                            evidence.get(k) is True
                            for k in (
                                "installed",
                                "activated",
                                "checked",
                                "old_connections_handled",
                            )
                        )
                        and composition_verified(evidence),
                        "transport_verified": all(
                            evidence.get(k) is True
                            for k in (
                                "installed",
                                "activated",
                                "checked",
                                "old_connections_handled",
                            )
                        ),
                        "time": stamp(),
                        "composition_pending": not composition_verified(evidence),
                        "evidence": evidence,
                    }
                except Exception as error:
                    operation["results"][n] = {
                        "verified": False,
                        "time": stamp(),
                        "error": diagnostic(error),
                    }
            try:
                complete_composition(store, operation, state, check_only=True)
            except Exception as error:
                operation["completion_error"] = diagnostic(error)
            operation["phase"] = (
                "complete"
                if all(
                    operation["results"].get(n, {}).get("verified")
                    for n in operation["recipients"]
                )
                and "completion_error" not in operation
                else "partial"
            )
            save_operation(store, operation)
        fleet_observations = {}
        if check and state:
            for n, expected in state["artifacts"].items():
                if (
                    state["security"]["disabled"].get(n, {}).get("reason")
                    == "suspected compromise"
                ):
                    continue
                if operation and n in operation["results"]:
                    fleet_observations[n] = operation["results"][n]
                    continue
                try:
                    evidence = decode(transport.inspect(state["issued"][n], expected))
                    fleet_observations[n] = {
                        "verified": all(
                            evidence.get(k) is True
                            for k in (
                                "installed",
                                "activated",
                                "checked",
                                "old_connections_handled",
                            )
                        )
                        and composition_verified(evidence),
                        "time": stamp(),
                        "evidence": evidence,
                    }
                except Exception as error:
                    fleet_observations[n] = {
                        "verified": False,
                        "time": stamp(),
                        "error": diagnostic(error),
                    }
        deadlines = (
            None
            if state is None
            else {
                "issuer": state["security"]["issuer_retire_after"],
                "nodes": {
                    n: {
                        "expires": m["identity"]["details"]["notAfter"],
                        "due": credentials.date(m["identity"]["details"]["notAfter"])
                        <= credentials.now()
                        + timedelta(days=state["security"]["lifetimes"]["renew_days"]),
                    }
                    for n, m in state["issued"].items()
                },
                "issuer_due": credentials.date(state["security"]["issuer_retire_after"])
                <= credentials.now()
                + timedelta(days=state["security"]["lifetimes"]["renew_days"]),
            }
        )
        result = (
            summary(operation, state)
            if operation
            else {"ok": False, "phase": "not planned"}
        )
        result.update(
            deadlines=deadlines,
            fleet_observations=fleet_observations,
            observation="current check" if check else "last observed",
            history_coverage="recorded issuance only; unseen post-backup issuance cannot be ruled out",
        )
        if check and any(not row["verified"] for row in fleet_observations.values()):
            result["ok"] = False
        return result
