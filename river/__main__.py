"""Operator intentions, retained plans and native node delivery."""

import argparse
import os
from pathlib import Path
import resource
import sys

from . import authority, desired, facts, node
from .common import (
    LIMIT,
    NODE_STORE,
    decode,
    diagnostic,
    encode,
    locked,
    private_directory,
    read,
)


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(prog="river", description=__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version="river " + Path(__file__).with_name("VERSION").read_text().strip(),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    local = {
        "prepare",
        "install",
        "validate",
        "check",
        "disable",
        "node-status",
        "reconcile",
        "koi",
        "peers",
        "authorization",
    }
    for command in (
        "init",
        "plan",
        "renew",
        "compromise",
        "replace",
        "apply",
        "status",
        "show",
        "directory",
        "bundle",
        "backup",
        *sorted(local),
    ):
        sub = commands.add_parser(command)
        sub.add_argument(
            "--store",
            type=Path,
            default=NODE_STORE if command in local else None,
            required=command not in local,
        )
        if command in ("compromise", "replace", "bundle"):
            sub.add_argument("name")
        if command == "koi":
            sub.add_argument(
                "action",
                choices=[
                    "manage",
                    "export-dns",
                    "server-key",
                    "project",
                    "check-targets",
                    "withdraw",
                ],
            )
        if command == "replace":
            sub.add_argument("--target", required=True)
        if command == "renew":
            sub.add_argument("--due", action="store_true", required=True)
        if command == "apply":
            sub.add_argument(
                "--yes",
                action="store_true",
                help="Apply the reviewed plan without an interactive confirmation",
            )
            sub.add_argument("--password-file", type=Path)
        if command == "status":
            sub.add_argument("--check", action="store_true")
        if command == "backup":
            sub.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command in ("plan", "renew", "compromise", "replace", "apply", "status"):
        from . import lifecycle

    store = private_directory(args.store.resolve())
    if args.command == "koi":
        from . import koi, koi_security

        if os.geteuid() != 0 or store != NODE_STORE:
            raise ValueError(
                "Run River Koi operations as the installed node administrator"
            )
        if args.action in ("manage", "export-dns"):
            getattr(koi, args.action.replace("-", "_"))()
            return
        with locked(store):
            if args.action == "withdraw":
                koi_security.withdraw()
                result = {"withdrawn": True, "state_retained": True}
            elif args.action == "server-key":
                result = {
                    "server_key": koi.management_key("server")
                    .with_suffix(".key.pub")
                    .read_text()
                    .strip()
                }
            else:
                result = koi_security.project(
                    decode(sys.stdin.buffer.read(LIMIT + 1)),
                    check=args.action == "check-targets",
                )
    elif args.command in ("plan", "renew", "compromise", "replace"):
        result = lifecycle.prepare(
            store,
            {"plan": "map", "renew": "renew"}.get(args.command, args.command),
            getattr(args, "name", None),
            getattr(args, "target", None),
        )
    elif args.command == "apply":
        result = lifecycle.apply(store, password_file=args.password_file, yes=args.yes)
    elif args.command == "status":
        result = lifecycle.status(store, check=args.check)
    else:
        with locked(store):
            if args.command == "init":
                result = desired.initialize(store)
            elif args.command == "backup":
                result = authority.backup(store, args.out)
            elif args.command == "show":
                result = authority.show(store)
            elif args.command == "directory":
                result = facts.directory(authority.load(store))
            elif args.command == "bundle":
                state = authority.load(store)
                if args.name in state["security"]["disabled"]:
                    raise ValueError("Cannot export authority for a disabled node")
                result = state["artifacts"][args.name]
            elif args.command == "prepare":
                result = node.prepare(store, decode(sys.stdin.buffer.read(LIMIT + 1)))
            elif args.command == "reconcile":
                result = node.install(store, read(store / "desired.json"))
                completion = result["evidence"].get("composition", {})
                if completion.get("verified") is False:
                    raise ValueError(
                        "Composition reconciliation failed: "
                        + completion.get("error", "completion did not verify")
                    )
            elif args.command == "peers":
                result = node.peers(store)
            elif args.command == "authorization":
                result = node.authorization(store)
            elif args.command in ("install", "validate", "check", "disable"):
                bundle = decode(sys.stdin.buffer.read(LIMIT + 1))
                if args.command == "check":
                    result = node.check(store, bundle)
                elif args.command == "disable":
                    result = {"evidence": node.disable(store, bundle)}
                else:
                    result = node.install(
                        store, bundle, validate_only=args.command == "validate"
                    )
            else:
                result = node.status(store)
    print(encode(result).decode(), end="")
    if args.command in ("apply", "status") and result.get("ok") is False:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("river: " + diagnostic(error), file=sys.stderr)
        sys.exit(1)
