"""Ordinary caller-configured SSH. This is a tool, not mesh discovery or gossip."""

import shlex
from .common import run

STATE = "/var/lib/nebula"


def ssh(target, arguments, data=None, config=None):
    return command(target, shlex.join(["river", *arguments]), data, config)


def validate_target(target):
    if not target or target.startswith("-") or any(c in target for c in "\n\r\x00"):
        raise ValueError("Invalid administration target")


def command(target, remote, data=None, config=None):
    validate_target(target)
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ForwardAgent=no",
    ]
    if config:
        command += ["-F", config]
    return run(
        *command,
        "--",
        target,
        remote,
        input=data,
        timeout=60,
    )


def prepare(peer, request):
    from .common import encode

    if peer["role"] != "lighthouse":
        return ssh(peer["target"], ["prepare"], encode(request), peer.get("ssh_config"))
    script = """import json, pathlib, subprocess, sys, uuid, os
request=json.load(sys.stdin)
if request["manager"]: raise ValueError("Native lighthouse has no manager identity")
base=pathlib.Path("/var/lib/nebula")
directory=base/"keys"/str(uuid.UUID(request["operation"]))
directory.mkdir(parents=True,mode=0o700,exist_ok=True)
key=pathlib.Path(request["network_key"]) if request["network_key"] else directory/"network.key"
if not key.is_relative_to(base/"keys"): raise ValueError("Wrong key store")
public=key.with_suffix(".pub")
if not key.exists() and not public.exists():
 subprocess.run(["nebula-cert","keygen","-out-key",str(key),"-out-pub",str(public)],check=True)
 key.chmod(0o600)
if not key.exists() or not public.exists(): raise ValueError("Incomplete prepared identity")
print(json.dumps(dict(network_path=str(key),network_public=public.read_text().strip(),management_path=None,management_public=None)))
"""
    return command(
        peer["target"],
        "python3 -c " + shlex.quote(script),
        encode(request),
        peer.get("ssh_config"),
    )


def native_update(member, bundle, *, check_only=False):
    from .common import encode

    script = """import hashlib, json, os, pathlib, subprocess, sys, tempfile, time
bundle=json.load(sys.stdin)
base=pathlib.Path("/var/lib/nebula"); config=base/"config.json"
check_only=CHECK_ONLY
run=lambda *args: subprocess.check_output(args,stderr=subprocess.PIPE).decode().strip()
def record(value):
 fd,temp=tempfile.mkstemp(dir=base); os.fchmod(fd,0o600)
 with os.fdopen(fd,"w") as f: json.dump(value,f); f.flush(); os.fsync(f.fileno())
 os.replace(temp,base/"delivery.json")
 directory=os.open(base,os.O_DIRECTORY)
 try: os.fsync(directory)
 finally: os.close(directory)
disabled=bundle.get("disabled",False)
expected=(json.dumps(bundle if disabled else bundle["config"],sort_keys=True,separators=(",",":"))+"\\n").encode()
digest=hashlib.sha256(expected).hexdigest()
receipt=json.loads((base/"delivery.json").read_text()) if (base/"delivery.json").exists() else None
if receipt:
 if receipt.get("format")!=2: raise ValueError("Unsupported native delivery receipt; explicit authority transition required")
 old=receipt["anchor"]
 if old["sequence"]>bundle["anchor"]["sequence"] or old["issued"]>bundle["anchor"]["issued"]: raise ValueError("Operator history is older than installed authority")
 if bundle["revision"]<receipt["revision"] or (bundle["revision"]==receipt["revision"] and (digest!=receipt["digest"] or disabled!=receipt["disabled"])): raise ValueError("Stale or conflicting accepted native revision")
 if receipt["disabled"] and not disabled and bundle.get("replacement") is not True: raise ValueError("Retired native authority requires explicit operator replacement")
accepted=dict(format=2,anchor=bundle["anchor"],revision=bundle["revision"],disabled=disabled,digest=digest,invocation=None)
if disabled:
 if not check_only:
  record(accepted)
  config.unlink(missing_ok=True)
  subprocess.run(["systemctl","stop","nebula.service"],check=True)
  receipt=accepted
 if not receipt or receipt["digest"]!=digest or not receipt["disabled"] or subprocess.run(["systemctl","is-active","--quiet","nebula.service"]).returncode==0 or config.exists(): raise ValueError("Native retirement not installed/activated")
 print(json.dumps(dict(installed=True,activated=True,checked=True,old_connections_handled=True,retired=True,anchor=receipt["anchor"]))); sys.exit()
if not check_only:
 fd,temp=tempfile.mkstemp(dir=base); os.fchmod(fd,0o600)
 with os.fdopen(fd,"wb") as f: f.write(expected); f.flush(); os.fsync(f.fileno())
 subprocess.run(["nebula","-test","-config",temp],check=True,stdout=sys.stderr)
 record(accepted)
 os.replace(temp,config)
 subprocess.run(["systemctl","restart","nebula.service"],check=True)
 for _ in range(50):
  if subprocess.run(["systemctl","is-active","--quiet","nebula.service"],stdout=subprocess.DEVNULL).returncode==0 and subprocess.run(["ip","link","show","river"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0: break
  time.sleep(.1)
 accepted["invocation"]=run("systemctl","show","nebula.service","-p","InvocationID","--value")
 record(accepted)
if subprocess.run(["ip","link","show","river"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode: raise ValueError("Native tunnel interface absent")
if config.read_bytes()!=expected: raise ValueError("Native configuration readback mismatch")
subprocess.run(["nebula","-test","-config",str(config)],check=True,stdout=sys.stderr)
receipt=json.loads((base/"delivery.json").read_text())
if receipt["revision"]!=bundle["revision"] or receipt["anchor"]!=bundle["anchor"] or receipt["digest"]!=digest or receipt["disabled"]: raise ValueError("Native accepted artifacts differ from prepared operation")
if receipt["anchor"]["sequence"]>bundle["anchor"]["sequence"] or receipt["anchor"]["issued"]>bundle["anchor"]["issued"]: raise ValueError("Operator history is older than installed authority")
instance=run("systemctl","show","nebula.service","-p","InvocationID","--value")
pid=run("systemctl","show","nebula.service","-p","MainPID","--value")
if not instance or instance!=receipt["invocation"] or subprocess.run(["systemctl","is-active","--quiet","nebula.service"]).returncode: raise ValueError("Native service activation differs")
if str(config).encode() not in (pathlib.Path("/proc")/pid/"cmdline").read_bytes().split(b"\\0"): raise ValueError("Native process uses a different configuration")
print(json.dumps(dict(installed=True,activated=True,checked=True,old_connections_handled=True,pid=pid,invocation_id=instance,anchor=receipt["anchor"],revocation_check=dict(nebula_fingerprints=bundle["config"]["pki"]["blocklist"]))))
""".replace("CHECK_ONLY", repr(check_only))
    return command(
        member["target"],
        "python3 -c " + shlex.quote(script),
        encode(bundle),
        member.get("ssh_config"),
    )


def deliver(member, bundle):
    from .common import encode, decode

    if member["native"]:
        return native_update(member, bundle)
    command_name = "disable" if bundle.get("disabled") else "install"
    response = decode(
        ssh(member["target"], [command_name], encode(bundle), member["ssh_config"])
    )
    return encode(response["evidence"])


def inspect(member, bundle):
    from .common import encode

    if member["native"]:
        return native_update(member, bundle, check_only=True)
    return ssh(member["target"], ["check"], encode(bundle), member["ssh_config"])
