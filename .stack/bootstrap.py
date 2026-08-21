#!/usr/bin/env python3
"""Fail-closed shared composition bootstrap.

Reviewed installs are offline and wheel-only. The caller supplies an independently
authenticated hash-locked requirements file and local wheelhouse. Every run builds
a fresh private environment; existing ignored environments are never executed.
Receipts are advisory install evidence only, never promotion/completion authority.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, secrets, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

SCRIPT = Path(__file__).absolute()
ROOT = SCRIPT.parent
RUNTIME = ROOT / "runtime"
STAGING = RUNTIME / "staging"
RUNS = RUNTIME / "runs"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LOCK_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)==(?P<version>[^\\s;]+) --hash=sha256:(?P<sha>[0-9a-f]{64})$")
ROOTS = {
    "base": ("httpx","pydantic","python-dotenv","pytest","pytest-asyncio","hypothesis"),
    "mirofish": ("httpx","pydantic","python-dotenv","pytest","pytest-asyncio","hypothesis",
                 "flask","flask-cors","openai","zep-cloud","camel-oasis","camel-ai",
                 "pymupdf","charset-normalizer","chardet"),
}
SOURCES = {
    "mirofish":"https://github.com/666ghj/MiroFish",
    "oasis":"https://github.com/camel-ai/oasis",
    "camel":"https://github.com/camel-ai/camel",
}

class Refused(RuntimeError): pass

def h(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def norm(name: str) -> str: return re.sub(r"[-_.]+","-",name).lower()

def read_regular(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os,"O_NOFOLLOW"):
        raise Refused("reviewed install requires POSIX O_NOFOLLOW semantics")
    fd=os.open(path, os.O_RDONLY|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0))
    try:
        a=os.fstat(fd)
        if not stat.S_ISREG(a.st_mode): raise Refused(f"not a regular file: {path}")
        chunks=[]
        while True:
            b=os.read(fd,1024*1024)
            if not b: break
            chunks.append(b)
        z=os.fstat(fd)
        if (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):
            raise Refused(f"file changed while read: {path}")
        data=b"".join(chunks)
        if len(data)!=a.st_size: raise Refused(f"short read: {path}")
        return data
    finally: os.close(fd)

def private_dir(path: Path) -> None:
    try: os.mkdir(path,0o700)
    except FileExistsError:
        s=os.lstat(path)
        if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode): raise Refused(f"unsafe directory: {path}")
        if s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)&0o077: raise Refused(f"directory not private/current-user-owned: {path}")

def safe_root() -> None:
    if SCRIPT.is_symlink() or ROOT.is_symlink() or ROOT.resolve()!=ROOT: raise Refused("symlinked .stack path")
    s=os.lstat(ROOT)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid(): raise Refused("unowned/non-directory .stack root")

def parse_lock(data: bytes) -> dict[str,dict[str,str]]:
    try: lines=data.decode("utf-8").splitlines()
    except UnicodeDecodeError as e: raise Refused("lock must be UTF-8") from e
    out={}
    for n,line in enumerate(lines,1):
        if not line: continue
        if line.strip()!=line or "\r" in line: raise Refused(f"noncanonical lock line {n}")
        m=LOCK_RE.fullmatch(line)
        if not m: raise Refused(f"lock line {n} must be NAME==VERSION --hash=sha256:<64 lowercase hex>")
        name=norm(m["name"])
        if name in out: raise Refused(f"duplicate lock package: {name}")
        out[name]={"version":m["version"],"sha256":m["sha"]}
    if not out: raise Refused("empty lock")
    return out

def validate_roots(profile: str, lock: dict[str,dict[str,str]]) -> None:
    missing=[x for x in ROOTS[profile] if norm(x) not in lock]
    if missing: raise Refused("lock missing profile roots: "+", ".join(missing))

def write_new(path: Path, data: bytes, mode=0o600) -> None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0),mode)
    try:
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0: raise Refused(f"short write: {path}")
            view=view[n:]
        os.fsync(fd)
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=len(data): raise Refused(f"unsafe output: {path}")
    finally: os.close(fd)

def snapshot_wheels(source: Path, dest: Path, lock: dict[str,dict[str,str]]) -> list[dict[str,object]]:
    s=os.lstat(source)
    if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode): raise Refused("wheelhouse must be a real directory")
    os.mkdir(dest,0o700)
    inv=[]
    for src in sorted(source.iterdir(),key=lambda x:x.name):
        st=os.lstat(src)
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or not src.name.endswith(".whl"):
            raise Refused(f"wheelhouse may contain only regular .whl files: {src.name}")
        data=read_regular(src); digest=h(data)
        write_new(dest/src.name,data,0o400)
        inv.append({"name":src.name,"sha256":digest,"size":len(data)})
    if not inv: raise Refused("empty wheelhouse")
    hashes={x["sha256"] for x in inv}
    missing=[name for name,m in lock.items() if m["sha256"] not in hashes]
    if missing: raise Refused("wheelhouse missing lock hashes for: "+", ".join(sorted(missing)))
    return inv

def pip_env(venv_bin: Path) -> dict[str,str]:
    env={"PATH":str(venv_bin)+os.pathsep+os.defpath,"PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1",
         "PIP_CONFIG_FILE":os.devnull,"PIP_DISABLE_PIP_VERSION_CHECK":"1","PIP_NO_INPUT":"1",
         "PIP_NO_INDEX":"1","PIP_ONLY_BINARY":":all:","PIP_REQUIRE_HASHES":"1"}
    for k in ("SYSTEMROOT","WINDIR","COMSPEC","PATHEXT","TEMP","TMP","TMPDIR"):
        if os.environ.get(k): env[k]=os.environ[k]
    return env

def interpreter_identity() -> tuple[Path,str]:
    p=Path(sys.executable).resolve(strict=True)
    return p,h(read_regular(p))

def verify_report(report: Path, lock: dict[str,dict[str,str]], inv: list[dict[str,object]]) -> list[dict[str,str]]:
    obj=json.loads(read_regular(report))
    installs=obj.get("install")
    if not isinstance(installs,list): raise Refused("pip report missing install list")
    wh={str(x["sha256"]) for x in inv}; seen={}; result=[]
    for item in installs:
        meta=item.get("metadata",{}); dl=item.get("download_info",{}); ai=dl.get("archive_info",{})
        name=norm(str(meta.get("name",""))); version=str(meta.get("version",""))
        hashes=ai.get("hashes",{}) if isinstance(ai,dict) else {}
        digest=str(hashes.get("sha256","")).lower() if isinstance(hashes,dict) else ""
        if not name or name in seen or name not in lock: raise Refused(f"unexpected/duplicate installed package: {name}")
        if version!=lock[name]["version"] or digest!=lock[name]["sha256"] or digest not in wh:
            raise Refused(f"installed artifact does not match lock/wheel snapshot: {name}")
        seen[name]=1; result.append({"name":name,"version":version,"sha256":digest})
    if set(seen)!=set(lock): raise Refused("pip report package set differs from lock")
    return sorted(result,key=lambda x:x["name"])

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--profile",choices=sorted(ROOTS),default="base")
    ap.add_argument("--dry-run",action="store_true")
    ap.add_argument("--lock",type=Path)
    ap.add_argument("--lock-sha256")
    ap.add_argument("--wheelhouse",type=Path)
    a=ap.parse_args()
    if a.dry_run:
        print(json.dumps({"schema":"amazingbecca-shared-composition-stack-v2-plan","profile":a.profile,
          "profile_roots":list(ROOTS[a.profile]),"install":"offline-wheelhouse-only",
          "authority":"advisory-install-evidence-only","promotion_authorized":False,"completion_authorized":False},indent=2,sort_keys=True))
        return 0
    if a.profile=="mirofish" and sys.version_info[:2]!=(3,11):
        raise SystemExit(f"mirofish profile requires CPython 3.11; current interpreter is {sys.version.split()[0]}")
    if not a.lock or not a.wheelhouse or not a.lock_sha256: raise SystemExit("install requires --lock --lock-sha256 --wheelhouse")
    expected=a.lock_sha256.lower()
    if not HEX64.fullmatch(expected): raise SystemExit("--lock-sha256 must be 64 lowercase hex")
    safe_root()
    lock_bytes=read_regular(a.lock)
    if h(lock_bytes)!=expected: raise Refused("lock SHA-256 mismatch")
    lock=parse_lock(lock_bytes); validate_roots(a.profile,lock)
    interp,interp_hash=interpreter_identity(); bootstrap_hash=h(read_regular(SCRIPT))
    for d in (RUNTIME,STAGING,RUNS): private_dir(d)
    profile_dir=RUNS/a.profile; private_dir(profile_dir)
    rid=secrets.token_hex(16)
    stage=Path(tempfile.mkdtemp(prefix=f"{a.profile}-{rid}-",dir=STAGING)); os.chmod(stage,0o700)
    final=profile_dir/rid
    try:
        write_new(stage/"lock.txt",lock_bytes,0o400)
        wheel_dir=stage/"wheelhouse"; inv=snapshot_wheels(a.wheelhouse,wheel_dir,lock)
        env_dir=stage/"venv"; env=pip_env(env_dir/"bin")
        subprocess.run([str(interp),"-I","-m","venv","--copies",str(env_dir)],check=True,cwd=stage,env=env)
        py=env_dir/"bin"/"python"
        if not py.is_file() or py.is_symlink(): raise Refused("fresh venv interpreter missing or symlinked")
        report=stage/"pip-report.json"
        subprocess.run([str(py),"-I","-m","pip","install","--isolated","--disable-pip-version-check",
          "--no-input","--no-index","--only-binary=:all:","--require-hashes","--find-links",str(wheel_dir),
          "--report",str(report),"-r",str(stage/"lock.txt")],check=True,cwd=stage,env=env)
        installed=verify_report(report,lock,inv)
        receipt={"schema":"amazingbecca-shared-composition-stack-v2","authority":"advisory-install-evidence-only",
          "profile":a.profile,"profile_roots":list(ROOTS[a.profile]),"python":sys.version.split()[0],
          "interpreter":str(interp),"interpreter_sha256":interp_hash,"bootstrap_sha256":bootstrap_hash,
          "lock_sha256":expected,"wheelhouse":inv,"installed":installed,"pip_report_sha256":h(read_regular(report)),
          "network_install":False,"source_distribution_builds":False,"reused_environment":False,
          "sources":SOURCES,"promotion_authorized":False,"completion_authorized":False}
        receipt["receipt_sha256"]=h(json.dumps(receipt,sort_keys=True,separators=(",",":")).encode())
        write_new(stage/"receipt.json",(json.dumps(receipt,indent=2,sort_keys=True)+"\n").encode())
        os.rename(stage,final)
        dfd=os.open(profile_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except Exception:
        if stage.exists() and stage.is_dir() and not stage.is_symlink(): shutil.rmtree(stage)
        raise
    print(final/"receipt.json")
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except Refused as e: raise SystemExit(f"bootstrap refused: {e}") from e
