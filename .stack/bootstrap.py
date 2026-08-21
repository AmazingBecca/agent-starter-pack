#!/usr/bin/env python3
"""Fail-closed shared composition bootstrap.

Reviewed installs are offline, wheel-only, exact-hash locked, and dependency traversal
is disabled. The caller supplies an independently authenticated lock and local
wheelhouse. A fresh private environment is built for every run. Receipts are
advisory install evidence only, never promotion/completion authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).absolute()
ROOT = SCRIPT.parent
RUNTIME = ROOT / "runtime"
STAGING = RUNTIME / "staging"
RUNS = RUNTIME / "runs"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LOCK_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)==(?P<version>[^\s;]+) "
    r"--hash=sha256:(?P<sha>[0-9a-f]{64})$"
)
ROOTS = {
    "base": ("httpx", "pydantic", "python-dotenv", "pytest", "pytest-asyncio", "hypothesis"),
    "mirofish": (
        "httpx", "pydantic", "python-dotenv", "pytest", "pytest-asyncio", "hypothesis",
        "flask", "flask-cors", "openai", "zep-cloud", "camel-oasis", "camel-ai",
        "pymupdf", "charset-normalizer", "chardet",
    ),
}
SOURCES = {
    "mirofish": "https://github.com/666ghj/MiroFish",
    "oasis": "https://github.com/camel-ai/oasis",
    "camel": "https://github.com/camel-ai/camel",
}

# Runs inside the newly created, still-empty venv. It uses pip's vendored packaging
# parser before any candidate wheel is installed, so wheel dependency metadata can
# be validated without executing package code or permitting pip dependency traversal.
METADATA_VALIDATOR = r'''
import hashlib
import json
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path
from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name

wheel_dir = Path(sys.argv[1])
lock = json.loads(sys.stdin.read())
if not isinstance(lock, dict) or not lock:
    raise SystemExit("invalid lock payload")

by_digest = {}
for wheel in sorted(wheel_dir.iterdir(), key=lambda p: p.name):
    if not wheel.is_file() or wheel.is_symlink() or wheel.suffix != ".whl":
        raise SystemExit(f"unsafe wheel snapshot entry: {wheel.name}")
    data = wheel.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest in by_digest:
        raise SystemExit(f"duplicate wheel digest: {digest}")
    by_digest[digest] = wheel

metadata = {}
requirements = {}
for locked_name, item in sorted(lock.items()):
    digest = item.get("sha256")
    version = item.get("version")
    wheel = by_digest.get(digest)
    if wheel is None:
        raise SystemExit(f"wheel hash absent from snapshot: {locked_name}")
    with zipfile.ZipFile(wheel) as zf:
        members = zf.namelist()
        for member in members:
            parts = Path(member).parts
            if member.startswith(("/", "\\")) or "\\" in member or ".." in parts:
                raise SystemExit(f"unsafe wheel member path: {wheel.name}:{member}")
        metas = [m for m in members if len(Path(m).parts) == 2 and m.endswith(".dist-info/METADATA")]
        if len(metas) != 1:
            raise SystemExit(f"wheel must contain exactly one top-level METADATA: {wheel.name}")
        msg = BytesParser().parsebytes(zf.read(metas[0]))
    name = canonicalize_name(msg.get("Name", ""))
    actual_version = msg.get("Version", "")
    if name != locked_name or actual_version != version:
        raise SystemExit(
            f"wheel metadata does not match lock: {locked_name} expected {version}, "
            f"got {name or '<missing>'} {actual_version or '<missing>'}"
        )
    metadata[locked_name] = {"version": actual_version, "wheel_sha256": digest}
    requirements[locked_name] = list(msg.get_all("Requires-Dist", []))

# Every lock entry is installed explicitly, so its base requirements are active.
# Extras requested by dependency edges propagate to the target package until fixed.
active_extras = {name: {""} for name in lock}
env = default_environment()
closure = []
changed = True
while changed:
    changed = False
    closure = []
    for source in sorted(lock):
        extras = active_extras[source]
        for raw in requirements[source]:
            try:
                req = Requirement(raw)
            except Exception as exc:
                raise SystemExit(f"invalid Requires-Dist in {source}: {raw}: {exc}")
            if req.url is not None:
                raise SystemExit(f"direct URL dependency forbidden in {source}: {raw}")
            active = req.marker is None
            if req.marker is not None:
                for extra in extras:
                    marker_env = dict(env)
                    marker_env["extra"] = extra
                    if req.marker.evaluate(marker_env):
                        active = True
                        break
            if not active:
                continue
            dep = canonicalize_name(req.name)
            if dep not in lock:
                raise SystemExit(f"active dependency missing from complete lock: {source} -> {raw}")
            if req.specifier and not req.specifier.contains(lock[dep]["version"], prereleases=True):
                raise SystemExit(
                    f"locked version does not satisfy dependency: {source} -> {raw}; "
                    f"locked {dep}=={lock[dep]['version']}"
                )
            requested = {canonicalize_name(x) for x in req.extras}
            before = len(active_extras[dep])
            active_extras[dep].update(requested)
            if len(active_extras[dep]) != before:
                changed = True
            closure.append({"source": source, "requirement": str(req), "target": dep})

print(json.dumps({
    "packages": metadata,
    "dependency_edges": sorted(closure, key=lambda x: (x["source"], x["requirement"], x["target"])),
    "dependency_traversal": False,
}, sort_keys=True, separators=(",", ":")))
'''


class Refused(RuntimeError):
    pass


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_regular(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise Refused("reviewed install requires POSIX O_NOFOLLOW semantics")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        a = os.fstat(fd)
        if not stat.S_ISREG(a.st_mode):
            raise Refused(f"not a regular file: {path}")
        chunks = []
        while True:
            b = os.read(fd, 1024 * 1024)
            if not b:
                break
            chunks.append(b)
        z = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) != (
            z.st_dev, z.st_ino, z.st_size, z.st_mtime_ns, z.st_ctime_ns
        ):
            raise Refused(f"file changed while read: {path}")
        data = b"".join(chunks)
        if len(data) != a.st_size:
            raise Refused(f"short read: {path}")
        return data
    finally:
        os.close(fd)


def private_dir(path: Path) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        s = os.lstat(path)
        if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode):
            raise Refused(f"unsafe directory: {path}")
        if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) & 0o077:
            raise Refused(f"directory not private/current-user-owned: {path}")


def safe_root() -> None:
    if SCRIPT.is_symlink() or ROOT.is_symlink() or ROOT.resolve() != ROOT:
        raise Refused("symlinked .stack path")
    s = os.lstat(ROOT)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid():
        raise Refused("unowned/non-directory .stack root")


def parse_lock(data: bytes) -> dict[str, dict[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as e:
        raise Refused("lock must be UTF-8") from e
    out: dict[str, dict[str, str]] = {}
    for n, line in enumerate(lines, 1):
        if not line:
            continue
        if line.strip() != line or "\r" in line:
            raise Refused(f"noncanonical lock line {n}")
        m = LOCK_RE.fullmatch(line)
        if not m:
            raise Refused(f"lock line {n} must be NAME==VERSION --hash=sha256:<64 lowercase hex>")
        name = norm(m["name"])
        if name in out:
            raise Refused(f"duplicate lock package: {name}")
        out[name] = {"version": m["version"], "sha256": m["sha"]}
    if not out:
        raise Refused("empty lock")
    return out


def validate_roots(profile: str, lock: dict[str, dict[str, str]]) -> None:
    missing = [x for x in ROOTS[profile] if norm(x) not in lock]
    if missing:
        raise Refused("lock missing profile roots: " + ", ".join(missing))


def validate_profile_runtime(profile: str, implementation: str, version: tuple[int, int]) -> None:
    if profile == "mirofish" and (implementation != "cpython" or version != (3, 11)):
        raise Refused(
            "mirofish profile requires CPython 3.11; "
            f"current interpreter is {implementation} {version[0]}.{version[1]}"
        )


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise Refused(f"short write: {path}")
            view = view[n:]
        os.fsync(fd)
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size != len(data):
            raise Refused(f"unsafe output: {path}")
    finally:
        os.close(fd)


def snapshot_wheels(
    source: Path, dest: Path, lock: dict[str, dict[str, str]]
) -> list[dict[str, object]]:
    s = os.lstat(source)
    if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode):
        raise Refused("wheelhouse must be a real directory")
    os.mkdir(dest, 0o700)
    inv: list[dict[str, object]] = []
    for src in sorted(source.iterdir(), key=lambda x: x.name):
        st = os.lstat(src)
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or not src.name.endswith(".whl"):
            raise Refused(f"wheelhouse may contain only regular .whl files: {src.name}")
        data = read_regular(src)
        digest = h(data)
        write_new(dest / src.name, data, 0o400)
        inv.append({"name": src.name, "sha256": digest, "size": len(data)})
    if not inv:
        raise Refused("empty wheelhouse")
    hashes = {str(x["sha256"]) for x in inv}
    missing = [name for name, item in lock.items() if item["sha256"] not in hashes]
    if missing:
        raise Refused("wheelhouse missing lock hashes for: " + ", ".join(sorted(missing)))
    return inv


def pip_env(venv_bin: Path) -> dict[str, str]:
    env = {
        "PATH": str(venv_bin) + os.pathsep + os.defpath,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_NO_INDEX": "1",
        "PIP_ONLY_BINARY": ":all:",
        "PIP_REQUIRE_HASHES": "1",
    }
    for k in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def interpreter_identity() -> tuple[Path, str]:
    p = Path(sys.executable).resolve(strict=True)
    return p, h(read_regular(p))


def validate_wheel_metadata(
    py: Path, wheel_dir: Path, lock: dict[str, dict[str, str]], env: dict[str, str]
) -> dict[str, object]:
    payload = json.dumps(lock, sort_keys=True, separators=(",", ":"))
    result = subprocess.run(
        [str(py), "-I", "-c", METADATA_VALIDATOR, str(wheel_dir)],
        input=payload,
        text=True,
        capture_output=True,
        cwd=wheel_dir.parent,
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise Refused("wheel metadata closure invalid: " + (detail or f"exit {result.returncode}"))
    try:
        obj = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Refused("wheel metadata validator returned invalid JSON") from exc
    if obj.get("dependency_traversal") is not False or not isinstance(obj.get("packages"), dict):
        raise Refused("wheel metadata validator returned invalid authority state")
    return obj


def verify_report(
    report: Path, lock: dict[str, dict[str, str]], inv: list[dict[str, object]]
) -> list[dict[str, str]]:
    obj = json.loads(read_regular(report))
    installs = obj.get("install")
    if not isinstance(installs, list):
        raise Refused("pip report missing install list")
    wh = {str(x["sha256"]) for x in inv}
    seen: dict[str, int] = {}
    result: list[dict[str, str]] = []
    for item in installs:
        meta = item.get("metadata", {})
        dl = item.get("download_info", {})
        ai = dl.get("archive_info", {})
        name = norm(str(meta.get("name", "")))
        version = str(meta.get("version", ""))
        hashes = ai.get("hashes", {}) if isinstance(ai, dict) else {}
        digest = str(hashes.get("sha256", "")).lower() if isinstance(hashes, dict) else ""
        if not name or name in seen or name not in lock:
            raise Refused(f"unexpected/duplicate installed package: {name}")
        if version != lock[name]["version"] or digest != lock[name]["sha256"] or digest not in wh:
            raise Refused(f"installed artifact does not match lock/wheel snapshot: {name}")
        seen[name] = 1
        result.append({"name": name, "version": version, "sha256": digest})
    if set(seen) != set(lock):
        raise Refused("pip report package set differs from lock")
    return sorted(result, key=lambda x: x["name"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=sorted(ROOTS), default="base")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--lock", type=Path)
    ap.add_argument("--lock-sha256")
    ap.add_argument("--wheelhouse", type=Path)
    a = ap.parse_args()
    if a.dry_run:
        print(
            json.dumps(
                {
                    "schema": "amazingbecca-shared-composition-stack-v3-plan",
                    "profile": a.profile,
                    "profile_roots": list(ROOTS[a.profile]),
                    "install": "offline-wheelhouse-only-no-deps",
                    "authority": "advisory-install-evidence-only",
                    "promotion_authorized": False,
                    "completion_authorized": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    try:
        validate_profile_runtime(a.profile, sys.implementation.name, sys.version_info[:2])
    except Refused as exc:
        raise SystemExit(str(exc)) from exc
    if not a.lock or not a.wheelhouse or not a.lock_sha256:
        raise SystemExit("install requires --lock --lock-sha256 --wheelhouse")
    expected = a.lock_sha256.lower()
    if not HEX64.fullmatch(expected):
        raise SystemExit("--lock-sha256 must be 64 lowercase hex")

    safe_root()
    lock_bytes = read_regular(a.lock)
    if h(lock_bytes) != expected:
        raise Refused("lock SHA-256 mismatch")
    lock = parse_lock(lock_bytes)
    validate_roots(a.profile, lock)
    interp, interp_hash = interpreter_identity()
    bootstrap_hash = h(read_regular(SCRIPT))

    for d in (RUNTIME, STAGING, RUNS):
        private_dir(d)
    profile_dir = RUNS / a.profile
    private_dir(profile_dir)
    rid = secrets.token_hex(16)
    stage = Path(tempfile.mkdtemp(prefix=f"{a.profile}-{rid}-", dir=STAGING))
    os.chmod(stage, 0o700)
    final = profile_dir / rid
    try:
        write_new(stage / "lock.txt", lock_bytes, 0o400)
        wheel_dir = stage / "wheelhouse"
        inv = snapshot_wheels(a.wheelhouse, wheel_dir, lock)
        env_dir = stage / "venv"
        env = pip_env(env_dir / "bin")
        subprocess.run(
            [str(interp), "-I", "-m", "venv", "--copies", str(env_dir)],
            check=True,
            cwd=stage,
            env=env,
        )
        py = env_dir / "bin" / "python"
        if not py.is_file() or py.is_symlink():
            raise Refused("fresh venv interpreter missing or symlinked")

        metadata = validate_wheel_metadata(py, wheel_dir, lock, env)
        metadata_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        report = stage / "pip-report.json"
        subprocess.run(
            [
                str(py), "-I", "-m", "pip", "install", "--isolated",
                "--disable-pip-version-check", "--no-input", "--no-index",
                "--only-binary=:all:", "--require-hashes", "--no-deps",
                "--find-links", str(wheel_dir), "--report", str(report),
                "-r", str(stage / "lock.txt"),
            ],
            check=True,
            cwd=stage,
            env=env,
        )
        installed = verify_report(report, lock, inv)
        receipt = {
            "schema": "amazingbecca-shared-composition-stack-v3",
            "authority": "advisory-install-evidence-only",
            "profile": a.profile,
            "profile_roots": list(ROOTS[a.profile]),
            "python": sys.version.split()[0],
            "python_implementation": sys.implementation.name,
            "python_cache_tag": sys.implementation.cache_tag,
            "platform": sysconfig.get_platform(),
            "interpreter": str(interp),
            "interpreter_sha256": interp_hash,
            "bootstrap_sha256": bootstrap_hash,
            "lock_sha256": expected,
            "wheelhouse": inv,
            "dependency_metadata_sha256": h(metadata_bytes),
            "dependency_metadata_validated": True,
            "dependency_traversal": False,
            "installed": installed,
            "pip_report_sha256": h(read_regular(report)),
            "network_install": False,
            "source_distribution_builds": False,
            "reused_environment": False,
            "sources": SOURCES,
            "promotion_authorized": False,
            "completion_authorized": False,
        }
        receipt["receipt_sha256"] = h(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        )
        write_new(stage / "receipt.json", (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
        os.rename(stage, final)
        dfd = os.open(profile_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        if stage.exists() and stage.is_dir() and not stage.is_symlink():
            shutil.rmtree(stage)
        raise

    print(final / "receipt.json")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refused as e:
        raise SystemExit(f"bootstrap refused: {e}") from e
