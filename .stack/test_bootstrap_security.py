#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import functools
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socketserver
import subprocess
import sys
import sysconfig
import tempfile
import threading
import unittest
import zipfile
from email.parser import BytesParser

HERE = Path(__file__).resolve().parent
BOOTSTRAP = Path(os.environ.get("AB_STACK_BOOTSTRAP", HERE / "bootstrap.py")).resolve()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_bootstrap():
    spec = importlib.util.spec_from_file_location("shared_stack_bootstrap_under_test", BOOTSTRAP)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load bootstrap")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_wheel(
    directory: Path,
    project: str,
    version: str = "1.0.0",
    requires: list[str] | None = None,
) -> tuple[Path, str]:
    dist = project.replace("-", "_")
    import_name = dist.replace(".", "_")
    dist_info = f"{dist}-{version}.dist-info"
    wheel = directory / f"{dist}-{version}-py3-none-any.whl"
    metadata = "Metadata-Version: 2.1\n" + f"Name: {project}\nVersion: {version}\n"
    for requirement in requires or []:
        metadata += f"Requires-Dist: {requirement}\n"
    metadata += "\n"
    files: dict[str, bytes] = {
        f"{import_name}/__init__.py": f'__version__ = "{version}"\n'.encode(),
        f"{dist_info}/METADATA": metadata.encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: shared-stack-security-test\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode(),
    }
    rows: list[tuple[str, str, str]] = []
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        rows.append((path, f"sha256={digest}", str(len(data))))
    record = f"{dist_info}/RECORD"
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerows(rows)
    writer.writerow((record, "", ""))
    files[record] = buf.getvalue().encode()
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in files.items():
            zf.writestr(path, data)
    data = wheel.read_bytes()
    return wheel, sha256(data)


def find_real_pip_wheel() -> Path:
    pkg_dir = sysconfig.get_config_var("WHEEL_PKG_DIR")
    if pkg_dir:
        matches = sorted(Path(pkg_dir).glob("pip-*.whl"))
        if matches:
            return matches[-1]
    try:
        import ensurepip
        ctx = getattr(ensurepip, "_get_pip_whl_path_ctx", None)
        if ctx is not None:
            with ctx() as path:
                if Path(path).is_file():
                    target = Path(tempfile.mkdtemp()) / Path(path).name
                    shutil.copyfile(path, target)
                    return target
    except Exception:
        pass
    raise unittest.SkipTest("real pip wheel unavailable for offline bootstrap regression")


def wheel_identity(wheel: Path) -> tuple[str, str, str]:
    data = wheel.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        metas = [m for m in zf.namelist() if len(Path(m).parts) == 2 and m.endswith(".dist-info/METADATA")]
        if len(metas) != 1:
            raise RuntimeError("bad test pip wheel")
        msg = BytesParser().parsebytes(zf.read(metas[0]))
    return str(msg["Name"]), str(msg["Version"]), sha256(data)


def populate_base_wheelhouse(root: Path, direct_url: str | None = None) -> tuple[Path, bytes]:
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    pip_src = find_real_pip_wheel()
    pip_dst = wheelhouse / pip_src.name
    shutil.copyfile(pip_src, pip_dst)
    pip_name, pip_version, pip_digest = wheel_identity(pip_dst)
    lines = [f"{pip_name}=={pip_version} --hash=sha256:{pip_digest}"]
    roots = ["httpx", "pydantic", "python-dotenv", "pytest", "pytest-asyncio", "hypothesis"]
    for project in roots:
        requires = [direct_url] if (project == "httpx" and direct_url) else []
        _wheel, digest = make_wheel(wheelhouse, project, requires=requires)
        lines.append(f"{project}==1.0.0 --hash=sha256:{digest}")
    return wheelhouse, ("\n".join(lines) + "\n").encode()


class SharedStackBootstrapSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("reviewed bootstrap requires POSIX O_NOFOLLOW semantics")
        self.mod = load_bootstrap()

    def test_lock_parser_rejects_unhashed_ranges_urls_options_and_duplicates(self) -> None:
        bad = [
            b"httpx>=1.0\n",
            b"httpx==1.0.0\n",
            b"httpx @ https://example.invalid/httpx.whl --hash=sha256:" + b"0" * 64 + b"\n",
            b"--index-url https://example.invalid\n",
            b"httpx==1.0.0 --hash=sha256:" + b"0" * 64 + b"\nHTTPX==1.0.0 --hash=sha256:" + b"1" * 64 + b"\n",
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                with self.assertRaises(self.mod.Refused):
                    self.mod.parse_lock(payload)

    def test_profile_roots_require_authenticated_pip(self) -> None:
        lock = self.mod.parse_lock(b"httpx==1.0.0 --hash=sha256:" + b"0" * 64 + b"\n")
        with self.assertRaises(self.mod.Refused) as cm:
            self.mod.validate_roots("base", lock)
        self.assertIn("pip", str(cm.exception))

    def test_mirofish_rejects_non_cpython_311(self) -> None:
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_profile_runtime("mirofish", "pypy", (3, 11))
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_profile_runtime("mirofish", "cpython", (3, 12))
        self.mod.validate_profile_runtime("mirofish", "cpython", (3, 11))

    def test_write_new_refuses_preexisting_symlink_and_preserves_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            victim = root / "victim"
            victim.write_bytes(b"keep")
            out = root / "receipt.json"
            out.symlink_to(victim)
            with self.assertRaises(FileExistsError):
                self.mod.write_new(out, b"replacement")
            self.assertEqual(victim.read_bytes(), b"keep")

    def test_dry_run_does_not_create_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            stack = Path(td) / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)
            result = subprocess.run(
                [sys.executable, str(script), "--profile", "base", "--dry-run"],
                text=True,
                capture_output=True,
                check=True,
            )
            plan = json.loads(result.stdout)
            self.assertEqual(plan["installer"], "hash-locked-pip-wheel-no-ensurepip")
            self.assertFalse((stack / "runtime").exists())

    def test_exact_lock_mismatch_fails_before_runtime_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            stack = Path(td) / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)
            lock = Path(td) / "lock.txt"
            lock.write_text("pip==1.0.0 --hash=sha256:" + "0" * 64 + "\n")
            wheelhouse = Path(td) / "wheels"
            wheelhouse.mkdir()
            result = subprocess.run(
                [sys.executable, str(script), "--profile", "base", "--lock", str(lock),
                 "--lock-sha256", "1" * 64, "--wheelhouse", str(wheelhouse)],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("lock SHA-256 mismatch", result.stderr)
            self.assertFalse((stack / "runtime").exists())

    def test_direct_url_dependency_is_rejected_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stack = root / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)
            served = root / "served"
            served.mkdir()
            evil, _ = make_wheel(served, "evil")
            hits: list[str] = []

            class Handler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    hits.append(self.path)
                    return super().do_GET()

            handler = functools.partial(Handler, directory=str(served))
            server = socketserver.TCPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                wheelhouse, lock_bytes = populate_base_wheelhouse(
                    root, f"evil @ http://127.0.0.1:{port}/{evil.name}"
                )
                lock = root / "base.lock"
                lock.write_bytes(lock_bytes)
                result = subprocess.run(
                    [sys.executable, str(script), "--profile", "base", "--lock", str(lock),
                     "--lock-sha256", sha256(lock_bytes), "--wheelhouse", str(wheelhouse)],
                    text=True,
                    capture_output=True,
                    env={"PATH": os.defpath, "LANG": "C.UTF-8"},
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("direct URL dependency forbidden", result.stderr)
            self.assertEqual(hits, [])

    def test_without_pip_venv_starts_without_seeded_distributions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            venv = Path(td) / "venv"
            subprocess.run(
                [sys.executable, "-I", "-m", "venv", "--without-pip", "--copies", str(venv)],
                check=True,
                env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            )
            py = venv / "bin" / "python"
            audit = subprocess.run(
                [str(py), "-I", "-c", "from importlib.metadata import distributions; print(list(distributions()))"],
                text=True,
                capture_output=True,
                check=True,
                env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            )
            self.assertEqual(audit.stdout.strip(), "[]")
            missing_pip = subprocess.run(
                [str(py), "-I", "-m", "pip", "--version"],
                text=True,
                capture_output=True,
                env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            )
            self.assertNotEqual(missing_pip.returncode, 0)

    def test_fake_pip_wheel_cannot_be_used_as_installer_without_matching_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wh = root / "wh"
            wh.mkdir()
            fake, digest = make_wheel(wh, "pip", "0.0.1")
            lock = {"pip": {"version": "99.0", "sha256": digest}}
            inv = [{"name": fake.name, "sha256": digest, "size": fake.stat().st_size}]
            with self.assertRaises(self.mod.Refused):
                self.mod.locked_pip_wheel(wh, lock, inv)

    def test_offline_install_uses_hash_locked_pip_and_exact_distribution_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stack = root / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)
            legacy_python = stack / ".venv" / "bin" / "python"
            legacy_python.parent.mkdir(parents=True)
            marker = root / "legacy-executed"
            legacy_python.write_text(f"#!/bin/sh\ntouch {marker}\nexit 99\n")
            legacy_python.chmod(0o755)
            legacy_receipts = stack / "receipts"
            legacy_receipts.mkdir()
            victim = root / "receipt-victim"
            victim.write_text("keep")
            (legacy_receipts / "base.json").symlink_to(victim)

            wheelhouse, lock_bytes = populate_base_wheelhouse(root)
            lock = root / "base.lock"
            lock.write_bytes(lock_bytes)
            lock_hash = sha256(lock_bytes)
            lock_names = {
                line.split("==", 1)[0].lower().replace("_", "-")
                for line in lock_bytes.decode().splitlines()
            }
            receipts: list[Path] = []
            for _ in range(2):
                result = subprocess.run(
                    [sys.executable, str(script), "--profile", "base", "--lock", str(lock),
                     "--lock-sha256", lock_hash, "--wheelhouse", str(wheelhouse)],
                    text=True,
                    capture_output=True,
                    check=True,
                    env={"PATH": os.defpath, "LANG": "C.UTF-8"},
                )
                receipt = Path(result.stdout.strip().splitlines()[-1])
                receipts.append(receipt)
                obj = json.loads(receipt.read_text())
                self.assertEqual(obj["schema"], "amazingbecca-shared-composition-stack-v4")
                self.assertFalse(obj["ensurepip_used"])
                self.assertEqual(obj["installer"], "hash-locked-pip-wheel-zipimport")
                self.assertTrue(obj["environment_matches_complete_lock"])
                self.assertEqual(set(obj["environment_distributions"]), lock_names)
                self.assertEqual({x["name"] for x in obj["installed"]}, lock_names)
                vpy = receipt.parent / "venv" / "bin" / "python"
                pip_version = subprocess.run(
                    [str(vpy), "-I", "-m", "pip", "--version"],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                self.assertIn("pip ", pip_version.stdout)

            self.assertNotEqual(receipts[0].parent, receipts[1].parent)
            self.assertFalse(marker.exists())
            self.assertEqual(victim.read_text(), "keep")


if __name__ == "__main__":
    unittest.main(verbosity=2)
