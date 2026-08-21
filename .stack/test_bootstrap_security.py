#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

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


def make_wheel(directory: Path, project: str, version: str = "1.0.0") -> tuple[Path, str]:
    dist = project.replace("-", "_")
    import_name = dist.replace(".", "_")
    dist_info = f"{dist}-{version}.dist-info"
    wheel = directory / f"{dist}-{version}-py3-none-any.whl"
    files: dict[str, bytes] = {
        f"{import_name}/__init__.py": f'__version__ = "{version}"\n'.encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {project}\n"
            f"Version: {version}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: shared-stack-security-test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
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

    def test_profile_roots_must_all_be_locked(self) -> None:
        lock = self.mod.parse_lock(b"httpx==1.0.0 --hash=sha256:" + b"0" * 64 + b"\n")
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_roots("base", lock)

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

    def test_dry_run_does_not_require_mirofish_python_or_create_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            stack = Path(td) / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)
            result = subprocess.run(
                [sys.executable, str(script), "--profile", "mirofish", "--dry-run"],
                text=True,
                capture_output=True,
                check=True,
            )
            plan = json.loads(result.stdout)
            self.assertEqual(plan["profile"], "mirofish")
            self.assertEqual(plan["install"], "offline-wheelhouse-only")
            self.assertFalse((stack / "runtime").exists())

    def test_exact_lock_mismatch_fails_before_runtime_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            stack = Path(td) / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)
            lock = Path(td) / "lock.txt"
            lock.write_text("httpx==1.0.0 --hash=sha256:" + "0" * 64 + "\n")
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

    def test_symlinked_lock_and_wheelhouse_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            regular_lock = root / "real.lock"
            regular_lock.write_bytes(b"x")
            link_lock = root / "link.lock"
            link_lock.symlink_to(regular_lock)
            with self.assertRaises(OSError):
                self.mod.read_regular(link_lock)

            real_wh = root / "real-wheels"
            real_wh.mkdir()
            link_wh = root / "link-wheels"
            link_wh.symlink_to(real_wh, target_is_directory=True)
            with self.assertRaises(self.mod.Refused):
                self.mod.snapshot_wheels(link_wh, root / "snapshot", {"x": {"version": "1", "sha256": "0" * 64}})

    def test_offline_install_uses_fresh_run_and_never_touches_legacy_paths(self) -> None:
        roots = ["httpx", "pydantic", "python-dotenv", "pytest", "pytest-asyncio", "hypothesis"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            stack = root / ".stack"
            stack.mkdir(mode=0o700)
            script = stack / "bootstrap.py"
            shutil.copyfile(BOOTSTRAP, script)

            # Predecessor-v1 attack surfaces: a hostile ignored interpreter and receipt symlink.
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

            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            lock_lines: list[str] = []
            for project in roots:
                _wheel, digest = make_wheel(wheelhouse, project)
                lock_lines.append(f"{project}==1.0.0 --hash=sha256:{digest}")
            lock_bytes = ("\n".join(lock_lines) + "\n").encode()
            lock = root / "base.lock"
            lock.write_bytes(lock_bytes)
            lock_hash = sha256(lock_bytes)

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
                self.assertTrue(receipt.is_file())
                receipts.append(receipt)
                obj = json.loads(receipt.read_text())
                self.assertEqual(obj["schema"], "amazingbecca-shared-composition-stack-v2")
                self.assertFalse(obj["network_install"])
                self.assertFalse(obj["source_distribution_builds"])
                self.assertFalse(obj["reused_environment"])
                self.assertFalse(obj["promotion_authorized"])
                self.assertFalse(obj["completion_authorized"])
                self.assertEqual({x["name"] for x in obj["installed"]}, {p.replace("_", "-").lower() for p in roots})
                self.assertEqual(obj["lock_sha256"], lock_hash)
                self.assertEqual(len(obj["wheelhouse"]), len(roots))

            self.assertNotEqual(receipts[0].parent, receipts[1].parent)
            self.assertFalse(marker.exists(), "legacy ignored venv interpreter was executed")
            self.assertEqual(victim.read_text(), "keep", "legacy receipt symlink target was modified")


if __name__ == "__main__":
    unittest.main(verbosity=2)
