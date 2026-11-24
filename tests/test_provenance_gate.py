"""Tests for the pre-generation gate (require_official / --allow-unofficial / provenance.json) and query warnings.

All use synthetic data and do not depend on the local game. Run: python -B -m unittest discover -s tests -v
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_install as vi  # noqa: E402
from test_verify_install import Fixture  # noqa: E402

OFFICIAL_EDF_SHA = "0d5092393a1b9d8f1b75b0c93d8a8f65615a36a92c46e40349c2b66c733d0916"
OFFICIAL_EXE_SHA = "87fadc7dbfb6f50d0f1bfea5b3f51af779aeaa9fa03a90c62a695eb39f1e0989"


def run(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-B", *map(str, args)], cwd=cwd, capture_output=True,
                          encoding="utf-8", errors="replace", timeout=120)


class TempCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def fake_game(self, name="game", files=("EDF.dll", "EDF6.exe")):
        game = self.tmp / name
        game.mkdir()
        for f in files:
            (game / f).write_bytes(b"MZ not the official " + f.encode())
        return game


class HelperTests(TempCase):
    def test_provenance_path_dir_and_file(self):
        d = self.tmp / "artifact"
        d.mkdir()
        self.assertEqual(vi.provenance_path(d), d / "provenance.json")
        f = self.tmp / "probe.jsonl"
        self.assertEqual(vi.provenance_path(f), self.tmp / "probe.jsonl.provenance.json")

    def test_write_read_roundtrip(self):
        d = self.tmp / "artifact"
        d.mkdir()
        vi.write_provenance(d, {"verdict": "official", "files": []})
        self.assertEqual(vi.read_provenance(d)["verdict"], "official")
        self.assertIsNone(vi.read_provenance(self.tmp / "nothing"))

    def test_warnings(self):
        self.assertEqual(vi.provenance_warnings(None, {"EDF.dll": OFFICIAL_EDF_SHA, "EDF6.exe": OFFICIAL_EXE_SHA}), [])
        w = vi.provenance_warnings(None, {"EDF.dll": "ab" * 32})
        self.assertEqual(len(w), 1)
        self.assertIn("EDF.dll", w[0])
        w = vi.provenance_warnings({"verdict": "unofficial", "unofficial_allowed": True,
                                    "files": [{"module": "Root.cpk", "sha256": "cd" * 32}]})
        self.assertTrue(any("--allow-unofficial" in x for x in w))
        self.assertTrue(any("Root.cpk" in x for x in w))
        official = {"verdict": "official", "files": [{"module": "EDF.dll", "sha256": OFFICIAL_EDF_SHA}]}
        self.assertEqual(vi.provenance_warnings(official), [])

    def test_require_official_records_gate(self):
        fx = Fixture(self.tmp)
        res = vi.require_official(fx.game, ["EDF.dll"], known_builds_path=fx.kb, progress=False, tool="t")
        self.assertEqual(res["gate"]["tool"], "t")
        self.assertEqual(res["gate"]["modules"], ["EDF.dll"])
        self.assertFalse(res["unofficial_allowed"])
        (fx.game / "EDF.dll").write_bytes(b"MZ changed")
        res = vi.require_official(fx.game, ["EDF.dll"], allow_unofficial=True, known_builds_path=fx.kb,
                                  progress=False)
        self.assertTrue(res["unofficial_allowed"])
        self.assertEqual(res["verdict"], "unofficial")

    def test_cli_module_and_allow_unofficial(self):
        fx = Fixture(self.tmp)
        (fx.game / "EDF6.exe").write_bytes(b"MZ changed")
        out = self.tmp / "nested" / "dir" / "p.json"   # must be writable even if the parent directory does not exist
        rc = vi.main([str(fx.game), "--module", "EDF.dll", "--json", str(out), "--known-builds", str(fx.kb)])
        self.assertEqual(rc, 0)
        self.assertEqual([f["module"] for f in json.loads(out.read_text(encoding="utf-8"))["files"]], ["EDF.dll"])
        rc = vi.main([str(fx.game), "--quick", "--allow-unofficial", "--json", str(out),
                      "--known-builds", str(fx.kb)])
        self.assertEqual(rc, vi.EXIT_UNOFFICIAL)   # letting it through does not change the exit code, only records it
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(data["unofficial_allowed"])
        self.assertTrue(data["gate"]["allow_unofficial"])


class ScriptGateTests(TempCase):
    def test_missions_refuses_unofficial(self):
        # known-builds.tsv lists 4 CPKs: a hash mismatch means "modified", exit code 2, and no output directory is created
        game = self.fake_game(files=("Root.cpk", "Chunk01.cpk", "Chunk02.cpk", "DX11.cpk"))
        out = self.tmp / "missions-out"
        p = run(ROOT / "missions.py", game, "--output", out)
        self.assertEqual(p.returncode, vi.EXIT_UNOFFICIAL, p.stderr)
        self.assertIn("--allow-unofficial", p.stderr)
        self.assertFalse(out.exists(), "no output directory should be created when the gate does not pass")

    def test_vanilla_build_refuses_unofficial(self):
        game = self.fake_game()
        db = self.tmp / "v.sqlite"
        p = run(ROOT / "vanilla.py", "--db", db, "build", game)
        self.assertEqual(p.returncode, vi.EXIT_UNOFFICIAL, p.stderr)
        self.assertIn("--allow-unofficial", p.stderr)
        self.assertFalse(db.exists())

    def test_vanilla_verify_refuses_unofficial(self):
        game = self.fake_game()
        p = run(ROOT / "vanilla.py", "--db", self.tmp / "v.sqlite", "verify", game)
        self.assertEqual(p.returncode, vi.EXIT_UNOFFICIAL, p.stderr)


class VanillaQueryWarningTests(TempCase):
    def make_db(self, sha):
        sys.path.insert(0, str(ROOT))
        import vanilla
        db_path = self.tmp / "v.sqlite"
        with sqlite3.connect(db_path) as db:
            db.executescript(vanilla.SCHEMA)
            db.execute("INSERT INTO image VALUES (?,?,?,?,?,?,?)", ("EDF.dll", sha, 0x678CCB46, 0x180000000, 0, 1, 1))
        db.close()
        return db_path

    def summary(self, db_path):
        return run(ROOT / "vanilla.py", "--db", db_path, "summary")

    def test_official_db_no_warning(self):
        p = self.summary(self.make_db(OFFICIAL_EDF_SHA))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("warning", p.stderr)
        json.loads(p.stdout)   # stdout is still pure JSON

    def test_unknown_build_warns(self):
        p = self.summary(self.make_db("ef" * 32))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("warning", p.stderr.splitlines()[0])
        self.assertIn("known-builds", p.stderr)

    def test_unofficial_provenance_warns(self):
        db_path = self.make_db(OFFICIAL_EDF_SHA)
        vi.write_provenance(db_path, {"verdict": "unofficial", "unofficial_allowed": True, "files": []})
        self.assertTrue((self.tmp / "v.sqlite.provenance.json").is_file())
        p = self.summary(db_path)
        self.assertIn("--allow-unofficial", p.stderr)


@unittest.skipUnless(shutil.which("powershell"), "needs Windows PowerShell")
class DecompileGateTests(TempCase):
    def test_decompile_stops_before_ghidra(self):
        game = self.fake_game()
        ghidra = self.tmp / "ghidra"
        jar = ghidra / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b"")
        out = self.tmp / "pseudo"
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-File", str(ROOT / "decompile.ps1"), "-Game", str(game), "-Ghidra", str(ghidra),
                            "-Output", str(out), "-ReuseProject", "-Java", "java-should-not-run.exe", "-Python", sys.executable],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=180)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not a verified official build", p.stdout + p.stderr)
        self.assertNotIn("java-should-not-run", p.stdout + p.stderr)
        self.assertFalse((out / "EDF.dll").exists())


if __name__ == "__main__":
    unittest.main()
