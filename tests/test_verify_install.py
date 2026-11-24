"""Unit tests for verify_install.py: synthetic depot manifests and temporary directories; no dependency on the local game.

Run: python -B -m unittest discover -s tests -v
"""
from __future__ import annotations

import hashlib
import io
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_install as vi  # noqa: E402


# ---- Minimal protobuf encoder (only for building test data) ----

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _f_varint(field: int, n: int) -> bytes:
    return _varint(field << 3) + _varint(n)


def _f_bytes(field: int, b: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(b)) + b


def _mapping(name: str, content: bytes | None, flags: int = 0, encrypted_name: bool = False) -> bytes:
    body = _f_bytes(1, (b"ENCRYPTED==" + hashlib.md5(name.encode()).hexdigest().encode())
                    if encrypted_name else name.encode())
    body += _f_varint(2, len(content or b""))
    body += _f_varint(3, flags)
    body += _f_bytes(4, vi.sha_filename_of(name))
    body += _f_bytes(5, hashlib.sha1(content).digest() if content is not None else b"\0" * 20)
    if content:
        chunk = _f_bytes(1, hashlib.sha1(content).digest()) + _varint(2 << 3 | 5) + struct.pack("<I", 1)
        body += _f_bytes(6, chunk)
    return body


def build_manifest(files: dict[str, bytes | None], depot: int = 2291062, gid: int = 123456789,
                   encrypted: bool = False, dirs: tuple[str, ...] = ()) -> bytes:
    payload = b"".join(_f_bytes(1, _mapping(n, c, encrypted_name=encrypted)) for n, c in files.items())
    payload += b"".join(_f_bytes(1, _mapping(d, None, flags=vi.FLAG_DIRECTORY, encrypted_name=encrypted))
                        for d in dirs)
    meta = (_f_varint(1, depot) + _f_varint(2, gid) + _f_varint(3, 1737284596)
            + _f_varint(4, 1 if encrypted else 0))
    sig = _f_bytes(1, b"\x01" * 16)

    def sec(magic: int, body: bytes) -> bytes:
        return struct.pack("<II", magic, len(body)) + body

    return (sec(vi.MAGIC_PAYLOAD, payload) + sec(vi.MAGIC_METADATA, meta)
            + sec(vi.MAGIC_SIGNATURE, sig) + struct.pack("<I", vi.MAGIC_END))


def fake_pe(ts: int = 0x678CCB46, image_base: int = 0x180000000, sections=(".text", ".data"),
            filler: bytes = b"") -> bytes:
    pe_off = 0x80
    d = bytearray(0x400)
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 0x3C, pe_off)
    d[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HHI", d, pe_off + 4, 0x8664, len(sections), ts)
    optsz = 0xF0
    struct.pack_into("<H", d, pe_off + 20, optsz)
    struct.pack_into("<H", d, pe_off + 24, 0x20B)
    struct.pack_into("<Q", d, pe_off + 24 + 24, image_base)
    s0 = pe_off + 24 + optsz
    for i, s in enumerate(sections):
        d[s0 + i * 40:s0 + i * 40 + 8] = s.encode().ljust(8, b"\0")
    return bytes(d) + filler


ACF = '''"AppState"
{
\t"appid"\t\t"2291060"
\t"installdir"\t\t"EARTH DEFENSE FORCE 6"
\t"buildid"\t\t"17055427"
\t"InstalledDepots"
\t{
\t\t"2291062"
\t\t{
\t\t\t"manifest"\t\t"123456789"
\t\t\t"size"\t\t"100"
\t\t}
\t}
}
'''


class Fixture:
    """steam/steamapps/common/EARTH DEFENSE FORCE 6 + depotcache + known-builds.tsv"""

    def __init__(self, tmp: Path, *, encrypted: bool = False, write_acf: bool = True):
        self.root = tmp / "steam"
        self.game = self.root / "steamapps" / "common" / "EARTH DEFENSE FORCE 6"
        self.game.mkdir(parents=True)
        (self.root / "depotcache").mkdir()
        self.dll = fake_pe(filler=b"dll-body" * 100)
        self.exe = fake_pe(ts=0x678CCB63, image_base=0x140000000, filler=b"exe-body" * 50)
        self.cpk = {n: n.encode() * 1000 for n in ("Root.cpk", "Chunk01.cpk", "Chunk02.cpk", "DX11.cpk")}
        files = {"EDF.dll": self.dll, "EDF6.exe": self.exe, **self.cpk,
                 "steam_api64.dll": b"orig-steam-api", "SOUND\\bgm.awb": b"bgm"}
        for name, content in files.items():
            p = self.game / name.replace("\\", "/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        (self.root / "depotcache" / "2291062_123456789.manifest").write_bytes(
            build_manifest(files, encrypted=encrypted, dirs=("SOUND",)))
        if write_acf:
            (self.root / "steamapps" / "appmanifest_2291060.acf").write_text(ACF, encoding="utf-8")
        self.kb = tmp / "known-builds.tsv"
        self.write_known_builds({"EDF.dll": self.dll, "EDF6.exe": self.exe})

    def write_known_builds(self, mods: dict[str, bytes]):
        lines = ["# test", "\t".join(vi.KNOWN_BUILDS_COLUMNS)]
        for name, content in mods.items():
            lines.append("\t".join([name, hashlib.sha256(content).hexdigest(), hashlib.sha1(content).hexdigest(),
                                    str(len(content)), "0x678CCB46", "0x180000000", "17055427", "2291062",
                                    "123456789", "test"]))
        self.kb.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def verify(self, **kw):
        kw.setdefault("known_builds_path", self.kb)
        kw.setdefault("progress", False)
        return vi.verify(self.game, **kw)


def _by_module(res):
    return {f["module"]: f for f in res["files"]}


class ProtobufAndManifestTests(unittest.TestCase):
    def test_varint_roundtrip(self):
        for n in (0, 1, 127, 128, 300, 2**32 + 5, 2**63 - 1):
            self.assertEqual(vi._read_varint(_varint(n), 0), (n, len(_varint(n))))

    def test_iter_fields_wire_types(self):
        buf = _f_varint(1, 5) + _f_bytes(2, b"ab") + _varint(3 << 3 | 5) + struct.pack("<I", 7) \
            + _varint(4 << 3 | 1) + struct.pack("<Q", 9)
        self.assertEqual(list(vi.iter_fields(buf)), [(1, 0, 5), (2, 2, b"ab"), (3, 5, 7), (4, 1, 9)])

    def test_truncated_raises(self):
        with self.assertRaises(vi.ProtoError):
            list(vi.iter_fields(_f_bytes(1, b"abcdef")[:-2]))

    def test_parse_manifest(self):
        data = build_manifest({"EDF.dll": b"x" * 10, "a\\b.txt": b""}, dirs=("a",))
        m = vi.parse_manifest_bytes(data)
        self.assertEqual(m["metadata"]["depot_id"], 2291062)
        self.assertEqual(m["metadata"]["gid_manifest"], 123456789)
        self.assertFalse(m["metadata"]["filenames_encrypted"])
        self.assertTrue(m["has_signature"])
        self.assertTrue(m["has_end_marker"])
        names = {x["filename"]: x for x in m["mappings"]}
        self.assertEqual(names["EDF.dll"]["size"], 10)
        self.assertEqual(names["EDF.dll"]["sha_content"], hashlib.sha1(b"x" * 10).digest())
        self.assertEqual(names["EDF.dll"]["chunks"], 1)
        self.assertEqual(names["a"]["flags"] & vi.FLAG_DIRECTORY, vi.FLAG_DIRECTORY)

    def test_parse_zip_wrapped_manifest(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("z", build_manifest({"EDF.dll": b"y"}))
        m = vi.parse_manifest_bytes(bio.getvalue())
        self.assertEqual(m["mappings"][0]["filename"], "EDF.dll")

    def test_unknown_section_rejected(self):
        with self.assertRaises(vi.ProtoError):
            vi.parse_manifest_bytes(struct.pack("<II", 0xDEADBEEF, 0))

    def test_missing_payload_rejected(self):
        with self.assertRaises(vi.ProtoError):
            vi.parse_manifest_bytes(struct.pack("<I", vi.MAGIC_END))

    def test_sha_filename_normalisation(self):
        self.assertEqual(vi.sha_filename_of("SOUND/BGM.awb"), hashlib.sha1(b"sound\\bgm.awb").digest())


class VdfAndKnownBuildsTests(unittest.TestCase):
    def test_parse_acf(self):
        st = vi.parse_vdf(ACF)["AppState"]
        self.assertEqual(st["buildid"], "17055427")
        self.assertEqual(st["InstalledDepots"]["2291062"]["manifest"], "123456789")

    def test_vdf_escapes(self):
        d = vi.parse_vdf('"a" { "p" "D:\\\\steam\\\\x" // c\n "q" "say \\"hi\\"" }')
        self.assertEqual(d["a"]["p"], "D:\\steam\\x")
        self.assertEqual(d["a"]["q"], 'say "hi"')

    def test_repo_known_builds_has_official_pe(self):
        rows = {r["module"]: r for r in vi.load_known_builds()}
        self.assertEqual(rows["EDF.dll"]["sha256"],
                         "0d5092393a1b9d8f1b75b0c93d8a8f65615a36a92c46e40349c2b66c733d0916")
        self.assertEqual(rows["EDF.dll"]["TimeDateStamp"], "0x678CCB46")
        self.assertEqual(rows["EDF6.exe"]["sha256"],
                         "87fadc7dbfb6f50d0f1bfea5b3f51af779aeaa9fa03a90c62a695eb39f1e0989")
        for r in rows.values():
            self.assertEqual(set(vi.KNOWN_BUILDS_COLUMNS) - set(r), set())


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_official_full(self):
        fx = Fixture(self.tmp)
        res = fx.verify()
        self.assertEqual(res["verdict"], "official", res)
        self.assertEqual(res["exit_code"], vi.EXIT_OFFICIAL)
        self.assertEqual(res["steam"]["buildid"], "17055427")
        for f in res["files"]:
            self.assertEqual(f["verdict"], "official", f)
            self.assertTrue(f["basis"].startswith("depot-manifest:2291062/123456789"))
        self.assertEqual(res["missing_from_install"], [])
        self.assertEqual(res["third_party"], [])

    def test_quick_skips_cpk(self):
        fx = Fixture(self.tmp)
        res = fx.verify(quick=True)
        mods = _by_module(res)
        self.assertEqual(mods["EDF.dll"]["verdict"], "official")
        self.assertEqual(mods["Root.cpk"]["verdict"], "unchecked")
        self.assertIsNone(mods["Root.cpk"]["sha1"])
        self.assertEqual(res["exit_code"], vi.EXIT_OFFICIAL)
        # The summary must not say "official original": the CPKs were never hashed
        self.assertIn("Verdict: PEs official, CPKs not checked (exit code 0)", vi.format_summary(res))
        self.assertNotIn("official original", vi.format_summary(res))
        self.assertIn("Verdict: official original", vi.format_summary(fx.verify()))

    def test_modified_cpk_detected(self):
        fx = Fixture(self.tmp)
        p = fx.game / "Chunk02.cpk"
        b = bytearray(p.read_bytes())
        b[5] ^= 1
        p.write_bytes(bytes(b))
        res = fx.verify()
        self.assertEqual(_by_module(res)["Chunk02.cpk"]["verdict"], "modified")
        self.assertEqual(res["exit_code"], vi.EXIT_UNOFFICIAL)

    def test_missing_and_third_party(self):
        fx = Fixture(self.tmp)
        (fx.game / "SOUND" / "bgm.awb").unlink()
        (fx.game / "cream_api.ini").write_text("x")
        (fx.game / "winmm.dll").write_bytes(b"x")
        (fx.game / "EDF6.exe.bak").write_bytes(b"x")
        (fx.game / "steam_api64_o.dll").write_bytes(b"orig-steam-api")
        (fx.game / "steam_api64.dll").write_bytes(b"cream-api-replacement")
        res = fx.verify(quick=True)
        self.assertIn("SOUND\\bgm.awb", res["missing_from_install"])
        origins = {t["name"]: t["origin"] for t in res["third_party"]}
        self.assertEqual(origins["cream_api.ini"], "CreamAPI")
        self.assertEqual(origins["winmm.dll"], "EDFModLoader")
        self.assertIn("Steamless", origins["EDF6.exe.bak"])
        api = [t for t in res["third_party"] if t["name"] == "steam_api64.dll"][0]
        self.assertIn("steam_api64_o.dll matches the manifest original", api["detail"])
        self.assertEqual(res["size_mismatch"][0]["name"], "steam_api64.dll")
        # Third-party files only warn, they do not block
        self.assertEqual(res["exit_code"], vi.EXIT_OFFICIAL)

    def test_missing_target_is_unofficial(self):
        fx = Fixture(self.tmp)
        (fx.game / "DX11.cpk").unlink()
        res = fx.verify(quick=True)
        self.assertEqual(_by_module(res)["DX11.cpk"]["verdict"], "missing")
        self.assertEqual(res["exit_code"], vi.EXIT_UNOFFICIAL)

    def test_encrypted_filenames_fall_back(self):
        fx = Fixture(self.tmp, encrypted=True)
        res = fx.verify(quick=True)
        self.assertEqual(_by_module(res)["EDF.dll"]["verdict"], "official")
        self.assertTrue(any("file names are encrypted" in w for w in res["warnings"]))
        self.assertEqual(res["missing_from_install"], [])  # cannot check by name

    def test_encrypted_no_cross_file_sha1(self):
        fx = Fixture(self.tmp, encrypted=True)
        # With encrypted file names entries are found only by sha_filename: putting another genuine file's content under this name must not count as official
        (fx.game / "Chunk01.cpk").write_bytes(fx.cpk["Chunk02.cpk"])
        res = fx.verify(modules=("Chunk01.cpk",))
        f = _by_module(res)["Chunk01.cpk"]
        self.assertEqual(f["verdict"], "modified", f)
        self.assertEqual(res["exit_code"], vi.EXIT_UNOFFICIAL)
        # After a rename sha_filename finds no entry: no per-name basis, and a SHA1 set must not be used to judge official
        (fx.game / "Root.cpk").rename(fx.game / "Renamed.cpk")
        res = fx.verify(modules=("Renamed.cpk",))
        f = _by_module(res)["Renamed.cpk"]
        self.assertEqual(f["verdict"], "unknown", f)
        self.assertEqual(res["exit_code"], vi.EXIT_UNDECIDED)

    def test_plain_manifest_no_cross_file_sha1(self):
        fx = Fixture(self.tmp)
        (fx.game / "DX11.cpk").write_bytes(fx.cpk["Root.cpk"])
        f = _by_module(fx.verify(modules=("DX11.cpk",)))["DX11.cpk"]
        self.assertEqual(f["verdict"], "modified", f)

    def test_manifest_match_but_unregistered_pe(self):
        fx = Fixture(self.tmp)
        fx.write_known_builds({"EDF6.exe": fx.exe})   # EDF.dll is not in known-builds
        res = fx.verify(quick=True)
        f = _by_module(res)["EDF.dll"]
        self.assertEqual(f["verdict"], "unregistered", f)
        self.assertIn("Steam new build, not registered", f["detail"])
        self.assertEqual(_by_module(res)["EDF6.exe"]["verdict"], "official")
        self.assertEqual((res["verdict"], res["exit_code"]), ("unregistered", vi.EXIT_UNDECIDED))
        summary = vi.format_summary(res)
        self.assertIn("Verdict: Steam new build, not registered (exit code 3)", summary)
        self.assertIn("shared/builds.tsv", summary)
        # Gate: refuses by default (exit code 3); --allow-unofficial lets it through and hints to register
        with self.assertRaises(vi.UnofficialInstallError) as cm:
            vi.require_official(fx.game, ["EDF.dll"], known_builds_path=fx.kb, progress=False)
        self.assertEqual(cm.exception.result["exit_code"], vi.EXIT_UNDECIDED)
        self.assertIn("known-builds.tsv", str(cm.exception))
        res = vi.require_official(fx.game, ["EDF.dll"], allow_unofficial=True, known_builds_path=fx.kb,
                                  progress=False)
        self.assertTrue(res["unofficial_allowed"])
        self.assertEqual(res["verdict"], "unregistered")

    def test_known_builds_sha_must_match_module(self):
        fx = Fixture(self.tmp, write_acf=False)
        # Genuine EDF6.exe content under the EDF.dll name: the sha256 is in known-builds, but the module name is wrong
        (fx.game / "EDF.dll").write_bytes(fx.exe)
        f = _by_module(fx.verify(modules=("EDF.dll",)))["EDF.dll"]
        self.assertEqual(f["verdict"], "modified", f)

    def test_explicit_manifest_and_steam_root(self):
        fx = Fixture(self.tmp, write_acf=False)
        res = fx.verify(quick=True)
        self.assertEqual(res["steam"]["manifests"], [])
        # No acf: fall back to known-builds, PEs official
        self.assertEqual(_by_module(res)["EDF.dll"]["basis"], "known-builds")
        res = fx.verify(quick=True, manifests=[fx.root / "depotcache" / "2291062_123456789.manifest"])
        self.assertEqual(_by_module(res)["EDF.dll"]["basis"], "depot-manifest:2291062/123456789+known-builds")
        (fx.root / "steamapps" / "appmanifest_2291060.acf").write_text(ACF, encoding="utf-8")
        res = fx.verify(quick=True, steam_root=fx.root)
        self.assertEqual(res["steam"]["buildid"], "17055427")
        self.assertEqual(len(res["steam"]["manifests"]), 1)

    def test_no_manifest_known_builds(self):
        game = self.tmp / "copied"
        game.mkdir()
        fx = Fixture(self.tmp)
        (game / "EDF.dll").write_bytes(fx.dll)
        res = vi.verify(game, modules=("EDF.dll",), known_builds_path=fx.kb, progress=False)
        self.assertEqual(res["verdict"], "official")
        # Change one byte -> unofficial, with a note that the timestamp is the same
        b = bytearray(fx.dll)
        b[-1] ^= 1
        (game / "EDF.dll").write_bytes(bytes(b))
        res = vi.verify(game, modules=("EDF.dll",), known_builds_path=fx.kb, progress=False)
        f = _by_module(res)["EDF.dll"]
        self.assertEqual(f["verdict"], "modified")
        self.assertIn("same timestamp as the genuine build", f["detail"])
        self.assertEqual(res["exit_code"], vi.EXIT_UNOFFICIAL)

    def test_no_reference_is_undecided(self):
        game = self.tmp / "copied"
        game.mkdir()
        (game / "Root.cpk").write_bytes(b"r")
        empty_kb = self.tmp / "empty.tsv"
        empty_kb.write_text("\t".join(vi.KNOWN_BUILDS_COLUMNS) + "\n", encoding="utf-8")
        res = vi.verify(game, modules=("Root.cpk",), known_builds_path=empty_kb, progress=False)
        self.assertEqual(res["exit_code"], vi.EXIT_UNDECIDED)

    def test_require_official(self):
        fx = Fixture(self.tmp)
        res = vi.require_official(fx.game, ["EDF.dll"], known_builds_path=fx.kb, progress=False)
        self.assertEqual(res["verdict"], "official")
        (fx.game / "EDF.dll").write_bytes(b"MZ-not-official")
        with self.assertRaises(vi.UnofficialInstallError) as cm:
            vi.require_official(fx.game, ["EDF.dll"], known_builds_path=fx.kb, progress=False)
        self.assertEqual(cm.exception.result["exit_code"], vi.EXIT_UNOFFICIAL)
        res = vi.require_official(fx.game, ["EDF.dll"], allow_unofficial=True, known_builds_path=fx.kb,
                                  progress=False)
        self.assertEqual(res["verdict"], "unofficial")

    def test_cli_exit_code_and_json(self):
        fx = Fixture(self.tmp)
        out = self.tmp / "p.json"
        rc = vi.main([str(fx.game), "--quick", "--json", str(out), "--known-builds", str(fx.kb)])
        self.assertEqual(rc, 0)
        import json
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["verdict"], "official")
        self.assertIn("sha256", data["files"][0])

    def test_pe_info(self):
        p = self.tmp / "x.exe"
        p.write_bytes(fake_pe(sections=(".text", ".bind")))
        pi = vi.pe_info(p)
        self.assertEqual(pi["TimeDateStamp"], "0x678CCB46")
        self.assertEqual(pi["image_base"], "0x180000000")
        self.assertTrue(pi["has_bind"])


if __name__ == "__main__":
    unittest.main()
