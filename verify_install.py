#!/usr/bin/env python3
"""Check that the local EDF6 install is the official original build (the gate before generating assembly / pseudocode / mission script indexes).

Basis:
  - PE modules (EDF.dll / EDF6.exe) count as official only by SHA-256 in known-builds.tsv (the module name must match too).
    Generated addresses are bound to one specific build, so an unregistered build is not let through even if it matches the Steam manifest:
    it is judged "Steam new build, not registered" (unregistered, exit code 3); --allow-unofficial lets it through when needed,
    and the build should then be registered in known-builds.tsv and shared/builds.tsv via a PR.
  - Other files (CPKs) are compared with the SHA1 of the same-named entry in the Steam depot manifest (depotcache/<depot>_<manifest>.manifest),
    or with a SHA-256 in known-builds.tsv. The manifest is located from InstalledDepots in steamapps/appmanifest_2291060.acf.
    When manifest file names are encrypted, entries are matched only by sha_filename (the file-name hash); there is no cross-file SHA1 set matching.
  No match -> unofficial.

Standard library only; the game directory is read-only.

Command line:
  python verify_install.py "<game directory>" [--quick] [--json PATH] [--steam-root DIR] [--manifest FILE ...]
Exit codes: 0 official (with --quick: "PEs official, CPKs not checked"), 2 unofficial or modified,
        3 undecided (no basis / new Steam build not registered).

Importable:
  verify(game_dir, quick=False, ...) -> dict
  require_official(game_dir, modules, allow_unofficial=False) -> dict
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import io
import json
import os
import re
import struct
import sys
import time
import zipfile
from pathlib import Path

APP_ID = "2291060"
HERE = Path(__file__).resolve().parent
KNOWN_BUILDS_TSV = HERE / "known-builds.tsv"

# Files code generation actually needs; non-PE files are skipped under --quick
TARGET_MODULES = ("EDF.dll", "EDF6.exe", "Root.cpk", "Chunk01.cpk", "Chunk02.cpk", "DX11.cpk")
PE_MODULES = ("EDF.dll", "EDF6.exe")

EXIT_OFFICIAL = 0
EXIT_UNOFFICIAL = 2
EXIT_UNDECIDED = 3

# ---------------------------------------------------------------------------
# Minimal protobuf decoder
# ---------------------------------------------------------------------------


class ProtoError(ValueError):
    pass


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ProtoError("varint out of range")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtoError("varint too long")


def iter_fields(buf: bytes):
    """Yield (field_no, wire_type, value) one by one. value: int for varint/fixed, bytes for length-delimited."""
    pos = 0
    n = len(buf)
    while pos < n:
        key, pos = _read_varint(buf, pos)
        field, wt = key >> 3, key & 7
        if field == 0:
            raise ProtoError("field number is 0")
        if wt == 0:
            val, pos = _read_varint(buf, pos)
        elif wt == 1:
            if pos + 8 > n:
                raise ProtoError("fixed64 out of range")
            val = struct.unpack_from("<Q", buf, pos)[0]
            pos += 8
        elif wt == 2:
            ln, pos = _read_varint(buf, pos)
            if pos + ln > n:
                raise ProtoError("length-delimited out of range")
            val = bytes(buf[pos:pos + ln])
            pos += ln
        elif wt == 5:
            if pos + 4 > n:
                raise ProtoError("fixed32 out of range")
            val = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
        else:
            raise ProtoError(f"unsupported wire type {wt}")
        yield field, wt, val


# ---------------------------------------------------------------------------
# Steam depot manifest
# ---------------------------------------------------------------------------

MAGIC_PAYLOAD = 0x71F617D0
MAGIC_METADATA = 0x1F4812BE
MAGIC_SIGNATURE = 0x1B81B817
MAGIC_END = 0x32C415AB

FLAG_DIRECTORY = 0x40
FLAG_SYMLINK = 0x200


def _parse_mapping(buf: bytes) -> dict:
    m = {"filename": "", "size": 0, "flags": 0, "sha_filename": b"", "sha_content": b"",
         "chunks": 0, "linktarget": ""}
    for f, _wt, v in iter_fields(buf):
        if f == 1:
            m["filename"] = v.decode("utf-8", "replace")
        elif f == 2:
            m["size"] = v
        elif f == 3:
            m["flags"] = v
        elif f == 4:
            m["sha_filename"] = v
        elif f == 5:
            m["sha_content"] = v
        elif f == 6:
            m["chunks"] += 1
        elif f == 7:
            m["linktarget"] = v.decode("utf-8", "replace")
    return m


def parse_manifest_bytes(data: bytes) -> dict:
    """Parse a depot manifest binary (a zip wrapper downloaded from the CDN is also accepted)."""
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            data = zf.read(zf.namelist()[0])
    pos = 0
    mappings: list[dict] = []
    meta: dict = {}
    signature = b""
    saw_payload = saw_end = False
    while pos + 4 <= len(data):
        magic = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if magic == MAGIC_END:
            saw_end = True
            break
        if pos + 4 > len(data):
            raise ProtoError("section length out of range")
        ln = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if pos + ln > len(data):
            raise ProtoError(f"section 0x{magic:08X} length {ln} exceeds the file")
        body = data[pos:pos + ln]
        pos += ln
        if magic == MAGIC_PAYLOAD:
            saw_payload = True
            for f, wt, v in iter_fields(body):
                if f == 1 and wt == 2:
                    mappings.append(_parse_mapping(v))
        elif magic == MAGIC_METADATA:
            names = {1: "depot_id", 2: "gid_manifest", 3: "creation_time", 4: "filenames_encrypted",
                     5: "cb_disk_original", 6: "cb_disk_compressed", 7: "unique_chunks",
                     8: "crc_encrypted", 9: "crc_clear"}
            for f, _wt, v in iter_fields(body):
                if f in names:
                    meta[names[f]] = v
        elif magic == MAGIC_SIGNATURE:
            for f, _wt, v in iter_fields(body):
                if f == 1:
                    signature = v
        else:
            raise ProtoError(f"unknown section magic 0x{magic:08X}")
    if not saw_payload:
        raise ProtoError("missing payload section")
    meta["filenames_encrypted"] = bool(meta.get("filenames_encrypted", False))
    return {"metadata": meta, "mappings": mappings, "has_signature": bool(signature),
            "has_end_marker": saw_end}


def parse_manifest_file(path: Path) -> dict:
    m = parse_manifest_bytes(Path(path).read_bytes())
    m["path"] = str(path)
    return m


def norm_name(name: str) -> str:
    return name.replace("/", "\\").strip("\\").lower()


def sha_filename_of(name: str) -> bytes:
    """Steam's sha_filename = SHA1(lower-case relative path with backslash separators)."""
    return hashlib.sha1(norm_name(name).encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# VDF (appmanifest_*.acf)
# ---------------------------------------------------------------------------

_VDF_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([{}])|//[^\n]*')


def parse_vdf(text: str) -> dict:
    stack: list[dict] = [{}]
    key = None
    for m in _VDF_TOKEN.finditer(text):
        s, brace = m.group(1), m.group(2)
        if s is None and brace is None:
            continue  # comment
        if brace == "{":
            if key is None:
                raise ValueError("VDF: no key before '{'")
            d: dict = {}
            stack[-1][key] = d
            stack.append(d)
            key = None
        elif brace == "}":
            if len(stack) == 1:
                raise ValueError("VDF: extra '}'")
            stack.pop()
            key = None
        else:
            s = s.replace("\\\\", "\\").replace('\\"', '"')
            if key is None:
                key = s
            else:
                stack[-1][key] = s
                key = None
    return stack[0]


def _find_steamapps(game_dir: Path) -> Path | None:
    for p in [game_dir, *game_dir.parents]:
        if p.name.lower() == "steamapps":
            return p
    return None


def locate_manifests(game_dir: Path, steam_root: Path | None = None,
                     manifests: list[Path] | None = None) -> dict:
    """Return {'acf': path|None, 'buildid': str|None, 'depots': {depot: manifest_id},
    'files': [manifest paths], 'notes': [...]}"""
    info: dict = {"acf": None, "buildid": None, "depots": {}, "files": [], "notes": []}
    if manifests:
        info["files"] = [Path(p) for p in manifests]
        info["notes"].append("manifest given explicitly with --manifest")
    steamapps = None
    if steam_root:
        steamapps = Path(steam_root) / "steamapps"
    else:
        steamapps = _find_steamapps(game_dir)
    acf = steamapps / f"appmanifest_{APP_ID}.acf" if steamapps else None
    if acf and acf.is_file():
        info["acf"] = str(acf)
        try:
            st = parse_vdf(acf.read_text(encoding="utf-8", errors="replace")).get("AppState", {})
        except ValueError as e:
            info["notes"].append(f"failed to parse appmanifest: {e}")
            st = {}
        info["buildid"] = st.get("buildid")
        if st.get("installdir") and st["installdir"].lower() != game_dir.name.lower():
            info["notes"].append(f"appmanifest installdir={st['installdir']!r} does not match the directory name")
        for depot, d in (st.get("InstalledDepots") or {}).items():
            if isinstance(d, dict) and d.get("manifest"):
                info["depots"][depot] = d["manifest"]
        if not manifests:
            root = Path(steam_root) if steam_root else steamapps.parent
            # When the library folder is not the Steam root, depotcache only exists in the main Steam directory; try both
            cands = [root / "depotcache"]
            for depot, mid in info["depots"].items():
                fn = f"{depot}_{mid}.manifest"
                hit = next((c / fn for c in cands if (c / fn).is_file()), None)
                if hit:
                    info["files"].append(hit)
                else:
                    info["notes"].append(f"{fn} not found in depotcache (use --steam-root / --manifest)")
    elif not manifests:
        info["notes"].append("steamapps/appmanifest_2291060.acf not found (not a Steam install, or the directory was copied out)")
    return info


# ---------------------------------------------------------------------------
# known-builds.tsv
# ---------------------------------------------------------------------------

KNOWN_BUILDS_COLUMNS = ("module", "sha256", "sha1", "size", "TimeDateStamp", "image_base",
                        "steam_buildid", "depot", "manifest_id", "note")


def load_known_builds(path: Path = KNOWN_BUILDS_TSV) -> list[dict]:
    rows = []
    if not Path(path).is_file():
        return rows
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    header = None
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if header is None:
            header = cols
            continue
        row = dict(zip(header, cols))
        row["sha256"] = row.get("sha256", "").lower()
        row["sha1"] = row.get("sha1", "").lower()
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# File hashes and PE
# ---------------------------------------------------------------------------


def hash_file(path: Path, progress: bool = True, label: str | None = None) -> tuple[str, str, int]:
    """Stream-compute (sha256, sha1, size). Large files print progress to stderr every 2 seconds."""
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    total = os.path.getsize(path)
    done = 0
    buf = bytearray(8 << 20)
    mv = memoryview(buf)
    t0 = last = time.monotonic()
    label = label or Path(path).name
    with open(path, "rb", buffering=0) as f:
        while True:
            n = f.readinto(buf)
            if not n:
                break
            h256.update(mv[:n])
            h1.update(mv[:n])
            done += n
            now = time.monotonic()
            if progress and now - last >= 2.0:
                rate = done / max(now - t0, 1e-6) / 2**20
                print(f"[hash] {label} {done / 2**30:.2f}/{total / 2**30:.2f} GiB "
                      f"{100 * done / max(total, 1):.1f}% {rate:.0f} MiB/s", file=sys.stderr, flush=True)
                last = now
    if progress and total >= 64 << 20:
        print(f"[hash] {label} done {done / 2**30:.2f} GiB in {time.monotonic() - t0:.0f}s",
              file=sys.stderr, flush=True)
    return h256.hexdigest(), h1.hexdigest(), done


def pe_info(path: Path) -> dict | None:
    try:
        with open(path, "rb") as f:
            d = f.read(4096)
        if d[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            return None
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        ts = struct.unpack_from("<I", d, pe + 8)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        magic = struct.unpack_from("<H", d, pe + 24)[0]
        image_base = (struct.unpack_from("<Q", d, pe + 24 + 24)[0] if magic == 0x20B
                      else struct.unpack_from("<I", d, pe + 24 + 28)[0])
        sec0 = pe + 24 + optsz
        sections = [d[sec0 + i * 40:sec0 + i * 40 + 8].rstrip(b"\0").decode("latin-1")
                    for i in range(nsec) if sec0 + i * 40 + 8 <= len(d)]
        return {"TimeDateStamp": f"0x{ts:08X}", "image_base": f"0x{image_base:X}",
                "sections": sections, "has_bind": ".bind" in sections}
    except (OSError, struct.error):
        return None


# ---------------------------------------------------------------------------
# Third-party file recognition
# ---------------------------------------------------------------------------

# (lower-case file/dir name, owner, description)
THIRD_PARTY_NAMES = [
    ("cream_api.ini", "CreamAPI", "DLC unlock config"),
    ("steam_api64_o.dll", "CreamAPI", "original steam_api64.dll kept by CreamAPI under a new name"),
    ("steam_api_o.dll", "CreamAPI", "original steam_api.dll kept by CreamAPI under a new name"),
    ("creamapi.dll", "CreamAPI", ""),
    ("winmm.dll", "EDFModLoader", "proxy DLL loader"),
    ("modloader.ini", "EDFModLoader", ""),
    ("modloader.log", "EDFModLoader", ""),
    ("edfmodloader", "EDFModLoader", ""),
    ("mods", "EDFModLoader", "Mods directory"),
    ("mod.dll", "third-party mod", "not in the Steam manifest"),
    ("mod.cpk", "third-party mod", "not in the Steam manifest"),
    ("epicdf61.exe", "Epic edition", "Epic main executable (a different build from Steam)"),
    ("steam_settings", "Goldberg Steam emulator", ""),
    ("steam_emu.ini", "Steam emulator (CODEX/RUNE etc.)", ""),
    ("steam_appid.txt", "Steam emulator / debugging", ""),
    ("local_save.txt", "Goldberg Steam emulator", ""),
    ("onlinefix.ini", "Online-Fix", ""),
    ("onlinefix64.dll", "Online-Fix", ""),
    ("smartsteamemu.ini", "SmartSteamEmu", ""),
    ("ali213.ini", "ALI213 emulator", ""),
    ("3dmgame.ini", "3DM emulator", ""),
    ("dinput8.dll", "proxy DLL injection", ""),
    ("d3d11.dll", "proxy DLL injection (ReShade/SpecialK etc.)", ""),
    ("dxgi.dll", "proxy DLL injection (ReShade/SpecialK etc.)", ""),
    ("version.dll", "proxy DLL injection", ""),
    ("reshade.ini", "ReShade", ""),
]
_STEAMLESS_PAT = re.compile(r"(\.unpacked\.(exe|dll)$)|(\.(exe|dll)\.(bak|orig|original)$)|(_o\.exe$)",
                            re.I)


def scan_third_party(game_dir: Path, manifest_names: set[str] | None) -> list[dict]:
    found = []
    try:
        entries = sorted(os.scandir(game_dir), key=lambda e: e.name.lower())
    except OSError:
        return found
    table = {n: (who, why) for n, who, why in THIRD_PARTY_NAMES}
    for e in entries:
        low = e.name.lower()
        if manifest_names is not None and low in manifest_names:
            continue  # files in the manifest: handled by the hash check
        kind = "dir" if e.is_dir() else "file"
        if low in table:
            who, why = table[low]
            found.append({"name": e.name, "kind": kind, "origin": who, "detail": why})
        elif _STEAMLESS_PAT.search(low):
            found.append({"name": e.name, "kind": kind, "origin": "Steamless / manual backup leftover",
                          "detail": "backup file name from before unpacking or replacement"})
        elif manifest_names is not None:
            found.append({"name": e.name, "kind": kind, "origin": "unknown", "detail": "not in the Steam manifest"})
    return found


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def verify(game_dir, quick: bool = False, steam_root=None, manifests=None,
           modules=TARGET_MODULES, known_builds_path: Path = KNOWN_BUILDS_TSV,
           progress: bool = True) -> dict:
    """Verify game_dir and return a provenance dict (see the --json output). Never writes to the game directory."""
    game_dir = Path(game_dir).resolve()
    t0 = time.time()
    res: dict = {
        "tool": "verify_install.py", "schema": 1, "time": _now_iso(), "game_dir": str(game_dir),
        "quick": bool(quick), "app_id": APP_ID, "steam": {}, "files": [], "missing_from_install": [],
        "size_mismatch": [], "third_party": [], "warnings": [], "verdict": None, "exit_code": None,
    }
    if not game_dir.is_dir():
        res["verdict"] = "undecided"
        res["exit_code"] = EXIT_UNDECIDED
        res["warnings"].append(f"directory does not exist: {game_dir}")
        return res

    loc = locate_manifests(game_dir, steam_root, manifests)
    res["steam"] = {"appmanifest": loc["acf"], "buildid": loc["buildid"], "depots": loc["depots"],
                    "manifests": []}
    res["warnings"].extend(loc["notes"])

    by_name: dict[str, dict] = {}      # lower-case name -> mapping (plain-text manifest)
    by_sha_filename: dict[bytes, dict] = {}
    any_encrypted = False
    parsed_any = False
    for mpath in loc["files"]:
        try:
            man = parse_manifest_file(mpath)
        except (OSError, ProtoError, zipfile.BadZipFile) as e:
            res["warnings"].append(f"failed to parse manifest {mpath}: {e}")
            continue
        parsed_any = True
        meta = man["metadata"]
        depot = str(meta.get("depot_id", ""))
        gid = str(meta.get("gid_manifest", ""))
        mi = {"path": str(mpath), "depot": depot, "manifest_id": gid,
              "creation_time": meta.get("creation_time"),
              "filenames_encrypted": meta["filenames_encrypted"], "files": len(man["mappings"]),
              "has_signature": man["has_signature"]}
        res["steam"]["manifests"].append(mi)
        if loc["depots"] and depot in loc["depots"] and loc["depots"][depot] != gid:
            res["warnings"].append(f"manifest {mpath} gid {gid} does not match the "
                                   f"{loc['depots'][depot]} recorded by appmanifest")
        if meta["filenames_encrypted"]:
            any_encrypted = True
            res["warnings"].append(f"depot {depot} manifest file names are encrypted: cannot check by name, "
                                   "matching entries by sha_filename (file-name hash) only")
        for m in man["mappings"]:
            m = dict(m, depot=depot, manifest_id=gid)
            if m["sha_filename"]:
                by_sha_filename[m["sha_filename"]] = m
            if not meta["filenames_encrypted"]:
                by_name[norm_name(m["filename"])] = m
    have_manifest = parsed_any

    # Files in the manifest: existence and size (stat only, no hashing)
    manifest_top_names: set[str] | None = None
    if have_manifest and not any_encrypted:
        manifest_top_names = set()
        for low, m in by_name.items():
            manifest_top_names.add(low.split("\\", 1)[0])
            if m["flags"] & FLAG_DIRECTORY:
                continue
            p = game_dir / m["filename"].replace("\\", os.sep)
            if not p.exists():
                res["missing_from_install"].append(m["filename"])
            elif not (m["flags"] & FLAG_SYMLINK) and p.is_file() and p.stat().st_size != m["size"]:
                res["size_mismatch"].append({"name": m["filename"], "expected": m["size"],
                                             "actual": p.stat().st_size})

    known = load_known_builds(known_builds_path)
    known_by_sha256 = {(r["module"].lower(), r["sha256"].lower()): r for r in known if r.get("sha256")}
    known_modules = {r["module"].lower() for r in known}
    known_ts = {(r["module"].lower(), r.get("TimeDateStamp", "").upper()) for r in known}

    for mod in modules:
        p = game_dir / mod
        is_pe = mod.lower().endswith((".dll", ".exe"))
        ent: dict = {"module": mod, "path": str(p), "sha256": None, "sha1": None, "size": None,
                     "verdict": None, "basis": None, "detail": ""}
        res["files"].append(ent)
        ref = by_name.get(norm_name(mod)) or by_sha_filename.get(sha_filename_of(mod))
        if not p.is_file():
            ent["verdict"] = "missing"
            ent["detail"] = "file does not exist"
            continue
        ent["size"] = p.stat().st_size
        if quick and not is_pe:
            ent["verdict"] = "unchecked"
            ent["detail"] = "--quick: not checked"
            if ref is not None and ref["size"] != ent["size"]:
                ent["detail"] += f" (but the size differs from the manifest: manifest {ref['size']})"
            continue
        ent["sha256"], ent["sha1"], _ = hash_file(p, progress=progress, label=mod)
        if is_pe:
            pi = pe_info(p)
            if pi:
                ent["pe"] = pi
        kb = known_by_sha256.get((mod.lower(), ent["sha256"]))
        ent["known_build"] = ({"steam_buildid": kb.get("steam_buildid"), "note": kb.get("note")}
                              if kb else None)
        if have_manifest and ref is not None:
            if ref["sha_content"].hex() == ent["sha1"] and ref["size"] == ent["size"]:
                ent["verdict"] = "official"
                ent["basis"] = f"depot-manifest:{ref['depot']}/{ref['manifest_id']}"
                if is_pe and kb is None:
                    # Address-bound builds: a PE counts only if its SHA-256 is registered in known-builds
                    ent["verdict"] = "unregistered"
                    ent["detail"] = ("Steam new build, not registered: matches the Steam manifest but its SHA-256 is not in known-builds.tsv; "
                                     "once confirmed, register it in known-builds.tsv and shared/builds.tsv via a PR")
                elif kb is not None:
                    ent["basis"] += "+known-builds"
            else:
                ent["verdict"] = "modified"
                ent["basis"] = f"depot-manifest:{ref['depot']}/{ref['manifest_id']}"
                ent["detail"] = (f"SHA1 / size differs from the manifest (manifest {ref['sha_content'].hex()}, "
                                 f"{ref['size']} bytes)")
                if kb is not None:
                    # The file itself is a known genuine build; only the local Steam manifest is for another build
                    ent["verdict"] = "official"
                    ent["basis"] = "known-builds"
                    ent["detail"] = (f"differs from the local Steam manifest but matches known-builds (buildid "
                                     f"{kb.get('steam_buildid')})")
            ent["expected_sha1"] = ref["sha_content"].hex()
            ent["expected_size"] = ref["size"]
        elif kb is not None:
            ent["verdict"] = "official"
            ent["basis"] = "known-builds"
        elif mod.lower() in known_modules:
            ent["verdict"] = "modified"
            ent["basis"] = "known-builds"
            ent["detail"] = "SHA-256 matches none of the known genuine builds in known-builds"
        elif have_manifest:
            ent["verdict"] = "modified" if not any_encrypted else "unknown"
            ent["basis"] = "depot-manifest"
            ent["detail"] = ("not in the Steam manifest" if not any_encrypted
                             else "manifest file names are encrypted; this file was not found by sha_filename")
        else:
            ent["verdict"] = "unknown"
            ent["detail"] = "no Steam manifest, and known-builds has no entry for this module"
        if is_pe and ent["verdict"] == "modified" and ent.get("pe"):
            pi = ent["pe"]
            if (mod.lower(), pi["TimeDateStamp"].upper()) in known_ts and not pi["has_bind"]:
                ent["detail"] += "; same timestamp as the genuine build but different hash (probably unpacked by Steamless or patched)"
            elif pi["has_bind"]:
                ent["detail"] += "; has a SteamStub .bind section"

    # Third-party files
    res["third_party"] = scan_third_party(game_dir, manifest_top_names)
    # steam_api64.dll that is in the manifest but was replaced (a CreamAPI sign)
    if have_manifest:
        for api in ("steam_api64.dll", "steam_api.dll"):
            ref = by_name.get(api)
            p = game_dir / api
            if ref and p.is_file():
                _, s1, _ = hash_file(p, progress=False)
                if s1 != ref["sha_content"].hex():
                    orig = game_dir / (api[:-4] + "_o.dll")
                    detail = "hash differs from the Steam manifest (replaced)"
                    if orig.is_file() and hash_file(orig, progress=False)[1] == ref["sha_content"].hex():
                        detail += f"; {orig.name} matches the manifest original"
                    res["third_party"].append({"name": api, "kind": "file", "origin": "CreamAPI / Steam emulator",
                                               "detail": detail})

    # Summary
    vs = [f["verdict"] for f in res["files"]]
    if any(v in ("modified", "missing") for v in vs):
        verdict, code = "unofficial", EXIT_UNOFFICIAL
    elif any(v == "unknown" for v in vs):
        verdict, code = "undecided", EXIT_UNDECIDED
    elif any(v == "unregistered" for v in vs):
        verdict, code = "unregistered", EXIT_UNDECIDED
    elif not any(v == "official" for v in vs):
        verdict, code = "undecided", EXIT_UNDECIDED
    else:
        verdict, code = "official", EXIT_OFFICIAL
    res["verdict"] = verdict
    res["exit_code"] = code
    res["quick"] = bool(quick)
    res["elapsed_s"] = round(time.time() - t0, 1)
    return res


class UnofficialInstallError(RuntimeError):
    def __init__(self, message: str, result: dict):
        super().__init__(message)
        self.result = result


def require_official(game_dir, modules, allow_unofficial: bool = False, **kw) -> dict:
    """Pre-generation gate: check only `modules` (e.g. ['EDF.dll']); raise UnofficialInstallError if not official.
    With allow_unofficial=True it only warns on stderr and returns the result (the verdict is recorded as is)."""
    kw.setdefault("progress", True)
    tool = kw.pop("tool", None)
    res = verify(game_dir, quick=False, modules=tuple(modules), **kw)
    res["gate"] = {"tool": tool, "modules": list(modules), "allow_unofficial": bool(allow_unofficial),
                   "argv": list(sys.argv)}
    res["unofficial_allowed"] = False
    if res["verdict"] != "official":
        bad = "; ".join(f"{f['module']}={f['verdict']}" + (f" ({f['detail']})" if f["detail"] else "")
                        for f in res["files"] if f["verdict"] != "official")
        msg = f"game files are not a confirmable official original: {bad or res['verdict']}"
        if res["verdict"] == "unregistered":
            msg += f"\n{REGISTER_HINT}"
        if not allow_unofficial:
            raise UnofficialInstallError(msg, res)
        res["unofficial_allowed"] = True
        print(f"[verify_install] warning (--allow-unofficial): {msg}", file=sys.stderr)
    else:
        basis = ", ".join(f"{f['module']}←{f['basis']}" for f in res["files"])
        print(f"[verify_install] official original: {basis}", file=sys.stderr)
    return res


REGISTER_HINT = ("This is a new build accepted by the Steam manifest but not yet registered in the repository: once confirmed, open a PR registering it in known-builds.tsv "
                 "and shared/builds.tsv; until then it can only be let through with --allow-unofficial (the output will be marked as an unregistered build).")


def _utf8_stderr() -> None:
    """Write gate / warning text to stderr as UTF-8 in pipes (the console already uses wide characters)."""
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def gate_or_exit(parser, game_dir, modules, allow_unofficial: bool = False, tool: str | None = None,
                 **kw) -> dict:
    """For command-line scripts: require_official; if it fails, parser.exit (exit code 2 / 3) with a hint about --allow-unofficial."""
    _utf8_stderr()
    try:
        return require_official(game_dir, modules, allow_unofficial=allow_unofficial, tool=tool, **kw)
    except UnofficialInstallError as e:
        parser.exit(e.result.get("exit_code") or EXIT_UNOFFICIAL,
                    f"{e}\nAdd --allow-unofficial if you really want to generate from these files (it is recorded in the output's provenance.json).\n")


PROVENANCE_NAME = "provenance.json"


def provenance_path(output: Path) -> Path:
    """Output is a directory -> <dir>/provenance.json; output is a single file -> <file name>.provenance.json."""
    output = Path(output)
    return output / PROVENANCE_NAME if output.is_dir() else output.with_name(output.name + "." + PROVENANCE_NAME)


def write_provenance(output: Path, res: dict) -> Path:
    p = provenance_path(output)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def read_provenance(output: Path) -> dict | None:
    p = provenance_path(output)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def provenance_warnings(provenance: dict | None = None, image_hashes: dict | None = None,
                        known_builds_path: Path = KNOWN_BUILDS_TSV) -> list[str]:
    """For query commands: the output does not come from a genuine build in known-builds, or provenance marks it unofficial -> list of warning texts.
    image_hashes: {module: sha256} (e.g. the image table of vanilla.sqlite)."""
    out = []
    known = {r["sha256"]: r for r in load_known_builds(known_builds_path) if r.get("sha256")}
    for module, sha in sorted((image_hashes or {}).items()):
        if (sha or "").lower() not in known:
            out.append(f"{module} SHA-256 {sha} is not in known-builds.tsv (not a known official build)")
    if provenance:
        if provenance.get("verdict") != "official":
            out.append(f"judged at generation time as {_OVERALL_EN.get(provenance.get('verdict'), provenance.get('verdict'))}"
                       + (", forced through with --allow-unofficial" if provenance.get("unofficial_allowed")
                          or (provenance.get("gate") or {}).get("allow_unofficial") else ""))
        for f in provenance.get("files", []):
            if f.get("sha256") and f["sha256"].lower() not in known and not (image_hashes or {}).get(f["module"]):
                out.append(f"{f['module']} SHA-256 {f['sha256']} is not in known-builds.tsv")
    return out


def print_provenance_warnings(warnings: list[str], stream=None) -> None:
    if stream is None:
        _utf8_stderr()
        stream = sys.stderr
    for w in warnings:
        print(f"warning: the output does not come from a known official build: {w}", file=stream, flush=True)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_VERDICT_EN = {"official": "official", "modified": "modified / mismatch", "missing": "missing", "unchecked": "not checked",
               "unknown": "no basis", "unregistered": "Steam new build, not registered"}
_OVERALL_EN = {"official": "official original", "unofficial": "unofficial or modified", "undecided": "undecided",
               "unregistered": "Steam new build, not registered"}


def overall_text(res: dict) -> str:
    """Overall verdict as text. Under --quick the CPKs are not hashed, so "official" only goes as far as the PEs."""
    if res.get("verdict") == "official" and any(f["verdict"] == "unchecked" for f in res.get("files", [])):
        return "PEs official, CPKs not checked"
    return _OVERALL_EN.get(res.get("verdict"), res.get("verdict"))


def format_summary(res: dict) -> str:
    out = []
    out.append(f"Game directory: {res['game_dir']}")
    st = res.get("steam") or {}
    if st.get("appmanifest"):
        out.append(f"Steam appmanifest: {st['appmanifest']} (buildid {st.get('buildid')})")
    for m in st.get("manifests", []):
        out.append(f"  depot {m['depot']} manifest {m['manifest_id']}: {m['files']} entries"
                   + (", file names encrypted" if m["filenames_encrypted"] else ""))
    if not st.get("manifests"):
        out.append("Steam depot manifest: none (falling back to known-builds.tsv)")
    out.append("Core files:")
    for f in res["files"]:
        line = f"  {f['module']:<12} {_VERDICT_EN.get(f['verdict'], f['verdict'])}"
        if f.get("basis"):
            line += f"  basis {f['basis']}"
        if f.get("sha1"):
            line += f"  sha1 {f['sha1']}"
        if f.get("detail"):
            line += f"  {f['detail']}"
        out.append(line)
    if res["missing_from_install"]:
        out.append(f"In the manifest but missing from the directory ({len(res['missing_from_install'])}):")
        out.extend(f"  {n}" for n in res["missing_from_install"][:50])
    if res["size_mismatch"]:
        out.append(f"Size differs from the manifest ({len(res['size_mismatch'])}, warning only):")
        out.extend(f"  {s['name']}: manifest {s['expected']}, actual {s['actual']}" for s in res["size_mismatch"][:50])
    if res["third_party"]:
        out.append(f"Third-party / files outside the manifest ({len(res['third_party'])}, warning only):")
        out.extend(f"  {t['name']}{'/' if t['kind'] == 'dir' else ''}  [{t['origin']}] {t['detail']}".rstrip()
                   for t in res["third_party"])
    for w in res["warnings"]:
        out.append(f"Warning: {w}")
    out.append(f"Verdict: {overall_text(res)} (exit code {res['exit_code']})")
    if res["verdict"] == "unregistered":
        out.append(REGISTER_HINT)
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check whether the EDF6 install is the official original build")
    ap.add_argument("game_dir")
    ap.add_argument("--quick", action="store_true", help="check only the PEs (EDF.dll / EDF6.exe); CPKs are marked not checked")
    ap.add_argument("--json", metavar="PATH", help="write provenance JSON")
    ap.add_argument("--steam-root", metavar="DIR", help="Steam root directory (containing steamapps/ and depotcache/)")
    ap.add_argument("--manifest", metavar="FILE", action="append", help="depot manifest to use explicitly; may be repeated")
    ap.add_argument("--known-builds", metavar="TSV", default=str(KNOWN_BUILDS_TSV))
    ap.add_argument("--module", action="append", metavar="NAME",
                    help="check only these files (may be repeated; default EDF.dll EDF6.exe and the 4 CPKs)")
    ap.add_argument("--allow-unofficial", action="store_true",
                    help="only record in the JSON that the caller let unofficial files through; the exit code is returned as is")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    res = verify(args.game_dir, quick=args.quick, steam_root=args.steam_root,
                 manifests=[Path(p) for p in args.manifest] if args.manifest else None,
                 modules=tuple(args.module) if args.module else TARGET_MODULES,
                 known_builds_path=Path(args.known_builds))
    res["gate"] = {"tool": "verify_install.py", "modules": [f["module"] for f in res["files"]],
                   "allow_unofficial": args.allow_unofficial, "argv": list(sys.argv)}
    res["unofficial_allowed"] = bool(args.allow_unofficial and res["verdict"] != "official")
    print(format_summary(res))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    return res["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
