#!/usr/bin/env python3
"""核对本机 EDF6 安装是否为官方原版（生成汇编 / 伪代码 / 任务脚本索引前的闸门）。

依据：
  - PE 模块（EDF.dll / EDF6.exe）判官方只认 known-builds.tsv 的 SHA-256（模块名也要一致）。
    生成结果的地址绑定具体构建，未登记的构建即使与 Steam 清单一致也不放行：
    判为「Steam 新构建，未登记」（unregistered，退出码 3），需要时 --allow-unofficial 放行，
    并去 PR 把它登记进 known-builds.tsv 与 shared/builds.tsv。
  - 其余文件（CPK）按 Steam depot 清单（depotcache/<depot>_<manifest>.manifest）里同名条目的 SHA1，
    或 known-builds.tsv 的 SHA-256。清单由 steamapps/appmanifest_2291060.acf 的 InstalledDepots 定位。
    清单文件名加密时只按 sha_filename（文件名哈希）找对应条目，不做跨文件的 SHA1 集合匹配。
  对不上 → 非官方。

只用标准库；只读游戏目录，不写入。

命令行：
  python verify_install.py "<游戏目录>" [--quick] [--json PATH] [--steam-root DIR] [--manifest FILE ...]
退出码：0 官方（--quick 时为「PE 官方，CPK 未核对」），2 非官方或被改，
        3 无法判定（缺依据 / Steam 新构建未登记）。

可 import：
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

# 代码生成实际要用的文件；PE 之外的在 --quick 下跳过
TARGET_MODULES = ("EDF.dll", "EDF6.exe", "Root.cpk", "Chunk01.cpk", "Chunk02.cpk", "DX11.cpk")
PE_MODULES = ("EDF.dll", "EDF6.exe")

EXIT_OFFICIAL = 0
EXIT_UNOFFICIAL = 2
EXIT_UNDECIDED = 3

# ---------------------------------------------------------------------------
# 最小 protobuf 解码
# ---------------------------------------------------------------------------


class ProtoError(ValueError):
    pass


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ProtoError("varint 越界")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtoError("varint 过长")


def iter_fields(buf: bytes):
    """逐个产出 (field_no, wire_type, value)。value：varint/fixed 为 int，length-delimited 为 bytes。"""
    pos = 0
    n = len(buf)
    while pos < n:
        key, pos = _read_varint(buf, pos)
        field, wt = key >> 3, key & 7
        if field == 0:
            raise ProtoError("字段号为 0")
        if wt == 0:
            val, pos = _read_varint(buf, pos)
        elif wt == 1:
            if pos + 8 > n:
                raise ProtoError("fixed64 越界")
            val = struct.unpack_from("<Q", buf, pos)[0]
            pos += 8
        elif wt == 2:
            ln, pos = _read_varint(buf, pos)
            if pos + ln > n:
                raise ProtoError("length-delimited 越界")
            val = bytes(buf[pos:pos + ln])
            pos += ln
        elif wt == 5:
            if pos + 4 > n:
                raise ProtoError("fixed32 越界")
            val = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
        else:
            raise ProtoError(f"不支持的 wire type {wt}")
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
    """解析 depot manifest 二进制（也接受 CDN 下载的 zip 包装）。"""
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
            raise ProtoError("section 长度越界")
        ln = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if pos + ln > len(data):
            raise ProtoError(f"section 0x{magic:08X} 长度 {ln} 超出文件")
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
            raise ProtoError(f"未知 section 魔数 0x{magic:08X}")
    if not saw_payload:
        raise ProtoError("缺少 payload section")
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
    """Steam 的 sha_filename = SHA1(小写、反斜杠分隔的相对路径)。"""
    return hashlib.sha1(norm_name(name).encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# VDF（appmanifest_*.acf）
# ---------------------------------------------------------------------------

_VDF_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([{}])|//[^\n]*')


def parse_vdf(text: str) -> dict:
    stack: list[dict] = [{}]
    key = None
    for m in _VDF_TOKEN.finditer(text):
        s, brace = m.group(1), m.group(2)
        if s is None and brace is None:
            continue  # 注释
        if brace == "{":
            if key is None:
                raise ValueError("VDF：'{' 前没有键")
            d: dict = {}
            stack[-1][key] = d
            stack.append(d)
            key = None
        elif brace == "}":
            if len(stack) == 1:
                raise ValueError("VDF：多余的 '}'")
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
    """返回 {'acf': path|None, 'buildid': str|None, 'depots': {depot: manifest_id},
    'files': [manifest paths], 'notes': [...]}"""
    info: dict = {"acf": None, "buildid": None, "depots": {}, "files": [], "notes": []}
    if manifests:
        info["files"] = [Path(p) for p in manifests]
        info["notes"].append("清单由 --manifest 显式指定")
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
            info["notes"].append(f"appmanifest 解析失败：{e}")
            st = {}
        info["buildid"] = st.get("buildid")
        if st.get("installdir") and st["installdir"].lower() != game_dir.name.lower():
            info["notes"].append(f"appmanifest 的 installdir={st['installdir']!r} 与目录名不一致")
        for depot, d in (st.get("InstalledDepots") or {}).items():
            if isinstance(d, dict) and d.get("manifest"):
                info["depots"][depot] = d["manifest"]
        if not manifests:
            root = Path(steam_root) if steam_root else steamapps.parent
            # 库文件夹不在 Steam 根时 depotcache 只在主 Steam 目录；两处都试
            cands = [root / "depotcache"]
            for depot, mid in info["depots"].items():
                fn = f"{depot}_{mid}.manifest"
                hit = next((c / fn for c in cands if (c / fn).is_file()), None)
                if hit:
                    info["files"].append(hit)
                else:
                    info["notes"].append(f"depotcache 里找不到 {fn}（可用 --steam-root / --manifest 指定）")
    elif not manifests:
        info["notes"].append("找不到 steamapps/appmanifest_2291060.acf（非 Steam 安装或目录被拷出）")
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
# 文件哈希与 PE
# ---------------------------------------------------------------------------


def hash_file(path: Path, progress: bool = True, label: str | None = None) -> tuple[str, str, int]:
    """流式算 (sha256, sha1, size)。大文件每 2 秒往 stderr 打进度。"""
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
        print(f"[hash] {label} 完成 {done / 2**30:.2f} GiB 用时 {time.monotonic() - t0:.0f}s",
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
# 第三方文件识别
# ---------------------------------------------------------------------------

# (小写文件/目录名, 归属, 说明)
THIRD_PARTY_NAMES = [
    ("cream_api.ini", "CreamAPI", "DLC 解锁配置"),
    ("steam_api64_o.dll", "CreamAPI", "CreamAPI 改名保留的原版 steam_api64.dll"),
    ("steam_api_o.dll", "CreamAPI", "CreamAPI 改名保留的原版 steam_api.dll"),
    ("creamapi.dll", "CreamAPI", ""),
    ("winmm.dll", "EDFModLoader", "代理 DLL 加载器"),
    ("modloader.ini", "EDFModLoader", ""),
    ("modloader.log", "EDFModLoader", ""),
    ("edfmodloader", "EDFModLoader", ""),
    ("mods", "EDFModLoader", "Mods 目录"),
    ("mod.dll", "第三方 Mod", "非 Steam 清单文件"),
    ("mod.cpk", "第三方 Mod", "非 Steam 清单文件"),
    ("epicdf61.exe", "Epic 版", "Epic 版主程序（与 Steam 版不同构建）"),
    ("steam_settings", "Goldberg Steam 模拟器", ""),
    ("steam_emu.ini", "Steam 模拟器（CODEX/RUNE 等）", ""),
    ("steam_appid.txt", "Steam 模拟器 / 调试", ""),
    ("local_save.txt", "Goldberg Steam 模拟器", ""),
    ("onlinefix.ini", "Online-Fix", ""),
    ("onlinefix64.dll", "Online-Fix", ""),
    ("smartsteamemu.ini", "SmartSteamEmu", ""),
    ("ali213.ini", "ALI213 模拟器", ""),
    ("3dmgame.ini", "3DM 模拟器", ""),
    ("dinput8.dll", "代理 DLL 注入", ""),
    ("d3d11.dll", "代理 DLL 注入（ReShade/SpecialK 等）", ""),
    ("dxgi.dll", "代理 DLL 注入（ReShade/SpecialK 等）", ""),
    ("version.dll", "代理 DLL 注入", ""),
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
            continue  # 清单内文件：由哈希核对负责
        kind = "dir" if e.is_dir() else "file"
        if low in table:
            who, why = table[low]
            found.append({"name": e.name, "kind": kind, "origin": who, "detail": why})
        elif _STEAMLESS_PAT.search(low):
            found.append({"name": e.name, "kind": kind, "origin": "Steamless / 手工备份痕迹",
                          "detail": "脱壳或替换前的备份文件名"})
        elif manifest_names is not None:
            found.append({"name": e.name, "kind": kind, "origin": "未知", "detail": "Steam 清单里没有"})
    return found


# ---------------------------------------------------------------------------
# 核对
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def verify(game_dir, quick: bool = False, steam_root=None, manifests=None,
           modules=TARGET_MODULES, known_builds_path: Path = KNOWN_BUILDS_TSV,
           progress: bool = True) -> dict:
    """核对 game_dir，返回 provenance dict（见 --json 输出）。不写游戏目录。"""
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
        res["warnings"].append(f"目录不存在：{game_dir}")
        return res

    loc = locate_manifests(game_dir, steam_root, manifests)
    res["steam"] = {"appmanifest": loc["acf"], "buildid": loc["buildid"], "depots": loc["depots"],
                    "manifests": []}
    res["warnings"].extend(loc["notes"])

    by_name: dict[str, dict] = {}      # 小写名 → mapping（明文清单）
    by_sha_filename: dict[bytes, dict] = {}
    any_encrypted = False
    parsed_any = False
    for mpath in loc["files"]:
        try:
            man = parse_manifest_file(mpath)
        except (OSError, ProtoError, zipfile.BadZipFile) as e:
            res["warnings"].append(f"清单 {mpath} 解析失败：{e}")
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
            res["warnings"].append(f"清单 {mpath} 的 gid {gid} 与 appmanifest 记录的 "
                                   f"{loc['depots'][depot]} 不一致")
        if meta["filenames_encrypted"]:
            any_encrypted = True
            res["warnings"].append(f"depot {depot} 清单文件名已加密：无法逐名核对，"
                                   "只按 sha_filename（文件名哈希）匹配对应条目")
        for m in man["mappings"]:
            m = dict(m, depot=depot, manifest_id=gid)
            if m["sha_filename"]:
                by_sha_filename[m["sha_filename"]] = m
            if not meta["filenames_encrypted"]:
                by_name[norm_name(m["filename"])] = m
    have_manifest = parsed_any

    # 清单内文件：存在性与大小（只 stat，不算哈希）
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
            ent["detail"] = "文件不存在"
            continue
        ent["size"] = p.stat().st_size
        if quick and not is_pe:
            ent["verdict"] = "unchecked"
            ent["detail"] = "--quick：未核对"
            if ref is not None and ref["size"] != ent["size"]:
                ent["detail"] += f"（但大小与清单不符：清单 {ref['size']}）"
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
                    # 地址绑定构建：PE 只认 known-builds 登记过的 SHA-256
                    ent["verdict"] = "unregistered"
                    ent["detail"] = ("Steam 新构建，未登记：与 Steam 清单一致但 SHA-256 不在 known-builds.tsv；"
                                     "确认后去 PR 登记 known-builds.tsv 与 shared/builds.tsv")
                elif kb is not None:
                    ent["basis"] += "+known-builds"
            else:
                ent["verdict"] = "modified"
                ent["basis"] = f"depot-manifest:{ref['depot']}/{ref['manifest_id']}"
                ent["detail"] = (f"SHA1 / 大小与清单不符（清单 {ref['sha_content'].hex()}，"
                                 f"{ref['size']} 字节）")
                if kb is not None:
                    # 文件本身是已知正版，只是本机 Steam 清单是别的构建
                    ent["verdict"] = "official"
                    ent["basis"] = "known-builds"
                    ent["detail"] = (f"与本机 Steam 清单不符但匹配 known-builds（buildid "
                                     f"{kb.get('steam_buildid')}）")
            ent["expected_sha1"] = ref["sha_content"].hex()
            ent["expected_size"] = ref["size"]
        elif kb is not None:
            ent["verdict"] = "official"
            ent["basis"] = "known-builds"
        elif mod.lower() in known_modules:
            ent["verdict"] = "modified"
            ent["basis"] = "known-builds"
            ent["detail"] = "SHA-256 不匹配 known-builds 里任何一个已知正版"
        elif have_manifest:
            ent["verdict"] = "modified" if not any_encrypted else "unknown"
            ent["basis"] = "depot-manifest"
            ent["detail"] = ("Steam 清单里没有此文件" if not any_encrypted
                             else "清单文件名加密，按 sha_filename 找不到此文件")
        else:
            ent["verdict"] = "unknown"
            ent["detail"] = "无 Steam 清单，known-builds 也没有此模块"
        if is_pe and ent["verdict"] == "modified" and ent.get("pe"):
            pi = ent["pe"]
            if (mod.lower(), pi["TimeDateStamp"].upper()) in known_ts and not pi["has_bind"]:
                ent["detail"] += "；时间戳与正版相同但哈希不同（疑似 Steamless 脱壳或打过补丁）"
            elif pi["has_bind"]:
                ent["detail"] += "；带 SteamStub .bind 节"

    # 第三方文件
    res["third_party"] = scan_third_party(game_dir, manifest_top_names)
    # 清单里有但被替换的 steam_api64.dll（CreamAPI 特征）
    if have_manifest:
        for api in ("steam_api64.dll", "steam_api.dll"):
            ref = by_name.get(api)
            p = game_dir / api
            if ref and p.is_file():
                _, s1, _ = hash_file(p, progress=False)
                if s1 != ref["sha_content"].hex():
                    orig = game_dir / (api[:-4] + "_o.dll")
                    detail = "哈希与 Steam 清单不符（被替换）"
                    if orig.is_file() and hash_file(orig, progress=False)[1] == ref["sha_content"].hex():
                        detail += f"；{orig.name} 与清单原版一致"
                    res["third_party"].append({"name": api, "kind": "file", "origin": "CreamAPI / Steam 模拟器",
                                               "detail": detail})

    # 汇总
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
    """生成前的闸门：只核对 modules（如 ['EDF.dll']），不是官方就抛 UnofficialInstallError。
    allow_unofficial=True 时只往 stderr 警告并返回结果（结果里 verdict 照实记录）。"""
    kw.setdefault("progress", True)
    tool = kw.pop("tool", None)
    res = verify(game_dir, quick=False, modules=tuple(modules), **kw)
    res["gate"] = {"tool": tool, "modules": list(modules), "allow_unofficial": bool(allow_unofficial),
                   "argv": list(sys.argv)}
    res["unofficial_allowed"] = False
    if res["verdict"] != "official":
        bad = "; ".join(f"{f['module']}={f['verdict']}" + (f"（{f['detail']}）" if f["detail"] else "")
                        for f in res["files"] if f["verdict"] != "official")
        msg = f"游戏文件不是可确认的官方原版：{bad or res['verdict']}"
        if res["verdict"] == "unregistered":
            msg += f"\n{REGISTER_HINT}"
        if not allow_unofficial:
            raise UnofficialInstallError(msg, res)
        res["unofficial_allowed"] = True
        print(f"[verify_install] 警告（--allow-unofficial）：{msg}", file=sys.stderr)
    else:
        basis = ", ".join(f"{f['module']}←{f['basis']}" for f in res["files"])
        print(f"[verify_install] 官方原版：{basis}", file=sys.stderr)
    return res


REGISTER_HINT = ("这是 Steam 清单认可、但仓库还没登记的新构建：确认无误后发 PR 把它登记进 known-builds.tsv "
                 "与 shared/builds.tsv；在那之前只能用 --allow-unofficial 放行（产物会被标为未登记构建）。")


def _utf8_stderr() -> None:
    """闸门 / 警告的中文写到 stderr：管道里按 UTF-8 输出（控制台本来就走宽字符）。"""
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def gate_or_exit(parser, game_dir, modules, allow_unofficial: bool = False, tool: str | None = None,
                 **kw) -> dict:
    """命令行脚本用：require_official，不通过就 parser.exit（退出码 2 / 3）并提示 --allow-unofficial。"""
    _utf8_stderr()
    try:
        return require_official(game_dir, modules, allow_unofficial=allow_unofficial, tool=tool, **kw)
    except UnofficialInstallError as e:
        parser.exit(e.result.get("exit_code") or EXIT_UNOFFICIAL,
                    f"{e}\n确认要用这份文件生成时加 --allow-unofficial（产物的 provenance.json 会记下）。\n")


PROVENANCE_NAME = "provenance.json"


def provenance_path(output: Path) -> Path:
    """产物是目录 → <目录>/provenance.json；产物是单个文件 → <文件名>.provenance.json。"""
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
    """查询命令用：产物来源不是 known-builds 里的正版，或 provenance 标记了非官方 → 警告文字列表。
    image_hashes：{module: sha256}（例如 vanilla.sqlite 的 image 表）。"""
    out = []
    known = {r["sha256"]: r for r in load_known_builds(known_builds_path) if r.get("sha256")}
    for module, sha in sorted((image_hashes or {}).items()):
        if (sha or "").lower() not in known:
            out.append(f"{module} SHA-256 {sha} 不在 known-builds.tsv（不是已知官方构建）")
    if provenance:
        if provenance.get("verdict") != "official":
            out.append(f"生成时判定为 {_OVERALL_ZH.get(provenance.get('verdict'), provenance.get('verdict'))}"
                       + ("，用 --allow-unofficial 强行放行" if provenance.get("unofficial_allowed")
                          or (provenance.get("gate") or {}).get("allow_unofficial") else ""))
        for f in provenance.get("files", []):
            if f.get("sha256") and f["sha256"].lower() not in known and not (image_hashes or {}).get(f["module"]):
                out.append(f"{f['module']} SHA-256 {f['sha256']} 不在 known-builds.tsv")
    return out


def print_provenance_warnings(warnings: list[str], stream=None) -> None:
    if stream is None:
        _utf8_stderr()
        stream = sys.stderr
    for w in warnings:
        print(f"警告：产物来源不是已知官方构建：{w}", file=stream, flush=True)


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

_VERDICT_ZH = {"official": "官方", "modified": "被改 / 不符", "missing": "缺失", "unchecked": "未核对",
               "unknown": "无依据", "unregistered": "Steam 新构建，未登记"}
_OVERALL_ZH = {"official": "官方原版", "unofficial": "非官方或被改", "undecided": "无法判定",
               "unregistered": "Steam 新构建，未登记"}


def overall_text(res: dict) -> str:
    """总判定的中文。--quick 下 CPK 没算哈希，官方只说到 PE 为止。"""
    if res.get("verdict") == "official" and any(f["verdict"] == "unchecked" for f in res.get("files", [])):
        return "PE 官方，CPK 未核对"
    return _OVERALL_ZH.get(res.get("verdict"), res.get("verdict"))


def format_summary(res: dict) -> str:
    out = []
    out.append(f"游戏目录：{res['game_dir']}")
    st = res.get("steam") or {}
    if st.get("appmanifest"):
        out.append(f"Steam appmanifest：{st['appmanifest']}（buildid {st.get('buildid')}）")
    for m in st.get("manifests", []):
        out.append(f"  depot {m['depot']} 清单 {m['manifest_id']}：{m['files']} 个条目"
                   + ("，文件名加密" if m["filenames_encrypted"] else ""))
    if not st.get("manifests"):
        out.append("Steam depot 清单：无（回退 known-builds.tsv）")
    out.append("核心文件：")
    for f in res["files"]:
        line = f"  {f['module']:<12} {_VERDICT_ZH.get(f['verdict'], f['verdict'])}"
        if f.get("basis"):
            line += f"  依据 {f['basis']}"
        if f.get("sha1"):
            line += f"  sha1 {f['sha1']}"
        if f.get("detail"):
            line += f"  {f['detail']}"
        out.append(line)
    if res["missing_from_install"]:
        out.append(f"清单里有但目录里缺（{len(res['missing_from_install'])}）：")
        out.extend(f"  {n}" for n in res["missing_from_install"][:50])
    if res["size_mismatch"]:
        out.append(f"大小与清单不符（{len(res['size_mismatch'])}，仅警告）：")
        out.extend(f"  {s['name']}：清单 {s['expected']}，实际 {s['actual']}" for s in res["size_mismatch"][:50])
    if res["third_party"]:
        out.append(f"第三方 / 清单外文件（{len(res['third_party'])}，仅警告）：")
        out.extend(f"  {t['name']}{'/' if t['kind'] == 'dir' else ''}  [{t['origin']}] {t['detail']}".rstrip()
                   for t in res["third_party"])
    for w in res["warnings"]:
        out.append(f"警告：{w}")
    out.append(f"判定：{overall_text(res)}（退出码 {res['exit_code']}）")
    if res["verdict"] == "unregistered":
        out.append(REGISTER_HINT)
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="核对 EDF6 安装是否为官方原版")
    ap.add_argument("game_dir")
    ap.add_argument("--quick", action="store_true", help="只核 PE（EDF.dll / EDF6.exe），CPK 标为未核对")
    ap.add_argument("--json", metavar="PATH", help="写 provenance JSON")
    ap.add_argument("--steam-root", metavar="DIR", help="Steam 根目录（含 steamapps/ 与 depotcache/）")
    ap.add_argument("--manifest", metavar="FILE", action="append", help="显式指定 depot 清单，可多次")
    ap.add_argument("--known-builds", metavar="TSV", default=str(KNOWN_BUILDS_TSV))
    ap.add_argument("--module", action="append", metavar="NAME",
                    help="只核对这些文件（可多次；默认 EDF.dll EDF6.exe 与 4 个 CPK）")
    ap.add_argument("--allow-unofficial", action="store_true",
                    help="只在 JSON 里记下调用方放行了非官方文件；退出码照实返回")
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
