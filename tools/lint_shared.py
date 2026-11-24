#!/usr/bin/env python3
"""Lint the shared/ reverse-engineering data and guard the repository against game-derived artifacts.

校验 shared/ 下的 TSV 与笔记格式，并拒绝由游戏文件生成的产物（汇编、伪代码、sqlite、任务脚本、CPK 等）。
只用 Python 标准库。退出码非 0 时逐行输出 `path:line: error: message`。

    python tools/lint_shared.py                      # 校验当前仓库
    python tools/lint_shared.py --game "D:/steam/steamapps/common/EARTH DEFENSE FORCE 6"
    python tools/lint_shared.py --history BASE...HEAD   # 另查范围内每个提交新增/修改过的文件（防先加后删）

守卫只是来源记录与防手滑的闸门，不是安全边界：它按特征拦截常见产物，拦不住刻意改写过的内容。
"""

import argparse
import bisect
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

SCHEMAS = {
    'builds': ('build', 'module', 'sha256', 'timedatestamp', 'image_base', 'size_of_image', 'notes'),
    'functions': ('build', 'rva', 'name', 'signature', 'confidence', 'evidence', 'notes'),
    'data': ('build', 'rva', 'name', 'type', 'confidence', 'evidence', 'notes'),
    'types': ('build', 'offset', 'size', 'name', 'type', 'confidence', 'evidence', 'notes'),
}
CONFIDENCE = ('confirmed', 'likely', 'guess')

BUILD_ID = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*')
SHA256 = re.compile(r'[0-9a-f]{64}')
HEX8 = re.compile(r'0x[0-9A-F]{8}')
HEX16 = re.compile(r'0x[0-9A-F]{16}')
OFFSET = re.compile(r'0x[0-9A-F]{4,8}')
SIZE = re.compile(r'\?|[1-9][0-9]*|0x[0-9A-F]+')
MODULE = re.compile(r'[A-Za-z0-9_.-]+\.(?:dll|exe)')
IDENT = r'[A-Za-z_][A-Za-z0-9_]*'
NAME = re.compile(rf'(?:{IDENT}::)*~?{IDENT}')
FIELD_NAME = re.compile(IDENT)
TYPE_FILE = re.compile(rf'(?:{IDENT}::)*{IDENT}|{IDENT}(?:\.{IDENT})*')
# Auto-generated names carry no information and must not enter the shared tables.
GENERATED_PART = re.compile(r'(?:thunk_)?(?:FUN|sub|LAB|DAT|PTR|SUB|undefined|field)_(?:0x)?[0-9A-Fa-f]{4,}|vslot_\d+')

# --- game artifact guard -------------------------------------------------------------------------
DUMP_SUFFIXES = {'.asm', '.sqlite', '.sqlite3', '.db', '.c', '.h', '.pcode', '.gzf', '.gpr', '.lst', '.idb', '.i64'}
# .ac / .h / .as: mission scripts and headers as missions.py copies them out of the CPKs (and AngelScript sources);
# missions.py's .BVM.asm listings are already caught as .asm.
GAME_SUFFIXES = {'.ac', '.as', '.bvm', '.cpk', '.sgo', '.rab', '.mrab', '.rmpa', '.mdb', '.mab', '.cas', '.awb', '.acb',
                 '.usm', '.dds', '.dll', '.exe', '.pdb', '.bin', '.dat', '.txt_sb'}
# Generated index files, recognised by name wherever they sit (missions.py, every generator's provenance record).
ARTIFACT_NAMES = {'native-usage.tsv', 'provenance.json'}
ARTIFACT_NAME_SUFFIXES = ('.provenance.json',)
# missions.py mirrors each archive as <output>/<Archive>.cpk/MISSION/...: a directory named like an archive.
ARCHIVE_DIR = re.compile(r'.+\.cpk', re.I)
# Leading columns of missions.py's files.tsv / native-usage.tsv, caught even when renamed.
ARTIFACT_HEADERS = (('archive', 'source', 'format', 'source_sha256', 'output'),
                    ('native_table', 'native_id', 'call_sites', 'script_count'))
DEFAULT_MAX_BYTES = 512 * 1024
GHIDRA_TOKEN = re.compile(r'\b(?:undefined[1-8]?|(?:thunk_)?FUN_[0-9a-fA-F]{6,}|DAT_[0-9a-fA-F]{6,}|'
                          r'LAB_[0-9a-fA-F]{6,}|PTR_[A-Za-z0-9_]*?[0-9a-fA-F]{6,}|in_stack_[0-9a-fA-F]+|'
                          r'unaff_[A-Z0-9]+|extraout_[A-Z0-9]+|param_\d+|[abcdfilpsuz]{1,4}Var\d+|'
                          r'local_[0-9a-fA-F]+|auStack_[0-9a-fA-F]+|CONCAT\d+|SUB\d+)\b')
# Decompiler output is judged by density, never by one stray token: the whole file (hits / non-blank lines, with an
# absolute minimum) or any window of consecutive non-blank lines (catches one function pasted into a long file).
GHIDRA_MIN_HITS = 8
GHIDRA_DENSITY = 0.25
GHIDRA_WINDOW = 30
GHIDRA_WINDOW_HITS = 12
ASM_LINE = re.compile(r'^\s*(?:0x)?[0-9A-Fa-f]{8,16}:?\s+(?:[0-9A-Fa-f]{2}\s){2,}', re.M)
ASM_THRESHOLD = 30
# Disassembly without the machine-code column (vanilla.py show / refs style): an address, a mnemonic, then a register
# or memory operand on the same line.
X86_MNEMONIC = (r'(?:mov[a-z]{0,5}|lea|push|pop|call|jmp|j[a-z]{1,3}|cmp[a-z]{0,4}|test|add[a-z]{0,3}|sub[a-z]{0,3}|'
                r'xor[a-z]{0,2}|and[a-z]{0,3}|or[a-z]{0,2}|imul|mul[a-z]{0,2}|div[a-z]{0,2}|idiv|inc|dec|neg|not|'
                r'sh[lr]d?|sa[lr]|ro[lr]|cmov[a-z]{1,3}|set[a-z]{1,3}|cvt[a-z0-9]{2,8}|u?comis[sd]|xchg|cmpxchg|'
                r'bt[a-z]?|stos[a-z]?|sqrt[a-z]{2}|min[a-z]{2}|max[a-z]{2}|pxor|por|pand|unpck[a-z]{3,4}|shuf[a-z]{2})')
X86_OPERAND = (r'(?:\[|\b(?:byte|word|dword|qword|xmmword|ymmword)\s+ptr\b|'
               r'\b(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|sp|bp)l?|r(?:[89]|1[0-5])[dwb]?|[xy]mm\d{1,2}|rip)\b)')
ASM_TEXT_LINE = re.compile(rf'^[ \t>]*(?:0x)?[0-9A-Fa-f]{{8,16}}\b:?[^\n]*?[ \t]{X86_MNEMONIC}[ \t]+[^\n]*?{X86_OPERAND}',
                           re.M | re.I)
ASM_TEXT_THRESHOLD = 20
NOTE_FENCE_MAX = 10
LIST_ITEM = re.compile(r'^(\s*)(?:[-*+]|\d{1,9}[.)])(\s+)(?=\S)')
SKIP_DIRS = {'.git', 'out', '_cache', '__pycache__'}


class Report:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.history = (0, 0)

    def error(self, path, line, message):
        self.errors.append(f'{path}:{line}: error: {message}')

    def warn(self, path, line, message):
        self.warnings.append(f'{path}:{line}: warning: {message}')


def rel(path, root):
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def read_table(path, kind, root, report):
    """Yield (line_number, row dict). Blank lines and lines starting with '#' are skipped."""
    shown = rel(path, root)
    raw = path.read_bytes()
    if raw.startswith(b'\xef\xbb\xbf'):
        report.error(shown, 1, 'UTF-8 BOM is not allowed')
        raw = raw[3:]
    if b'\r' in raw:
        report.error(shown, 1, 'use LF line endings (found CR)')
    if raw and not raw.endswith(b'\n'):
        report.error(shown, raw.count(b'\n') + 1, 'file must end with a newline')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        report.error(shown, 1, f'not valid UTF-8: {error}')
        return
    header = SCHEMAS[kind]
    seen_header = False
    for number, line in enumerate(text.replace('\r', '').split('\n'), 1):
        if not line.strip() or line.startswith('#'):
            continue
        cells = line.split('\t')
        if not seen_header:
            seen_header = True
            if tuple(cells) != header:
                report.error(shown, number, f'header must be: {chr(9).join(header)!r}')
                return
            continue
        if len(cells) != len(header):
            report.error(shown, number, f'expected {len(header)} tab-separated columns, found {len(cells)}')
            continue
        if any(cell != cell.strip() for cell in cells):
            report.error(shown, number, 'cells must not have leading or trailing spaces')
        yield number, dict(zip(header, cells))
    if not seen_header:
        report.error(shown, 1, 'missing header row')


def check_name(value, shown, number, report, pattern=NAME, what='name'):
    if not value:
        report.error(shown, number, f'{what} is empty')
        return False
    if not value.isascii():
        report.error(shown, number, f'{what} {value!r} must be ASCII (put Chinese descriptions in notes)')
        return False
    if not pattern.fullmatch(value):
        report.error(shown, number, f'{what} {value!r} has invalid characters (allowed: identifiers joined by ::)')
        return False
    for part in value.split('::'):
        if GENERATED_PART.fullmatch(part.lstrip('~')):
            report.error(shown, number, f'{what} {value!r} is an auto-generated placeholder; leave the row out')
            return False
    return True


def check_common(row, shown, number, report):
    if row['confidence'] not in CONFIDENCE:
        report.error(shown, number, f'confidence must be one of {", ".join(CONFIDENCE)}, got {row["confidence"]!r}')
    if not row['evidence']:
        report.error(shown, number, 'evidence is empty')


def load_builds(shared, root, report):
    builds = {}
    path = shared / 'builds.tsv'
    if not path.is_file():
        report.error(rel(path, root), 1, 'missing builds.tsv')
        return builds
    shown = rel(path, root)
    hashes = {}
    for number, row in read_table(path, 'builds', root, report):
        ok = True
        for field, pattern in (('build', BUILD_ID), ('module', MODULE), ('sha256', SHA256), ('timedatestamp', HEX8),
                               ('image_base', HEX16), ('size_of_image', HEX8)):
            if not pattern.fullmatch(row[field]):
                report.error(shown, number, f'{field} {row[field]!r} does not match {pattern.pattern}')
                ok = False
        if not ok:
            continue
        key = (row['build'], row['module'])
        if key in builds:
            report.error(shown, number, f'duplicate build/module {key[0]} {key[1]}')
            continue
        if row['sha256'] in hashes:
            report.error(shown, number, f'sha256 already used by {hashes[row["sha256"]]}')
        hashes[row['sha256']] = f'{key[0]} {key[1]}'
        builds[key] = dict(row, line=number, size=int(row['size_of_image'], 16))
    return builds


def check_address_table(path, kind, builds, root, report, names, addresses):
    shown = rel(path, root)
    module = path.stem
    if not MODULE.fullmatch(module):
        report.error(shown, 1, f'file name must be <module>.tsv such as EDF.dll.tsv, got {path.name!r}')
        return []
    rows = []
    for number, row in read_table(path, kind, root, report):
        key = (row['build'], module)
        if key not in builds:
            report.error(shown, number, f'build {row["build"]!r} with module {module} is not listed in builds.tsv')
            continue
        if not HEX8.fullmatch(row['rva']):
            report.error(shown, number, f'rva {row["rva"]!r} must be 8 upper-case hex digits like 0x00ABCDEF')
            continue
        rva = int(row['rva'], 16)
        if rva == 0 or rva >= builds[key]['size']:
            report.error(shown, number, f'rva {row["rva"]} outside image (size_of_image {builds[key]["size_of_image"]})')
            continue
        check_common(row, shown, number, report)
        if kind == 'functions' and row['signature'] and not ('(' in row['signature'] and row['signature'].endswith(')')):
            report.error(shown, number, 'signature must look like a C prototype: ret name(args)')
        if not check_name(row['name'], shown, number, report):
            continue
        where = f'{shown}:{number}'
        address_key = (row['build'], module, rva)
        if address_key in addresses:
            report.error(shown, number, f'rva {row["rva"]} already named at {addresses[address_key]}')
        else:
            addresses[address_key] = where
        name_key = (row['build'], module, row['name'])
        if name_key in names:
            report.error(shown, number, f'name {row["name"]!r} already used at {names[name_key]}; '
                                        'add a distinguishing suffix')
        else:
            names[name_key] = where
        rows.append((number, row, rva))
    return rows


def check_type_table(path, builds, root, report):
    shown = rel(path, root)
    if not TYPE_FILE.fullmatch(path.stem):
        report.error(shown, 1, f'type file name {path.name!r} must be <TypeName>.tsv (ASCII identifier)')
    known_builds = {build for build, _ in builds}
    fields = {}
    for number, row in read_table(path, 'types', root, report):
        if row['build'] not in known_builds:
            report.error(shown, number, f'build {row["build"]!r} is not listed in builds.tsv')
            continue
        if not OFFSET.fullmatch(row['offset']):
            report.error(shown, number, f'offset {row["offset"]!r} must be upper-case hex like 0x0228')
            continue
        if not SIZE.fullmatch(row['size']):
            report.error(shown, number, f'size {row["size"]!r} must be a positive integer, 0x hex, or ?')
            continue
        if not row['type']:
            report.error(shown, number, 'type is empty (use ? when unknown)')
        check_common(row, shown, number, report)
        check_name(row['name'], shown, number, report, FIELD_NAME, 'field name')
        offset = int(row['offset'], 16)
        size = None if row['size'] == '?' else int(row['size'], 0)
        per_build = fields.setdefault(row['build'], {})
        if offset in per_build:
            report.error(shown, number, f'offset {row["offset"]} already defined on line {per_build[offset][0]}')
            continue
        for other_offset, (other_line, other_size, other_name) in per_build.items():
            if row['name'] == other_name:
                report.error(shown, number, f'field name {other_name!r} already used on line {other_line}')
            low, high = sorted(((offset, size), (other_offset, other_size)))
            if low[1] is not None and low[0] + low[1] > high[0]:
                report.error(shown, number, f'overlaps field on line {other_line}')
        per_build[offset] = (number, size, row['name'])


def check_notes(shared, root, report):
    for path in sorted((shared / 'notes').rglob('*')) if (shared / 'notes').is_dir() else ():
        if path.is_dir():
            continue
        shown = rel(path, root)
        if path.suffix != '.md':
            report.error(shown, 1, 'shared/notes only accepts Markdown (.md) files')
            continue
        check_note_text(shown, path.read_text(encoding='utf-8', errors='replace'), report)


def note_code_blocks(text):
    """(first line, line count, closed) of each fenced or indented code block in a Markdown note.

    Fences follow CommonMark: a run of >= 3 backticks or tildes opens it, the same character at least as many times
    closes it; an unclosed fence runs to the end of the file. An indented block is a run of lines indented at least 4
    columns past the enclosing list item's content (column 0 outside a list) that does not continue a paragraph;
    blank lines inside it count."""
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    blocks = []
    fence = None              # (character, length, first line)
    indented = None           # [first line, last non-blank line]
    list_offset = None        # content column of the innermost list item; None outside a list
    previous_blank = True
    for number, raw in enumerate(lines, 1):
        line = raw.expandtabs(4)
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if fence is not None:
            mark, length, first = fence
            if indent < 4 and stripped.startswith(mark * length) and not stripped.rstrip().strip(mark):
                blocks.append((first, number - first - 1, True))
                fence = None
                previous_blank = False
            continue
        if not stripped:
            previous_blank = True
            continue
        need = 4 if list_offset is None else list_offset + 4
        if indent >= need and (previous_blank or indented is not None):
            if indented is None:
                indented = [number, number]
            indented[1] = number
            previous_blank = False
            continue
        if indented is not None:
            blocks.append((indented[0], indented[1] - indented[0] + 1, True))
            indented = None
        opener = re.match(r'`{3,}|~{3,}', stripped)
        if opener:
            fence = (opener.group()[0], len(opener.group()), number)
            previous_blank = False
            continue
        item = LIST_ITEM.match(line)
        if item:
            list_offset = item.end()
        elif indent == 0 and previous_blank:
            list_offset = None
        previous_blank = False
    if indented is not None:
        blocks.append((indented[0], indented[1] - indented[0] + 1, True))
    if fence is not None:
        blocks.append((fence[2], len(lines) - fence[2], False))
    return blocks


def check_note_text(shown, text, report):
    for start, length, closed in note_code_blocks(text):
        if not closed:
            report.error(shown, start, 'code fence is never closed (it runs to the end of the file)')
        if length > NOTE_FENCE_MAX:
            report.error(shown, start, f'code block has {length} lines; notes may quote at most '
                                       f'{NOTE_FENCE_MAX} lines of rewritten code')


def check_layout(shared, root, report):
    allowed_top = {'builds.tsv', 'README.md', 'README.en.md', 'functions', 'data', 'types', 'notes'}
    for path in sorted(shared.iterdir()):
        if path.name not in allowed_top:
            report.error(rel(path, root), 1, 'unexpected entry in shared/ (see CONTRIBUTING.md for the layout)')
    for folder in ('functions', 'data', 'types'):
        base = shared / folder
        if not base.is_dir():
            continue
        for path in sorted(base.rglob('*')):
            if path.is_dir():
                report.error(rel(path, root), 1, f'shared/{folder} must not contain sub-directories')
            elif path.suffix != '.tsv' and path.name != 'README.md':
                report.error(rel(path, root), 1, f'shared/{folder} only accepts .tsv files')


# --- PE checks (--game) --------------------------------------------------------------------------
class PEImage:
    def __init__(self, data):
        if data[:2] != b'MZ':
            raise ValueError('not an MZ image')
        self.data = data
        pe = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe:pe + 4] != b'PE\0\0':
            raise ValueError('missing PE signature')
        sections, self.timedatestamp = struct.unpack_from('<HI', data, pe + 6)
        optional_size = struct.unpack_from('<H', data, pe + 20)[0]
        opt = pe + 24
        if struct.unpack_from('<H', data, opt)[0] != 0x20B:
            raise ValueError('only PE32+ images are supported')
        self.image_base = struct.unpack_from('<Q', data, opt + 24)[0]
        self.size_of_image = struct.unpack_from('<I', data, opt + 56)[0]
        directories = struct.unpack_from('<I', data, opt + 108)[0]
        exception_rva, exception_size = struct.unpack_from('<II', data, opt + 112 + 3 * 8) if directories > 3 else (0, 0)
        self.sections = []
        table = opt + optional_size
        for index in range(sections):
            name, vsize, va, raw_size, raw_ptr = struct.unpack_from('<8sIIII', data, table + 40 * index)
            flags = struct.unpack_from('<I', data, table + 40 * index + 36)[0]
            self.sections.append((name.rstrip(b'\0').decode('latin-1'), va, max(vsize, raw_size), raw_ptr,
                                  raw_size, bool(flags & 0x20000000)))
        self.begins = set()
        self.ranges = []
        self.chained = {}   # fragment begin -> begin of the entry it chains to (UNW_FLAG_CHAININFO)
        if exception_size:
            offset = self.file_offset(exception_rva)
            for index in range(exception_size // 12):
                begin, end, unwind = struct.unpack_from('<III', data, offset + 12 * index)
                if not begin:
                    continue
                self.begins.add(begin)
                self.ranges.append((begin, end))
                parent = self.chain_parent(unwind)
                if parent is not None:
                    self.chained[begin] = parent
        self.ranges.sort()

    def chain_parent(self, unwind):
        try:
            info = self.file_offset(unwind)
        except ValueError:
            return None
        if not (self.data[info] >> 3) & 0x4:
            return None
        codes = self.data[info + 2]
        return struct.unpack_from('<I', self.data, info + 4 + ((codes + 1) & ~1) * 2)[0]

    def chain_root(self, rva):
        seen = set()
        while rva in self.chained and rva not in seen:
            seen.add(rva)
            rva = self.chained[rva]
        return rva

    def padded_start(self, rva):
        """A leaf function without .pdata usually starts 16-aligned right after int3/nop/ret padding."""
        if rva % 16:
            return False
        try:
            previous = self.data[self.file_offset(rva - 1)]
        except (ValueError, IndexError):
            return False
        return previous in (0xCC, 0x90, 0xC3)

    def section(self, rva):
        return next((s for s in self.sections if s[1] <= rva < s[1] + s[2]), None)

    def file_offset(self, rva):
        found = self.section(rva)
        if found is None:
            raise ValueError(f'rva {rva:#x} not inside any section')
        return found[3] + rva - found[1]

    def inside_range(self, rva):
        """Return the .pdata begin of the range that strictly contains rva (rva is mid-function)."""
        index = bisect.bisect_right(self.ranges, (rva, 0xFFFFFFFF)) - 1
        if index >= 0:
            begin, end = self.ranges[index]
            if begin < rva < end:
                return begin
        return None


def load_game_images(game, builds, report):
    images = {}
    for (build, module), row in builds.items():
        path = Path(game) / module
        if not path.is_file():
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != row['sha256']:
            continue
        try:
            image = PEImage(data)
        except (ValueError, struct.error) as error:
            report.error('shared/builds.tsv', row['line'], f'{path}: cannot parse PE: {error}')
            continue
        for field, actual, width in (('timedatestamp', image.timedatestamp, 8), ('image_base', image.image_base, 16),
                                     ('size_of_image', image.size_of_image, 8)):
            expected = f'0x{actual:0{width}X}'
            if row[field] != expected:
                report.error('shared/builds.tsv', row['line'], f'{build} {module}: {field} is {expected} in {path}')
        images[(build, module)] = image
    return images


def check_against_game(kind, path, rows, images, root, report):
    shown = rel(path, root)
    module = path.stem
    for number, row, rva in rows:
        image = images.get((row['build'], module))
        if image is None:
            continue
        section = image.section(rva)
        if section is None:
            report.error(shown, number, f'rva {row["rva"]} is not inside any PE section')
            continue
        if kind == 'functions':
            if not section[5]:
                report.error(shown, number, f'rva {row["rva"]} is in non-executable section {section[0]}')
                continue
            owner = image.inside_range(rva)
            if rva in image.chained:
                report.error(shown, number, f'rva {row["rva"]} is a chained unwind fragment of the function at '
                                            f'0x{image.chain_root(rva):08X}; name the function entry instead')
            elif owner is not None:
                report.error(shown, number, f'rva {row["rva"]} is inside the .pdata function starting at 0x{owner:08X}')
            elif rva not in image.begins and not image.padded_start(rva):
                report.warn(shown, number, f'rva {row["rva"]} has no .pdata entry (leaf function or wrong address?)')
        elif section[5]:
            report.warn(shown, number, f'data rva {row["rva"]} is in executable section {section[0]}')


# --- repository artifact guard -------------------------------------------------------------------
def repository_files(root):
    try:
        top = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'], capture_output=True,
                             text=True, check=True).stdout.strip()
        if top and Path(top).resolve() == root.resolve():
            listed = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--cached', '--others',
                                     '--exclude-standard'], capture_output=True, check=True).stdout
            return [root / name for name in listed.decode('utf-8').split('\0') if name and (root / name).is_file()]
    except (OSError, subprocess.CalledProcessError):
        pass
    found = []
    for directory, folders, files in os.walk(root):
        folders[:] = [name for name in folders if name not in SKIP_DIRS]
        found.extend(Path(directory) / name for name in files)
    return found


def decompiler_evidence(text):
    """Why text looks like decompiler output, or None (see GHIDRA_* for the density rules)."""
    hits = [len(GHIDRA_TOKEN.findall(line)) for line in text.split('\n') if line.strip()]
    total = sum(hits)
    if total >= GHIDRA_MIN_HITS and total >= GHIDRA_DENSITY * len(hits):
        return f'{total} Ghidra-style tokens in {len(hits)} non-blank lines'
    window = best = sum(hits[:GHIDRA_WINDOW])
    for index in range(GHIDRA_WINDOW, len(hits)):
        window += hits[index] - hits[index - GHIDRA_WINDOW]
        best = max(best, window)
    if best >= GHIDRA_WINDOW_HITS:
        return f'{best} Ghidra-style tokens within {GHIDRA_WINDOW} consecutive non-blank lines'
    return None


def check_artifact_name(shown, report):
    """Reject by path alone; True when rejected."""
    parts = shown.split('/')
    name = parts[-1].lower()
    suffix = Path(name).suffix
    if suffix in DUMP_SUFFIXES:
        report.error(shown, 1, f'{suffix} files are disassembly/decompiler/database dumps; generate them locally')
    elif suffix in GAME_SUFFIXES:
        report.error(shown, 1, f'{suffix} files are game content or binaries; never commit them')
    elif name in ARTIFACT_NAMES or name.endswith(ARTIFACT_NAME_SUFFIXES):
        report.error(shown, 1, f'{parts[-1]} is a generated index / provenance file; generate it locally')
    elif any(ARCHIVE_DIR.fullmatch(part) for part in parts[:-1]):
        report.error(shown, 1, 'path mirrors a game archive (<Archive>.cpk/...); extracted game files stay local')
    else:
        return False
    return True


def check_artifact_content(shown, data, report, notes=True):
    """Reject by content (the size limit is checked by the caller, before reading)."""
    if b'\0' in data[:8192]:
        report.error(shown, 1, 'binary file; only source code and text data are accepted')
        return
    text = data.decode('utf-8', errors='replace')
    first = tuple(text.lstrip('\ufeff').split('\n', 1)[0].rstrip('\r').split('\t'))
    if any(first[:len(header)] == header for header in ARTIFACT_HEADERS):
        report.error(shown, 1, 'this is a missions.py index (files.tsv / native-usage.tsv); generate it locally')
    why = decompiler_evidence(text)
    if why:
        report.error(shown, 1, f'{why} (param_N, uVar1, local_28, FUN_...); this looks like decompiler output')
    asm_lines = len(ASM_LINE.findall(text))
    if asm_lines >= ASM_THRESHOLD:
        report.error(shown, 1, f'{asm_lines} address + machine-code lines; this looks like a disassembly dump')
    else:
        text_lines = len(ASM_TEXT_LINE.findall(text))
        if text_lines >= ASM_TEXT_THRESHOLD:
            report.error(shown, 1, f'{text_lines} address + mnemonic + register/memory operand lines; '
                                   'this looks like a disassembly listing')
    if notes and shown.startswith('shared/notes/') and shown.endswith('.md'):
        check_note_text(shown, text, report)


def guard_artifacts(root, report, max_bytes):
    for path in sorted(repository_files(root)):
        shown = rel(path, root)
        if check_artifact_name(shown, report):
            continue
        size = path.stat().st_size
        if size > max_bytes:
            report.error(shown, 1, f'{size} bytes exceeds the {max_bytes}-byte limit for a single file')
            continue
        # shared/notes in the working tree are already checked by check_notes.
        check_artifact_content(shown, path.read_bytes(), report, notes=False)


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], capture_output=True, check=True).stdout


def guard_history(root, revisions, report, max_bytes):
    """Guard every file that a commit in `revisions` added or modified, with that commit's content, so a file added and
    deleted again inside a pull request is still caught. revisions: BASE..HEAD or BASE...HEAD (the commits reachable
    from HEAD and not from BASE) or a single commit. Returns (commits, files checked)."""
    match = re.fullmatch(r'(.+?)\.{2,3}(.+)', revisions)
    span = [match.group(2), '--not', match.group(1)] if match else ['-1', revisions]
    commits = git(root, 'rev-list', '--reverse', *span, '--').decode().split()
    checked = 0
    for commit in commits:
        raw = git(root, 'diff-tree', '-r', '-m', '--root', '--no-commit-id', '--no-renames', '-z',
                  '--diff-filter=ACMRT', commit).split(b'\0')
        seen = set()
        for meta, name in zip(raw[0::2], raw[1::2]):
            fields = meta.decode().split()
            if not meta.startswith(b':') or len(fields) < 4:
                continue
            mode, blob, path = fields[1], fields[3], name.decode('utf-8')
            if path in seen or mode in ('120000', '160000'):
                continue
            seen.add(path)
            inner = Report()
            if not check_artifact_name(path, inner):
                size = int(git(root, 'cat-file', '-s', blob))
                if size > max_bytes:
                    inner.error(path, 1, f'{size} bytes exceeds the {max_bytes}-byte limit for a single file')
                else:
                    check_artifact_content(path, git(root, 'cat-file', 'blob', blob), inner)
            report.errors.extend(f'{commit[:12]}:{error}' for error in inner.errors)
            checked += 1
    return len(commits), checked


def run(root, game=None, guard=True, max_bytes=DEFAULT_MAX_BYTES, history=None):
    report = Report()
    root = Path(root)
    shared = root / 'shared'
    if shared.is_dir():
        check_layout(shared, root, report)
        builds = load_builds(shared, root, report)
        images = load_game_images(game, builds, report) if game else {}
        for kind in ('functions', 'data'):
            names, addresses = {}, {}
            for path in sorted((shared / kind).glob('*.tsv')) if (shared / kind).is_dir() else ():
                rows = check_address_table(path, kind, builds, root, report, names, addresses)
                if images:
                    check_against_game(kind, path, rows, images, root, report)
        for path in sorted((shared / 'types').glob('*.tsv')) if (shared / 'types').is_dir() else ():
            check_type_table(path, builds, root, report)
        check_notes(shared, root, report)
        if game and not images:
            report.warn('shared/builds.tsv', 1, f'no module in {game} matches a sha256 in builds.tsv; PE checks skipped')
    if guard:
        guard_artifacts(root, report, max_bytes)
    if history:
        commits, files = guard_history(root, history, report, max_bytes)
        report.history = (commits, files)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=ROOT, help='repository root (default: this checkout)')
    parser.add_argument('--game', type=Path, help='game directory; verify RVAs against the installed PE images')
    parser.add_argument('--no-artifact-guard', action='store_true', help='only lint shared/')
    parser.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_BYTES, help='largest file size accepted')
    parser.add_argument('--history', metavar='BASE...HEAD',
                        help='also guard every file each commit in the range added or modified, as that commit had it')
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='backslashreplace')
    try:
        report = run(args.root, args.game, not args.no_artifact_guard, args.max_bytes, args.history)
    except subprocess.CalledProcessError as error:
        print(f'lint_shared: git failed: {error.stderr.decode(errors="replace").strip()}', file=sys.stderr)
        return 2
    for line in report.warnings + report.errors:
        print(line)
    if args.history:
        print(f'lint_shared: history {args.history}: {report.history[0]} commit(s), {report.history[1]} file version(s)',
              file=sys.stderr)
    print(f'lint_shared: {len(report.errors)} error(s), {len(report.warnings)} warning(s)', file=sys.stderr)
    return 1 if report.errors else 0


if __name__ == '__main__':
    sys.exit(main())
