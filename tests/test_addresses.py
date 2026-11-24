"""地址清单计算（edf6re_lib/addresses.py）的测试，全部用合成数据。

运行：python -B -m unittest discover -s tests -v
"""
from __future__ import annotations

import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from edf6re_lib import addresses  # noqa: E402

MODULE = 'EDF.dll'
BASE = 0x180000000


def database():
    db = sqlite3.connect(':memory:')
    db.executescript('''
        CREATE TABLE section(module TEXT, rva INTEGER, name TEXT, virtual_size INTEGER, raw_size INTEGER,
                             file_offset INTEGER, executable INTEGER);
        CREATE TABLE reference(module TEXT, source_rva INTEGER, target_rva INTEGER, kind TEXT);
        CREATE TABLE vslot(module TEXT, vtable_rva INTEGER, slot INTEGER, target_rva INTEGER);
        CREATE TABLE instruction(module TEXT, rva INTEGER, bytes BLOB, mnemonic TEXT, operands TEXT);
    ''')
    # .text 0x1000..0x1100 (virtual size smaller than raw), .rdata 0x2000.. not executable.
    db.execute("INSERT INTO section VALUES (?, 0x1000, '.text', 0x100, 0x200, 0x400, 1)", (MODULE,))
    db.execute("INSERT INTO section VALUES (?, 0x2000, '.rdata', 0x100, 0x100, 0x600, 0)", (MODULE,))
    db.execute("INSERT INTO section VALUES ('EDF6.exe', 0x1000, '.text', 0x1000, 0x1000, 0x400, 1)")
    return db


def write_functions(out, folder, rows):
    path = Path(out) / folder / MODULE / 'functions.tsv'
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ['rva\tname\tfile\tline\tstatus\tdiagnostic']
    lines += [f'0x{rva:08x}\tFUN\tpart-0000.c\t1\t{status}\t' for rva, status in rows]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


class FakePE:
    """Just the pefile surface relocated_code_pointers uses."""

    def __init__(self, image, slots):
        self.image = image
        self.OPTIONAL_HEADER = SimpleNamespace(ImageBase=BASE)
        entries = [SimpleNamespace(type=kind, rva=rva) for rva, kind in slots]
        self.DIRECTORY_ENTRY_BASERELOC = [SimpleNamespace(entries=entries)]

    def get_memory_mapped_image(self):
        return self.image


class AddressListTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.out = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_candidates_count_distinct_callers_and_slots_inside_code(self):
        db = database()
        rows = [(0x10, 0x1040, 'call'), (0x10, 0x1040, 'call'), (0x20, 0x1040, 'call'),  # 2 distinct callers
                (0x30, 0x1080, 'jmp'),                                                  # not a call
                (0x40, 0x1180, 'call'),                                                 # past VirtualSize
                (0x50, 0x2010, 'call'),                                                 # data section
                (0x60, 0x1000, 'call')]                                                 # already known
        db.executemany('INSERT INTO reference VALUES (?,?,?,?)', [(MODULE, *row) for row in rows])
        db.executemany('INSERT INTO vslot VALUES (?,?,?,?)',
                       [(MODULE, 0x2000, 0, 0x1060), (MODULE, 0x2008, 3, 0x1060), (MODULE, 0x2010, 1, 0x1040),
                        ('EDF6.exe', 0x2000, 0, 0x1050)])
        result = addresses.candidate_rows(db, MODULE, known={0x1000})
        self.assertEqual(result, [(0x1040, 2, 1), (0x1060, 0, 2)])

    def test_pointers_split_by_int3_alignment(self):
        db = database()
        image = bytearray(0x3000)
        image[0x103F] = 0xCC          # 0x1040: aligned, after INT3
        image[0x105F] = 0x90          # 0x1060: aligned, after NOP
        image[0x1047] = 0xCC          # 0x1048: after INT3 but not 16-aligned
        struct.pack_into('<Q', image, 0x2000, BASE + 0x1040)
        struct.pack_into('<Q', image, 0x2008, BASE + 0x1040)
        struct.pack_into('<Q', image, 0x2010, BASE + 0x2050)   # points to data: ignored
        struct.pack_into('<Q', image, 0x2018, BASE + 0x1060)   # HIGHLOW (type 3): ignored
        struct.pack_into('<Q', image, 0x2020, BASE + 0x1000)   # known
        pe = FakePE(bytes(image), [(0x2000, 10), (0x2008, 10), (0x2010, 10), (0x2018, 3), (0x2020, 10)])
        db.executemany('INSERT INTO instruction VALUES (?,?,?,?,?)',
                       [(MODULE, 0x1100, b'', 'lea', ''), (MODULE, 0x1108, b'', 'mov', ''),
                        (MODULE, 0x1110, b'', 'lea', '')])
        db.executemany('INSERT INTO reference VALUES (?,?,?,?)',
                       [(MODULE, 0x1100, 0x1060, 'rip'), (MODULE, 0x1108, 0x1048, 'rip'),  # mov: not lea
                        (MODULE, 0x1110, 0x1048, 'rip')])
        rows = addresses.pointer_rows(db, MODULE, pe, known={0x1000})
        self.assertEqual(rows, [(0x1040, [0x2000, 0x2008], [], 1), (0x1048, [], [0x1110], 0),
                                (0x1060, [], [0x1100], 0)])
        first, second = addresses.write_pointers(self.out, rows)
        self.assertEqual(first.read_text(encoding='ascii'), '0x00001040\n')
        self.assertEqual(second.read_text(encoding='ascii'), '0x00001048\n0x00001060\n')
        self.assertEqual((self.out / 'pointers.tsv').read_text(encoding='utf-8').splitlines()[1],
                         '0x00001040\t0x00002000,0x00002008\t\t1')

    def test_retry_takes_main_failures_not_fixed_by_unwind(self):
        write_functions(self.out, 'pseudocode', [(0x1000, 'ok'), (0x1010, 'failed'), (0x1020, 'failed')])
        write_functions(self.out, 'pseudocode-unwind', [(0x1010, 'ok'), (0x1030, 'failed')])
        # 0x1030 was only seeded by the unwind pass, so the saved project cannot retry it.
        self.assertEqual(addresses.retry_rvas(self.out, MODULE), [0x1020])

    def test_known_before_ignores_own_and_later_passes(self):
        write_functions(self.out, 'pseudocode', [(0x1000, 'ok')])
        write_functions(self.out, 'pseudocode-candidates', [(0x1010, 'ok')])
        write_functions(self.out, 'pseudocode-pointers', [(0x1020, 'ok')])
        addresses.write_list(self.out / 'addresses' / MODULE / 'candidates.txt', [0x1010, 0x1018])
        addresses.write_list(self.out / 'addresses' / MODULE / 'pointers.txt', [0x1020])
        self.assertEqual(addresses.known_before(self.out, MODULE, 'pseudocode-candidates'), {0x1000})
        # Candidates Ghidra rejected (0x1018) still count as tried for the later passes.
        self.assertEqual(addresses.known_before(self.out, MODULE, 'pseudocode-pointers'), {0x1000, 0x1010, 0x1018})

    def test_candidate_list_is_stable_when_recomputed_after_its_pass(self):
        db = database()
        db.executemany('INSERT INTO reference VALUES (?,?,?,?)',
                       [(MODULE, 0x10, 0x1040, 'call'), (MODULE, 0x20, 0x1050, 'call')])
        write_functions(self.out, 'pseudocode', [(0x1050, 'ok')])
        first = addresses.candidate_rows(db, MODULE, addresses.known_before(self.out, MODULE, 'pseudocode-candidates'))
        addresses.write_candidates(self.out / 'addresses' / MODULE, first)
        write_functions(self.out, 'pseudocode-candidates', [(0x1040, 'ok')])
        again = addresses.candidate_rows(db, MODULE, addresses.known_before(self.out, MODULE, 'pseudocode-candidates'))
        self.assertEqual(first, again)
        self.assertEqual(first, [(0x1040, 1, 0)])

    def test_angelscript_rvas_skip_blank_and_known(self):
        path = self.out / 'registrations.tsv'
        path.write_text('declaration\timplementation_rva\nA\t0x00001040\nB\t\nC\t0x00001000\nD\t0x00001040\n',
                        encoding='utf-8')
        self.assertEqual(addresses.angelscript_rvas(path, {0x1000}), [0x1040])

    def test_list_round_trip_and_missing_list(self):
        path = addresses.write_list(self.out / 'a' / 'b.txt', [0x1F, 0x12345678])
        self.assertEqual(path.read_text(encoding='ascii'), '0x0000001f\n0x12345678\n')
        self.assertEqual(addresses.read_list(path), {0x1F, 0x12345678})
        self.assertEqual(addresses.read_list(self.out / 'missing.txt'), set())
        self.assertFalse(list(self.out.rglob('*.tmp')))


if __name__ == '__main__':
    unittest.main()
