"""Tests for tools/lint_shared.py. Standard library only; no game files needed."""

import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('lint_shared', ROOT / 'tools' / 'lint_shared.py')
lint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lint)

BUILD = 'test-1'
SHA = 'ab' * 32
BUILDS = ('build\tmodule\tsha256\ttimedatestamp\timage_base\tsize_of_image\tnotes\n'
          f'{BUILD}\tEDF.dll\t{SHA}\t0x12345678\t0x0000000180000000\t0x00010000\t\n')
FUNCTIONS_HEADER = 'build\trva\tname\tsignature\tconfidence\tevidence\tnotes\n'
DATA_HEADER = 'build\trva\tname\ttype\tconfidence\tevidence\tnotes\n'
TYPES_HEADER = 'build\toffset\tsize\tname\ttype\tconfidence\tevidence\tnotes\n'


def function_row(rva='0x00001000', name='Foo::Bar', confidence='likely', signature='', evidence='RTTI Foo'):
    return f'{BUILD}\t{rva}\t{name}\t{signature}\t{confidence}\t{evidence}\t\n'


class LintCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write('shared/builds.tsv', BUILDS)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding='utf-8', newline='\n')
        return path

    def lint(self, **options):
        return lint.run(self.root, **options)

    def assertClean(self, report):
        self.assertEqual(report.errors, [])

    def assertError(self, report, fragment):
        self.assertTrue(any(fragment in error for error in report.errors),
                        f'expected an error containing {fragment!r}, got {report.errors}')


class TableTests(LintCase):
    def test_minimal_valid_tables(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row()
                   + function_row('0x00001010', 'Foo::~Foo', 'confirmed', 'void __thiscall ~Foo(Foo * this)'))
        self.write('shared/data/EDF.dll.tsv', DATA_HEADER + f'{BUILD}\t0x00002000\tg_Foo\tFoo*\tguess\tstring ref\tnote\n')
        self.write('shared/types/Foo.tsv', TYPES_HEADER + f'{BUILD}\t0x0010\t4\thp\tfloat\tlikely\twrite at 0x1234\t\n'
                   + f'{BUILD}\t0x0014\t?\tblock\tstruct\tlikely\tread at 0x1238\t\n')
        self.write('shared/notes/vehicle.md', '# 载具\n\n```\nshort\n```\n')
        self.assertClean(self.lint())

    def test_comments_and_blank_lines_are_ignored(self):
        self.write('shared/functions/EDF.dll.tsv', '# comment\n\n' + FUNCTIONS_HEADER + function_row())
        self.assertClean(self.lint())

    def test_bad_header(self):
        self.write('shared/functions/EDF.dll.tsv', 'rva\tname\n' + function_row())
        self.assertError(self.lint(), 'header must be')

    def test_column_count(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + f'{BUILD}\t0x00001000\tFoo\n')
        self.assertError(self.lint(), 'expected 7 tab-separated columns, found 3')

    def test_rva_format(self):
        for bad in ('0x1000', '0x00001a00', '00001000', '0x000010000'):
            with self.subTest(bad=bad):
                self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row(bad))
                self.assertError(self.lint(), 'must be 8 upper-case hex digits')

    def test_rva_outside_image(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row('0x00010000'))
        self.assertError(self.lint(), 'outside image')

    def test_unknown_build(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row().replace(BUILD, 'other-2', 1))
        self.assertError(self.lint(), 'is not listed in builds.tsv')

    def test_module_must_match_file(self):
        self.write('shared/functions/EDF6.exe.tsv', FUNCTIONS_HEADER + function_row())
        self.assertError(self.lint(), 'module EDF6.exe is not listed')

    def test_confidence_values(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row(confidence='high'))
        self.assertError(self.lint(), 'confidence must be one of')

    def test_evidence_required(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row(evidence=''))
        self.assertError(self.lint(), 'evidence is empty')

    def test_name_rules(self):
        cases = {'sub_180001000': 'auto-generated', 'FUN_180001000': 'auto-generated', 'Foo::thunk_FUN_00401000':
                 'auto-generated', '中文名': 'must be ASCII', 'Foo Bar': 'invalid characters', 'Foo::': 'invalid',
                 'Foo::vslot_3': 'auto-generated'}
        for name, fragment in cases.items():
            with self.subTest(name=name):
                self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row(name=name))
                self.assertError(self.lint(), fragment)

    def test_duplicate_rva_and_name(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row() + function_row(name='Other'))
        self.assertError(self.lint(), 'already named')
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row() + function_row('0x00001010'))
        self.assertError(self.lint(), 'already used')

    def test_conflict_between_functions_and_data(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row())
        self.write('shared/data/EDF.dll.tsv', DATA_HEADER + f'{BUILD}\t0x00001000\tg_X\tint\tlikely\tx\t\n')
        report = self.lint()
        self.assertClean(report)  # separate namespaces per kind, checked independently

    def test_signature_shape(self):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + function_row(signature='int'))
        self.assertError(self.lint(), 'signature must look like')

    def test_crlf_and_bom(self):
        self.write('shared/functions/EDF.dll.tsv', (FUNCTIONS_HEADER + function_row()).replace('\n', '\r\n').encode())
        self.assertError(self.lint(), 'LF line endings')
        self.write('shared/functions/EDF.dll.tsv', b'\xef\xbb\xbf' + (FUNCTIONS_HEADER + function_row()).encode())
        self.assertError(self.lint(), 'BOM')

    def test_type_overlap_and_offsets(self):
        self.write('shared/types/Foo.tsv', TYPES_HEADER + f'{BUILD}\t0x0010\t8\ta\tu64\tlikely\tx\t\n'
                   + f'{BUILD}\t0x0014\t4\tb\tu32\tlikely\tx\t\n')
        self.assertError(self.lint(), 'overlaps field')
        self.write('shared/types/Foo.tsv', TYPES_HEADER + f'{BUILD}\t0x10\t4\ta\tu32\tlikely\tx\t\n')
        self.assertError(self.lint(), 'offset')
        self.write('shared/types/Foo.tsv', TYPES_HEADER + f'{BUILD}\t0x0010\t4\ta\tu32\tlikely\tx\t\n'
                   + f'{BUILD}\t0x0020\t4\ta\tu32\tlikely\tx\t\n')
        self.assertError(self.lint(), "field name 'a' already used")

    def test_builds_table(self):
        self.write('shared/builds.tsv', BUILDS + BUILDS.splitlines(True)[1])
        self.assertError(self.lint(), 'duplicate build/module')
        self.write('shared/builds.tsv', BUILDS.replace('0x12345678', '12345678'))
        self.assertError(self.lint(), 'timedatestamp')

    def test_unexpected_layout(self):
        self.write('shared/misc.txt', 'x\n')
        self.write('shared/functions/sub/EDF.dll.tsv', FUNCTIONS_HEADER)
        report = self.lint()
        self.assertError(report, 'unexpected entry in shared/')
        self.assertError(report, 'must not contain sub-directories')

    def test_translated_readme_allowed(self):
        self.write('shared/README.en.md', 'English\n')
        self.assertNotIn('unexpected entry', '\n'.join(map(str, self.lint().errors)))

    def test_note_code_block_limit(self):
        body = '\n'.join(f'line {i}' for i in range(11))
        self.write('shared/notes/long.md', f'# x\n\n```c\n{body}\n```\n')
        self.assertError(self.lint(), 'code block has 11 lines')
        self.write('shared/notes/long.md', '# x\n')
        self.write('shared/notes/dump.c', 'int x;\n')
        self.assertError(self.lint(), 'only accepts Markdown')


class ArtifactGuardTests(LintCase):
    def test_forbidden_suffixes(self):
        for name in ('out.asm', 'vanilla.sqlite', 'entries.c', 'mission.bvm', 'script.ac', 'Root.cpk',
                     'model.sgo', 'EDF.dll'):
            with self.subTest(name=name):
                path = self.write(f'dump/{name}', 'x\n')
                self.assertTrue(any(name in error for error in self.lint().errors))
                path.unlink()

    def test_size_limit(self):
        self.write('big.md', 'a' * 200)
        self.assertError(self.lint(max_bytes=100), 'exceeds the 100-byte limit')

    def test_ghidra_output_detected(self):
        placeholder = 'undefined' + '8'
        function = 'FUN' + '_180012345'
        text = '\n'.join(f'{placeholder} {function}(longlong param_1) {{ return 0; }}' for _ in range(12))
        self.write('notes.txt', text + '\n')
        self.assertError(self.lint(), 'looks like decompiler output')

    def test_disassembly_detected(self):
        lines = '\n'.join(f'0x{0x180001000 + i * 4:016X}: 48 8b 05 00 mov rax, [rip]' for i in range(40))
        self.write('listing.txt', lines + '\n')
        self.assertError(self.lint(), 'looks like a disassembly dump')

    def test_binary_detected(self):
        self.write('blob.json', b'{\0\0\0}')
        self.assertError(self.lint(), 'binary file')

    def test_guard_can_be_disabled(self):
        self.write('x.asm', 'x\n')
        self.assertClean(self.lint(guard=False))

    # (a) headers, AngelScript sources and missions.py's output names
    def test_mission_artifact_names(self):
        for name in ('dump/common.h', 'dump/Script.AS', 'dump/MISSION.H', 'dump/MISSION.BVM.asm', 'native-usage.tsv',
                     'gen/provenance.json', 'EDF.dll.provenance.json', 'Root.cpk/MISSION/M001/notes.txt'):
            with self.subTest(name=name):
                path = self.write(name, 'x\n')
                self.assertTrue(any(error.startswith(name + ':') for error in self.lint().errors), self.lint().errors)
                path.unlink()

    def test_mission_index_by_header(self):
        self.write('renamed.tsv', 'archive\tsource\tformat\tsource_sha256\toutput\tlines\n')
        self.assertError(self.lint(), 'missions.py index')
        self.write('renamed.tsv', 'native_table\tnative_id\tcall_sites\tscript_count\tsignature_known\n')
        self.assertError(self.lint(), 'missions.py index')
        self.write('renamed.tsv', 'build\trva\tname\n')
        self.assertClean(self.lint())

    # (b) disassembly without the machine-code column
    def test_disassembly_without_bytes_detected(self):
        ops = ('mov          rax, qword ptr [rcx + 0x10]', 'lea          rdx, [rip + 0x1234]', 'test         eax, eax',
               'call         qword ptr [rax + 0x18]', 'xor          r8d, r8d')
        lines = '\n'.join(f'{0x1000 + 4 * i:08X}  {ops[i % len(ops)]}' for i in range(25))
        self.write('listing.txt', lines + '\n')
        self.assertError(self.lint(), 'this looks like a disassembly listing')
        refs = '\n'.join(f'0x{0x2000 + i:08X} -> 0x{0x9000 + i:08X}  call    mov rcx, [rbx + 0x8]' for i in range(25))
        self.write('listing.txt', refs + '\n')
        self.assertError(self.lint(), 'this looks like a disassembly listing')

    def test_address_prose_not_disassembly(self):
        prose = '\n'.join(f'- 0x{0x1000 + i:08X} Vehicle::Update{i}: moves the seat input into the vehicle block'
                          for i in range(60))
        self.write('notes.md', prose + '\n')
        self.assertClean(self.lint())

    # (d) decompiler output by density
    def test_single_function_with_new_tokens_detected(self):
        p, v, loc = 'param' + '_', 'Var', 'local' + '_'
        body = [f'void Thing(long long {p}1, int {p}2)', '{',
                f'  long long l{v}1;', f'  unsigned int u{v}2;', f'  char {loc}28 [16];',
                f'  l{v}1 = *(long long *)({p}1 + 0x10);', f'  u{v}2 = CON' + f'CAT44({p}2, {p}2);',
                f'  if (l{v}1 != 0) {{ pu{v}3 = (unsigned *)l{v}1; }}', f'  return (int)u{v}2;', '}']
        self.write('snippet.txt', '\n'.join(body) + '\n')
        self.assertError(self.lint(), 'looks like decompiler output')

    def test_function_inside_long_prose_detected(self):
        p, v = 'param' + '_', 'Var'
        prose = '\n'.join(f'Ordinary sentence number {i} about the vehicle seat.' for i in range(300))
        code = '\n'.join(f'  u{v}{i} = *(unsigned *)({p}1 + {i * 8}) + {p}2;' for i in range(8))
        self.write('long.md', f'{prose}\n{code}\n{prose}\n')
        self.assertError(self.lint(), 'consecutive non-blank lines')

    def test_sparse_tokens_not_flagged(self):
        p = 'param' + '_'
        lines = [f'The handler reads {p}1 as the seat index.', 'It writes the result to the vehicle block.',
                 'Nothing else is read.'] * 4
        self.write('note.md', '\n'.join(lines) + '\n')
        self.assertClean(self.lint())


class NoteBlockTests(LintCase):
    def test_unclosed_fence(self):
        self.write('shared/notes/open.md', '# x\n\n```c\nint a;\n')
        self.assertError(self.lint(), 'never closed')

    def test_long_fence_and_longer_closer(self):
        body = '\n'.join(f'line {i}' for i in range(11))
        self.write('shared/notes/long.md', f'# x\n\n````\n```\n{body}\n````\n')
        self.assertError(self.lint(), 'code block has 12 lines')
        self.write('shared/notes/long.md', f'# x\n\n~~~\n{chr(10).join(body.split(chr(10))[:9])}\n~~~\n')
        self.assertClean(self.lint())

    def test_indented_block_counted(self):
        body = '\n'.join(f'    line {i}' for i in range(11))
        self.write('shared/notes/indent.md', f'# x\n\n{body}\n')
        self.assertError(self.lint(), 'code block has 11 lines')
        tab = '\n'.join(f'\tline {i}' for i in range(6)) + '\n\n' + '\n'.join(f'\tline {i}' for i in range(5))
        self.write('shared/notes/indent.md', f'# x\n\n{tab}\n')
        self.assertError(self.lint(), 'code block has 12 lines')

    def test_indented_list_and_paragraph_not_code(self):
        items = '\n'.join(f'- item {i}\n\n  continued paragraph {i}\n    - nested {i}' for i in range(12))
        lazy = 'A paragraph\n' + '\n'.join(f'    wrapped line {i}' for i in range(12))
        self.write('shared/notes/list.md', f'# x\n\n{items}\n\n{lazy}\n')
        self.assertClean(self.lint())

    def test_indented_code_inside_list_counted(self):
        code = '\n'.join(f'      line {i}' for i in range(11))
        self.write('shared/notes/list.md', f'# x\n\n- item\n\n{code}\n')
        self.assertError(self.lint(), 'code block has 11 lines')


class HistoryTests(unittest.TestCase):
    """(e) every file version a commit added or modified, even if a later commit deletes it."""

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], capture_output=True, text=True, check=True).stdout

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'test')
        self.git('config', 'commit.gpgsign', 'false')
        (self.root / 'README.md').write_text('x\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-q', '-m', 'base')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def tearDown(self):
        self.temp.cleanup()

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '-m', message)

    def test_added_then_deleted_is_caught(self):
        (self.root / 'dump.asm').write_text('x\n', encoding='utf-8')
        lines = '\n'.join(f'{0x1000 + 4 * i:08X}  mov          rax, qword ptr [rcx + {i}]' for i in range(25))
        (self.root / 'notes.txt').write_text(lines + '\n', encoding='utf-8')
        self.commit('add')
        (self.root / 'dump.asm').unlink()
        (self.root / 'notes.txt').write_text('clean\n', encoding='utf-8')
        self.commit('remove again')
        self.assertEqual(lint.run(self.root).errors, [])
        for spec in (f'{self.base}...HEAD', f'{self.base}..HEAD'):
            with self.subTest(spec=spec):
                report = lint.run(self.root, guard=False, history=spec)
                self.assertEqual(report.history, (2, 3))
                self.assertTrue(any(':dump.asm:1: error:' in error for error in report.errors), report.errors)
                self.assertTrue(any(':notes.txt:1: error:' in error and 'disassembly listing' in error
                                    for error in report.errors), report.errors)

    def test_clean_range_and_cli(self):
        (self.root / 'ok.md').write_text('fine\n', encoding='utf-8')
        self.commit('ok')
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = lint.main(['--root', str(self.root), '--history', f'{self.base}...HEAD'])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn('1 commit(s), 1 file version(s)', err.getvalue())
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(lint.main(['--root', str(self.root), '--history', 'no-such-rev..HEAD']), 2)


def make_pe(text_bytes, pdata, trailer=b''):
    """Build a minimal PE32+ with an executable .text at RVA 0x1000 and a .pdata at RVA 0x2000.

    pdata holds (begin, end) or (begin, end, unwind_rva); trailer bytes follow the table (unwind info)."""
    file_align = 0x200
    headers = bytearray(0x400)
    headers[0:2] = b'MZ'
    struct.pack_into('<I', headers, 0x3C, 0x80)
    headers[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', headers, 0x84, 0x8664, 2, 0x12345678, 0, 0, 240, 0x2022)
    opt = 0x98
    struct.pack_into('<H', headers, opt, 0x20B)
    struct.pack_into('<Q', headers, opt + 24, 0x180000000)
    struct.pack_into('<II', headers, opt + 32, 0x1000, file_align)
    struct.pack_into('<I', headers, opt + 56, 0x10000)
    struct.pack_into('<I', headers, opt + 60, 0x400)
    struct.pack_into('<I', headers, opt + 108, 16)
    table_bytes = b''.join(struct.pack('<III', *(entry + (0,))[:3]) for entry in pdata)
    struct.pack_into('<II', headers, opt + 112 + 3 * 8, 0x2000, len(table_bytes))
    pdata_bytes = table_bytes + trailer
    table = opt + 240
    text = bytes(text_bytes).ljust(file_align, b'\xcc')
    pdata_raw = pdata_bytes.ljust(file_align, b'\0')
    struct.pack_into('<8sIIII', headers, table, b'.text', len(text_bytes), 0x1000, len(text), 0x400)
    struct.pack_into('<I', headers, table + 36, 0x60000020)
    struct.pack_into('<8sIIII', headers, table + 40, b'.pdata', len(pdata_bytes), 0x2000, len(pdata_raw), 0x600)
    struct.pack_into('<I', headers, table + 40 + 36, 0x40000040)
    return bytes(headers) + text + pdata_raw


class GameCheckTests(LintCase):
    def setUp(self):
        super().setUp()
        code = bytearray(b'\xcc' * 0x100)
        code[0x00:0x01] = b'\xc3'      # 0x1000 function with .pdata 0x1000-0x1020
        code[0x40:0x41] = b'\xc3'      # 0x1040 leaf after int3 padding
        image = make_pe(code, [(0x1000, 0x1020)])
        self.game = self.root / 'game'
        self.game.mkdir()
        (self.game / 'EDF.dll').write_bytes(image)
        import hashlib
        digest = hashlib.sha256(image).hexdigest()
        self.write('shared/builds.tsv', BUILDS.replace(SHA, digest).replace('0x00010000', '0x00010000'))

    def run_game(self, rows):
        self.write('shared/functions/EDF.dll.tsv', FUNCTIONS_HEADER + ''.join(rows))
        return self.lint(game=self.game, guard=False)

    def test_function_start_ok(self):
        report = self.run_game([function_row('0x00001000'), function_row('0x00001040', 'Leaf')])
        self.assertClean(report)
        self.assertEqual(report.warnings, [])

    def test_mid_function_rejected(self):
        self.assertError(self.run_game([function_row('0x00001008')]), 'inside the .pdata function starting at 0x00001000')

    def test_chained_fragment_rejected(self):
        # Two entries: 0x1000 primary, 0x1080 fragment whose unwind info chains back to 0x1000.
        entries = 24
        primary_info = 0x2000 + entries
        fragment_info = primary_info + 4
        trailer = bytes([1, 0, 0, 0]) + bytes([1 | (4 << 3), 0, 0, 0]) + struct.pack('<III', 0x1000, 0x1020, primary_info)
        code = bytearray(b'\xcc' * 0x100)
        image = make_pe(code, [(0x1000, 0x1020, primary_info), (0x1080, 0x10A0, fragment_info)], trailer)
        (self.game / 'EDF.dll').write_bytes(image)
        import hashlib
        self.write('shared/builds.tsv', BUILDS.replace(SHA, hashlib.sha256(image).hexdigest()))
        self.assertError(self.run_game([function_row('0x00001080')]), 'chained unwind fragment of the function at 0x00001000')

    def test_non_executable_rejected(self):
        self.assertError(self.run_game([function_row('0x00002000')]), 'non-executable section')

    def test_header_mismatch_reported(self):
        self.write('shared/builds.tsv', self.root.joinpath('shared/builds.tsv').read_text(encoding='utf-8')
                   .replace('0x12345678', '0x12345679'))
        self.assertError(self.run_game([function_row()]), 'timedatestamp is 0x12345678')

    def test_unknown_sha_skips(self):
        (self.game / 'EDF.dll').write_bytes(b'MZ' + b'\0' * 100)
        report = self.run_game([function_row('0x00001008')])
        self.assertClean(report)
        self.assertTrue(any('PE checks skipped' in warning for warning in report.warnings))


class RepositoryTests(unittest.TestCase):
    def test_repository_passes(self):
        report = lint.run(ROOT)
        self.assertEqual(report.errors, [])

    def test_cli_exit_codes(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools' / 'lint_shared.py'), '--root', str(ROOT)],
                                capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'x.cpk').write_bytes(b'x')
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = lint.main(['--root', temp])
            self.assertEqual(code, 1)
            self.assertIn('x.cpk:1: error:', out.getvalue())


if __name__ == '__main__':
    unittest.main()
