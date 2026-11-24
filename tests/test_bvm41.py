"""Tests for BVM container parsing / disassembly / stack checking (edf6re_lib/bvm41.py); all use synthetic scripts and never read game files.

Run: python -B -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from edf6re_lib import bvm41  # noqa: E402
from edf6re_lib.bvm41 import Function, Ins, Program  # noqa: E402

import missions  # noqa: E402


def program(push=True):
    """Main(): one native 0/17 (reads one int, leaves nothing) on a literal, then back to the epilogue."""
    body = [Ins(bvm41.OP_FPSUB, 1, 1), Ins(bvm41.OP_STOREL, 0)]
    if push:
        body.append(Ins(bvm41.OP_PUSH, 5, 1))
    body += [Ins(bvm41.OP_PUSHS, 'synthetic'), Ins(bvm41.OP_POP),
             Ins(bvm41.OP_NAT0, 17, 1), Ins(bvm41.OP_JMP, 0)]
    code = [Ins(bvm41.OP_PUSHL, 0), Ins(bvm41.OP_FPADD, 1, 1), Ins(bvm41.OP_RET)] + body
    return Program('Mission', ['g_value'], [Ins(bvm41.OP_PUSH, 0), Ins(bvm41.OP_STOREG, 0), Ins(bvm41.OP_END)],
                   [Function('Main', b'', code)])


class ContainerTest(unittest.TestCase):
    def test_round_trip(self):
        data = bvm41.build(program())
        parsed = bvm41.parse(data)
        self.assertEqual(parsed.name, 'Mission')
        self.assertEqual(parsed.globals, ['g_value'])
        self.assertEqual([f.name for f in parsed.funcs], ['Main'])
        self.assertEqual(bvm41.build(parsed), data)

    def test_rejects_non_bvm(self):
        with self.assertRaises(ValueError):
            bvm41.parse(b'NOPE' + bytes(0x60))

    def test_stack_check(self):
        self.assertEqual(bvm41.stack_check(bvm41.parse(bvm41.build(program()))), [])
        issues = bvm41.stack_check(bvm41.parse(bvm41.build(program(push=False))))
        self.assertTrue(any('epilogue' in issue for issue in issues), issues)

    def test_native_calls_see_literal_type(self):
        calls = bvm41.native_calls(bvm41.parse(bvm41.build(program())), {(bvm41.OP_NAT0, 17)})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][3][0].t, 'i')
        self.assertEqual(bvm41.type_check(bvm41.parse(bvm41.build(program()))), [])

    def test_listing(self):
        data = bvm41.build(program())
        sites = []
        text, functions, instructions = missions.bvm_listing(data, bvm41, sites)
        self.assertEqual(functions, 1)
        self.assertIn('; Main entry=0x', text)
        self.assertIn('native[0]', text)
        self.assertEqual([(table, number) for table, number, _, _ in sites], [(0, 17)])
        self.assertGreater(instructions, 0)

    def test_no_conversion_payload(self):
        # The public module is container + analysis only: no 4.1 -> EDF5 conversion tables or shipped script code.
        for name in ('EDF5_LIBRARY', 'convert', 'to_edf5', 'rewritten', 'TABLE1', 'NATIVES', 'SERGENT',
                     'RESULT_SCREENS', 'ENGINE_EVIDENCE', 'NET41', 'UnsupportedNative', 'edf6_strings'):
            self.assertFalse(hasattr(bvm41, name), name)


if __name__ == '__main__':
    unittest.main()
