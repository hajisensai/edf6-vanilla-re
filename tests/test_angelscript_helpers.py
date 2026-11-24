"""asSFuncPtr helper recognition in angelscript_index.py, on hand-written x64 snippets (no game bytes).

Needs capstone / pefile (requirements.txt); skipped when they are not installed (CI installs no dependencies).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
HAVE_DEPS = all(importlib.util.find_spec(name) for name in ('capstone', 'pefile'))

RET = 'c3'
MOV_RAX_RCX = '488bc1'            # mov rax, rcx
MOV_MEM_RCX_RDX = '488911'        # mov qword ptr [rcx], rdx
MOV_MEM_RCX_RCX = '488909'        # mov qword ptr [rcx], rcx
MOV_MEM_RCX8_0 = '48c7410800000000'   # mov qword ptr [rcx + 8], 0
MOV_HOME_RDX = '4889542410'       # mov qword ptr [rsp + 0x10], rdx
MOVZX_EAX_HOME1 = '0fb6442411'    # movzx eax, byte ptr [rsp + 0x11]
MOV_MEM_RCX1_AL = '884101'        # mov byte ptr [rcx + 1], al
MOV_MEM_RCX_DL = '8811'           # mov byte ptr [rcx], dl
MOV_MEM_RDX_RCX = '48890a'        # mov qword ptr [rdx], rcx
ADD_RCX_8 = '4883c108'            # add rcx, 8


@unittest.skipUnless(HAVE_DEPS, 'capstone / pefile not installed')
class PointerHelperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import angelscript_index
        cls.module = angelscript_index

    def check(self, *parts):
        code = bytes.fromhex(''.join(parts))
        return self.module.is_pointer_helper(b'\xcc' * 0x10 + code + b'\xcc' * 0x10, 0x10)

    def test_direct_store(self):
        self.assertTrue(self.check(MOV_MEM_RCX8_0, MOV_RAX_RCX, MOV_MEM_RCX_RDX, RET))

    def test_byte_copy_through_home_space(self):
        # Copies RDX through its home slot one byte at a time, like a debug build of the helper.
        parts = [MOV_HOME_RDX]
        for index in range(1, 8):
            parts += [f'0fb64424{0x10 + index:02x}', f'8841{index:02x}']
        self.assertTrue(self.check(*parts, MOV_RAX_RCX, MOV_MEM_RCX_DL, RET))

    def test_rejects_other_behaviour(self):
        self.assertFalse(self.check(MOV_RAX_RCX, MOV_MEM_RCX_RCX, RET))           # stores the wrong value
        self.assertFalse(self.check(MOV_MEM_RCX_RDX, RET))                         # does not return the object
        self.assertFalse(self.check(MOV_RAX_RCX, MOV_MEM_RCX_RDX, MOV_MEM_RDX_RCX, RET))  # writes elsewhere
        self.assertFalse(self.check(ADD_RCX_8, MOV_RAX_RCX, MOV_MEM_RCX_RDX, RET))  # unsupported instruction
        self.assertFalse(self.check(MOVZX_EAX_HOME1, MOV_MEM_RCX1_AL, RET))         # reads unwritten memory
        self.assertFalse(self.check(MOV_RAX_RCX, MOV_MEM_RCX_RDX))                  # never returns


if __name__ == '__main__':
    unittest.main()
