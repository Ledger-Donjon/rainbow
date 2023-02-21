# This file is part of rainbow
#
# rainbow is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# Copyright 2019 Victor Servant, Ledger SAS

import unicorn as uc
import capstone as cs
from rainbow.rainbow import Rainbow


class rainbow_x86(Rainbow):

    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "eip", "ebp"]
    TRACE_DISCARD = ["eflags"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.emu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        self.disasm = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.disasm.detail = True
        self.word_size = 4
        self.endianness = "little"
        self.page_size = self.emu.query(uc.UC_QUERY_PAGE_SIZE)
        self.page_shift = self.page_size.bit_length() - 1
        self.pc = uc.x86_const.UC_X86_REG_EIP

        known_regs = [i[len('UC_X86_REG_'):] for i in dir(uc.x86_const) if '_REG' in i]
        self.reg_map = {r.lower(): getattr(uc.x86_const, 'UC_X86_REG_'+r) for r in known_regs}

        self.setup()

        self.reset_stack()

    def reset_stack(self):
        self.emu.reg_write(uc.x86_const.UC_X86_REG_EBP, self.STACK_ADDR)
        self.emu.reg_write(uc.x86_const.UC_X86_REG_ESP, self.STACK_ADDR)

    def return_force(self):
        ret = self[self["esp"]]
        self["esp"] += self.word_size
        self["eip"] = int.from_bytes(ret, "little")
