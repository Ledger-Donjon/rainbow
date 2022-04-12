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
from rainbow.rainbow import rainbowBase
from rainbow.color_functions import color


class rainbow_x64(rainbowBase):

    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x100000, STACK_ADDR + 32)
    INTERNAL_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rip"]
    TRACE_DISCARD = ["rflags"]

    def __init__(self, local_vars={}, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.emu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        self.disasm = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.disasm.detail = True
        self.word_size = 8
        self.endianness = "little"
        self.page_size = self.emu.query(uc.UC_QUERY_PAGE_SIZE)
        self.page_shift = self.page_size.bit_length() - 1
        self.pc = uc.x86_const.UC_X86_REG_RIP

        # workaround for capstone 4
        uc.x86_const.UC_X86_REG_RFLAGS = uc.x86_const.UC_X86_REG_EFLAGS

        known_regs = [i[len('UC_X86_REG_'):] for i in dir(uc.x86_const) if '_REG' in i]
        self.reg_map = {r.lower(): getattr(uc.x86_const, 'UC_X86_REG_'+r) for r in known_regs}

        self.stubbed_functions = local_vars
        self.setup()

        self.reset_stack()

    def reset_stack(self):
        self.emu.reg_write(uc.x86_const.UC_X86_REG_RBP, self.STACK_ADDR)
        self.emu.reg_write(uc.x86_const.UC_X86_REG_RSP, self.STACK_ADDR)

    def start(self, begin, end, timeout=0, count=0):
        return self._start(begin, end, timeout, count)

    def return_force(self):
        ret = self[self["rsp"]]
        self["rsp"] += self.word_size
        self["rip"] = int.from_bytes(ret, "little")

    def block_handler(self, uci, address, size, user_data):
        return self.base_block_handler(address)
