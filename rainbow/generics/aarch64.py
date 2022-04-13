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


class rainbow_aarch64(rainbowBase):

    STACK_ADDR = 0x20000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = [f"x{i}" for i in range(30)]
    TRACE_DISCARD = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.emu = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
        self.disasm = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
        self.disasm.detail = True
        self.word_size = 8
        self.endianness = "little"
        self.page_size = self.emu.query(uc.UC_QUERY_PAGE_SIZE)
        self.page_shift = self.page_size.bit_length() - 1
        self.pc = uc.arm64_const.UC_ARM64_REG_PC

        known_regs = [i[len('UC_ARM64_REG_'):] for i in dir(uc.arm64_const) if '_REG' in i]
        self.reg_map = {r.lower(): getattr(uc.arm64_const, 'UC_ARM64_REG_'+r) for r in known_regs}

        self.setup()

        self.reset_stack()

    def reset_stack(self):
        self.emu.reg_write(uc.arm64_const.UC_ARM64_REG_SP, self.STACK_ADDR)

    def start(self, *args, **kwargs):
        return self._start(*args, **kwargs)

    def return_force(self):
        self["pc"] = self["lr"]

    def block_handler(self, uci, address, size, user_data):
        self.base_block_handler(address)
