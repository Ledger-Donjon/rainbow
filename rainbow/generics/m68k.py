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
# Copyright 2023 Jan Jancar

import unicorn as uc
import capstone as cs
from rainbow.rainbow import Rainbow


class rainbow_m68k(Rainbow):
    UC_ARCH = uc.UC_ARCH_M68K
    UC_MODE = uc.UC_MODE_BIG_ENDIAN
    CS_ARCH = cs.CS_ARCH_M68K
    CS_MODE = cs.CS_MODE_M68K_000
    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = [f"d{i}" for i in range(8)] + [f"a{i}" for i in range(8)] + ["pc"]
    IGNORED_REGS = set()
    WORD_SIZE = 4
    ENDIANNESS = "big"
    PC = uc.m68k_const.UC_M68K_REG_PC
    REGS = {name[len('UC_M68K_REG_'):].lower(): getattr(uc.m68k_const, name) for name in dir(uc.m68k_const) if
            "_REG" in name}
    OTHER_REGS = {}

    def reset_stack(self):
        self.emu.reg_write(uc.m68k_const.UC_M68K_REG_A7, self.STACK_ADDR)

    def return_force(self):
        ret = self[self["a7"]]
        self["a7"] += self.WORD_SIZE
        self["pc"] = int.from_bytes(ret, "big")
