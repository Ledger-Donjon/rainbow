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


class rainbow_aarch64(Rainbow):
    UC_ARCH = uc.UC_ARCH_ARM64
    UC_MODE = uc.UC_MODE_ARM
    CS_ARCH = cs.CS_ARCH_ARM64
    CS_MODE = cs.CS_MODE_ARM
    STACK_ADDR = 0x20000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = [f"x{i}" for i in range(30)]
    TRACE_DISCARD = []
    WORD_SIZE = 8
    ENDIANNESS = "little"
    PC = uc.arm64_const.UC_ARM64_REG_PC
    REGS = {name[len('UC_ARM64_REG_'):].lower(): getattr(uc.arm64_const, name) for name in dir(uc.arm64_const) if
            "_REG" in name}
    OTHER_REGS = {}

    def reset_stack(self):
        self.emu.reg_write(uc.arm64_const.UC_ARM64_REG_SP, self.STACK_ADDR)

    def return_force(self):
        self["pc"] = self["lr"]
