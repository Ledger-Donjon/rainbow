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


class rainbow_x86(Rainbow):
    UC_ARCH = uc.UC_ARCH_X86
    UC_MODE = uc.UC_MODE_32
    CS_ARCH = cs.CS_ARCH_X86
    CS_MODE = cs.CS_MODE_32
    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "eip", "ebp"]
    IGNORED_REGS = {"eflags"}
    WORD_SIZE = 4
    ENDIANNESS = "little"
    PC = uc.x86_const.UC_X86_REG_EIP
    REGS = {name[len('UC_X86_REG_'):].lower(): getattr(uc.x86_const, name) for name in dir(uc.x86_const) if
            "_REG" in name}
    OTHER_REGS = {}

    def reset_stack(self):
        self.emu.reg_write(uc.x86_const.UC_X86_REG_EBP, self.STACK_ADDR)
        self.emu.reg_write(uc.x86_const.UC_X86_REG_ESP, self.STACK_ADDR)

    def return_force(self):
        ret = self[self["esp"]]
        self["esp"] += self.WORD_SIZE
        self["eip"] = int.from_bytes(ret, "little")
