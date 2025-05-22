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

import capstone as cs
from rainbow.rainbow import Rainbow


class rainbow_arm(Rainbow):
    ARCH_NAME = "arm"
    STACK_ADDR = 0xb0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "pc", "lr"]
    IGNORED_REGS = set()
    PC_NAME = "pc"
    SP_NAME = ["sp"]
    OTHER_REGS = {}

    @property
    def thumb_bit(self) -> int:
        # Thumb execution state bit is bit 5 in CPSR
        return (self["cpsr"] >> 5) & 1

    def start(self, begin, *args, **kwargs):
        return super().start(begin | self.thumb_bit, *args, **kwargs)

    def return_force(self):
        self["pc"] = self["lr"]

    def _block_hook(self, uci, address, size, user_data):
        if self.thumb_bit == 0:
            # switch disassembler to ARM mode
            self.disasm.mode = cs.CS_MODE_ARM
        else:
            self.disasm.mode = cs.CS_MODE_THUMB

        super()._block_hook(uci, address | self.thumb_bit, size, user_data)
