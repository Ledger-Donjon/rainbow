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


class rainbow_arm(Rainbow):

    STACK_ADDR = 0xb0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "pc", "lr"]
    TRACE_DISCARD = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.emu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
        self.disasm = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        self.disasm.detail = True
        self.WORD_SIZE = 4
        self.endianness = "little"
        self.pc = uc.arm_const.UC_ARM_REG_PC

        known_regs = [i[len('UC_ARM_REG_'):] for i in dir(uc.arm_const) if '_REG' in i]
        self.reg_map = {r.lower(): getattr(uc.arm_const, 'UC_ARM_REG_'+r) for r in known_regs}

        self.setup()

        self.reset_stack()

    def start(self, begin, *args, **kwargs):
        # ARM Thumb mode case
        thumb_bit = (self["cpsr"] >> 5) & 1
        return super().start(begin | thumb_bit, *args, **kwargs)

    def reset_stack(self):
        self.emu.reg_write(uc.arm_const.UC_ARM_REG_SP, self.STACK_ADDR)

    def return_force(self):
        self["pc"] = self["lr"]

    def block_handler(self, uci, address, size, user_data):
        # Thumb execution state bit is bit 5 in CPSR
        thumb_bit = (self["cpsr"]>>5) & 1
        if thumb_bit == 0:
            # switch disassembler to ARM mode
            self.disasm.mode = cs.CS_MODE_ARM
        else:
            self.disasm.mode = cs.CS_MODE_THUMB

        super().block_handler(uci, address | thumb_bit, size, user_data)
