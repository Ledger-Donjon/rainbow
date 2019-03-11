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
from struct import unpack
from rainbow.rainbow import rainbowBase
from rainbow.color_functions import color


class rainbow_cortexm(rainbowBase):

    STACK_ADDR = 0x90000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "pc", "lr"]
    TRACE_DISCARD = []

    def __init__(self, trace=True, sca_mode=False, local_vars={}):
        super().__init__(trace, sca_mode)
        self.emu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB | uc.UC_MODE_MCLASS)
        self.disasm = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | cs.CS_MODE_MCLASS)
        self.disasm.detail = True
        self.word_size = 4
        self.endianness = "little"
        self.page_size = self.emu.query(uc.UC_QUERY_PAGE_SIZE)
        self.page_shift = self.page_size.bit_length() - 1
        self.uc_reg = "uc.arm_const.UC_ARM_REG_"
        self.pc = "pc"

        self.stubbed_functions = local_vars
        self.setup(sca_mode)

        self.emu.reg_write(uc.arm_const.UC_ARM_REG_SP, self.STACK_ADDR)
        self.emu.reg_write(uc.arm_const.UC_ARM_REG_APSR, 0)

        # Force mapping of those addresses so that
        # exception returns can be caught in the base
        # block hook rather than a code fetch hook
        self[0xfffffff0] = 0

        self.emu.hook_add(uc.UC_HOOK_INTR, self.intr_hook)

    def intr_hook(self, uci, intno, data):
        # Hack : pretend this is all exceptions at once
        self['ipsr'] = 0xfffffff

        sp = self["sp"] - 32
        self["sp"] = sp
        self[sp +  0] = self["r0"]
        self[sp +  4] = self["r1"]
        self[sp +  8] = self["r2"]
        self[sp + 12] = self["r3"]
        self[sp + 16] = self["r12"]
        self[sp + 20] = self["r14"]
        self[sp + 24] = self["pc"] | 1
        self[sp + 28] = self["APSR"]
        self['control'] = 0

        # TODO: handle other software-triggered exceptions (like bkpt)
        self["pc"] = self.functions["SVC_Handler"] | 1
        return True

    def start(self, begin, end, timeout=0, count=0):
        return self._start(begin | 1, end, timeout, count)

    def return_force(self):
        self["pc"] = self["lr"]

    def block_handler(self, uci, address, size, user_data):
        if (address & 0xfffffff0) == 0xfffffff0:
            is_psp = (address >> 2) & 1
            is_unpriv = (address >> 3) & 1
            self['control'] = (is_psp << 1) | is_unpriv

            sp = self["sp"]
            nvic_stack_bytes = self[sp:sp+32]
            nvic_stack = unpack('8I', nvic_stack_bytes)

            for i, reg in enumerate(['r0','r1','r2','r3','r12','r14','pc','APSR']):
                self[reg] = nvic_stack[i]

            self["sp"] = sp + 32
            return True

        self.base_block_handler(address)
