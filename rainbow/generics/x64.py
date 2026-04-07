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

from rainbow.rainbow import Rainbow


class rainbow_x64(Rainbow):
    ARCH_NAME = "amd64"
    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x100000, STACK_ADDR + 32)
    INTERNAL_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rip"]
    IGNORED_REGS = {"rflags"}
    PC_NAME = "rip"
    SP_NAME = ["rbp", "rsp"]
    # workaround for capstone 4
    # TODO: Not sure whether this is enough
    # REGS = {**BASE_REGS, "uc_x86_reg_rflags": uc.x86_const.UC_X86_REG_EFLAGS}
    OTHER_REGS = {}

    def return_force(self):
        ret = self[self["rsp"]]
        self["rsp"] += 8
        self["rip"] = int.from_bytes(ret, "little")
