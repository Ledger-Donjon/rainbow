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


class rainbow_x86(Rainbow):
    ARCH_NAME = "x86"
    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "eip", "ebp"]
    IGNORED_REGS = {"eflags"}
    PC_NAME = "eip"
    SP_NAME = ["ebp", "esp"]
    OTHER_REGS = {}

    def return_force(self):
        ret = self[self["esp"]]
        self["esp"] += 4
        self["eip"] = int.from_bytes(ret, "little")
