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


class rainbow_aarch64(Rainbow):
    ARCH_NAME = "aarch64"
    STACK_ADDR = 0x20000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = [f"x{i}" for i in range(30)]
    IGNORED_REGS = set()
    PC_NAME = "pc"
    SP_NAME = ["sp"]
    OTHER_REGS = {}

    def return_force(self):
        self["pc"] = self["lr"]
