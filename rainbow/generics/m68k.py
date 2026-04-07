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
import archinfo

class ArchM64k(archinfo.ArchPcode):
    def __init__(self, endness=archinfo.Endness.BE):
        super().__init__("68000:BE:32:default")

    cs_arch = cs.CS_ARCH_M68K
    cs_mode = cs.CS_MODE_M68K_000
    uc_arch = uc.UC_ARCH_M68K
    uc_mode = 0
    uc_const = uc.m68k_const
    uc_prefix = "UC_M68K_"

archinfo.register_arch([r"m68k.*"], 32, archinfo.Endness.BE, ArchM64k)


class rainbow_m68k(Rainbow):
    ARCH_NAME = "m68k"
    STACK_ADDR = 0xB0000000
    STACK = (STACK_ADDR - 0x200, STACK_ADDR + 32)
    INTERNAL_REGS = [f"d{i}" for i in range(8)] + [f"a{i}" for i in range(8)] + ["pc"]
    IGNORED_REGS = set()
    PC_NAME = "pc"
    SP_NAME = ["a7"]
    OTHER_REGS = {}

    def return_force(self):
        ret = self[self["a7"]]
        self["a7"] += 4
        self["pc"] = int.from_bytes(ret, "big")
