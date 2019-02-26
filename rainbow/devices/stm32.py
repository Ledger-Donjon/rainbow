# This file is part of rainbow 
#
# PyPDM is free software: you can redistribute it and/or modify
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
import pickle

from binascii import hexlify

from rainbow.generics import rainbow_cortexm
from rainbow.color_functions import color


class rainbow_stm32f215(rainbow_cortexm):

    FLASH = (0x00000000, 0x1FFFFFFF)
    RAM = (0x20000000, 0x3FFFFFFF)
    FSMC = (0xA0000000, 0xBFFFFFFF)
    PERIPHERALS = (0x40000000, 0x5FFFFFFF)
    INTERNAL = (0xE0000000, 0xFFFFFFFF)
    STACK_ADDR = RAM[1]

    def __init__(self, trace=True, sca_mode=False, local_vars={}):
        super().__init__(trace, sca_mode)
        self.stubbed_functions = local_vars

        self.setup_step(sca_mode)

    def setup_step(self, sca_mode):
        import pkg_resources

        ## Get register dictionary (dumped from .svd file)
        if self.OTHER_REGS_NAMES is None:
            regs_pickle = pkg_resources.resource_filename(
                __name__, "/stm32f215.pickle")
            self.load_other_regs_from_pickle(regs_pickle)

        ## Map specific memory regions
        self.map_space(*self.FLASH)
        self.map_space(*self.RAM)
        self.map_space(*self.FSMC)
        self.map_space(*self.PERIPHERALS)
        self.map_space(*self.INTERNAL)


class rainbow_stm32l431(rainbow_cortexm):
    def __init__(self, trace=True, sca_mode=False, local_vars={}):
        super().__init__(trace, sca_mode)
        import pkg_resources
        regs_pickle = pkg_resources.resource_filename(
            __name__, '/stm32l4x1.pickle')
        self.load_other_regs_from_pickle(regs_pickle)
