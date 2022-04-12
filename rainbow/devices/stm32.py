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

import random

import unicorn as uc

from ..generics import rainbow_cortexm


class rainbow_stm32(rainbow_cortexm):
    """STM32 generic device

    STMicroelectronics STM32 shares most peripherals addresses accross the family.
    """

    RNG_BASE_ADDR = 0x50060800

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Map RNG peripheral (Random Number Generator)
        self.map_space(self.RNG_BASE_ADDR, self.RNG_BASE_ADDR + 0xb)
        self.emu.hook_add(
            uc.UC_HOOK_MEM_READ,
            self.rng_sr_read,
            begin=self.RNG_BASE_ADDR + 0x4,
            end=self.RNG_BASE_ADDR + 0x4,
        )
        self.emu.hook_add(
            uc.UC_HOOK_MEM_READ,
            self.rng_dr_read,
            begin=self.RNG_BASE_ADDR + 0x8,
            end=self.RNG_BASE_ADDR + 0x8,
        )

    def rng_sr_read(self, _uci, _access, address, _size, _value, _user_data):
        """Hook called before RNG status register is read"""
        self[address] = 0x1  # data ready

    def rng_dr_read(self, _uci, _access, address, _size, _value, _user_data):
        """Hook called before RNG data register is read

        Please feel free to override me to implement custom random values.
        """
        self[address] = random.randint(0, 2**32 - 1)


class rainbow_stm32f215(rainbow_stm32):
    FLASH = (0x00000000, 0x1FFFFFFF)
    RAM = (0x20000000, 0x3FFFFFFF)
    FSMC = (0xA0000000, 0xBFFFFFFF)
    PERIPHERALS = (0x40000000, 0x5FFFFFFF)
    INTERNAL = (0xE0000000, 0xFFFFFFFF)
    STACK_ADDR = RAM[1]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setup_step()

    def setup_step(self):
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


class rainbow_stm32l431(rainbow_stm32):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import pkg_resources
        regs_pickle = pkg_resources.resource_filename(
            __name__, "/stm32l4x1.pickle")
        self.load_other_regs_from_pickle(regs_pickle)
