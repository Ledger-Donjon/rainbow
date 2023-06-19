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

import random
import pickle
import importlib.resources

import unicorn as uc

from ..generics import rainbow_cortexm


class rainbow_stm32(rainbow_cortexm):
    """STM32 generic device

    STMicroelectronics STM32 shares most peripherals addresses across the family.
    """

    RNG_BASE_ADDR = 0x50060800

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Map RNG peripheral (Random Number Generator)
        self.map_space(self.RNG_BASE_ADDR, self.RNG_BASE_ADDR + 0xb)
        self.emu.hook_add(
            uc.UC_HOOK_MEM_READ,
            self._rng_sr_read,
            begin=self.RNG_BASE_ADDR + 0x4,
            end=self.RNG_BASE_ADDR + 0x4,
        )
        self.emu.hook_add(
            uc.UC_HOOK_MEM_READ,
            self._rng_dr_read,
            begin=self.RNG_BASE_ADDR + 0x8,
            end=self.RNG_BASE_ADDR + 0x8,
        )

    def _rng_sr_read(self, _uci, _access, address, _size, _value, _user_data):
        """Hook called before RNG status register is read"""
        self[address] = 0x1  # data ready

    def _rng_dr_read(self, _uci, _access, address, _size, _value, _user_data):
        """Hook called before RNG data register is read

        Please feel free to override me to implement custom random values.
        """
        self[address] = random.randint(0, 2 ** 32 - 1)

    def _load_other_regs(self, filename):
        """
        Load OTHER_REGS from a dictionary in a pickle file.
        :param filename: pickle file path.
        """
        with open(filename, 'rb') as f:
            self.OTHER_REGS = pickle.load(f)


class rainbow_stm32f215(rainbow_stm32):
    FLASH = (0x00000000, 0x1FFFFFFF)
    RAM = (0x20000000, 0x3FFFFFFF)
    FSMC = (0xA0000000, 0xBFFFFFFF)
    PERIPHERALS = (0x40000000, 0x5FFFFFFF)
    INTERNAL = (0xE0000000, 0xFFFFFFFF)
    STACK_ADDR = RAM[1]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Load register dictionary dumped from SVD file
        with importlib.resources.path(__package__, "stm32f215.pickle") as p:
            self._load_other_regs(p)

        # Map specific memory regions
        self.map_space(*self.FLASH)
        self.map_space(*self.RAM)
        self.map_space(*self.FSMC)
        self.map_space(*self.PERIPHERALS)
        self.map_space(*self.INTERNAL)


class rainbow_stm32l431(rainbow_stm32):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Load register dictionary dumped from SVD file
        with importlib.resources.path(__package__, "stm32l4x1.pickle") as p:
            self._load_other_regs(p)
