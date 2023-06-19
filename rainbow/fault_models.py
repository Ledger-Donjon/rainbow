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
# Copyright 2022 Victor Servant, Ledger SAS
# Copyright 2022 Alexandre Iooss, Ledger SAS
# Copyright 2023 Jan Jancar

"""
This module is a collection of fault injection models.
A fault model is defined as a function that takes only a Rainbow instance as
argument, then updates the emulator state according to their model and returns
nothing.
"""
import unicorn as uc
from .rainbow import Rainbow, Print
from .utils.color_functions import color


def fault_skip(emu: Rainbow):
    """Increase program counter to skip current instruction

    Right now this only handles ARM emulation.
    """
    if emu.UC_ARCH != uc.UC_ARCH_ARM:
        raise NotImplementedError("Only ARM emulation is supported.")
    # Get current instruction size
    current_pc = emu["pc"]
    ins = emu.disassemble_single(current_pc, 4)
    if ins is None:
        raise RuntimeError("Skipping an invalid instruction")
    _, ins_size, _, _ = ins
    if emu.print_config & Print.Faults:
        print(
            "\n" + color("YELLOW", f"      --  instruction skip {current_pc:<8X}   "),
            end=";",
        )

    # Skip one instruction
    # Save and restore CPSR register as Unicorn changes its value
    cpsr = emu["cpsr"]
    emu["pc"] = current_pc + ins_size
    emu["cpsr"] = cpsr


def fault_stuck_at(value: int = 0):
    """Return a fault model that will inject `value` in current instruction
    destination register

    This will run current instruction and increase program counter.
    Right now this only handles ARM emulation.
    """

    def f(emu: Rainbow):
        if emu.UC_ARCH != uc.UC_ARCH_ARM:
            raise NotImplementedError("Only ARM emulation is supported.")
        # Get registers updated by current instruction
        current_pc = emu["pc"]
        ins = emu.disassemble_single_detailed(current_pc, 4)
        if ins is None:
            raise RuntimeError("Faulting an invalid instruction")
        _, regs_written = ins.regs_access()
        regs_written = map(ins.reg_name, regs_written)

        # We're stopped before executing the target instruction
        # so we step once and then inject the fault
        emu.start(current_pc, 0, count=1)

        # Inject the fault
        for reg_name in regs_written:
            if reg_name.lower() in ["cpsr", "pc", "lr"]:
                continue  # ignore

            emu[reg_name] = value
            break  # only fault one register, this could be improved later

    f.__name__ = f"fault_stuck_at_0x{value:X}"
    return f
