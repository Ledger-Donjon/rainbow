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

"""
This module is a collection of fault injection models.
Each function updates the emulator state according to their model.
"""

from .rainbow import rainbowBase


def fault_skip(emu: rainbowBase):
    """Increase program counter to skip current instruction

    Right now this only handles ARM emulation.
    """
    # Get current instruction size
    current_pc = emu["pc"]
    ins = emu.disassemble_single(current_pc, 4)
    if ins is None:
        raise RuntimeError("Skipping an invalid instruction")
    _, ins_size, _, _ = ins

    # Skip one instruction
    emu["pc"] = current_pc + ins_size


def fault_stuck_at(emu: rainbowBase, value: int = 0):
    """Inject `value` in current instruction destination register

    This will run current instruction and increase program counter.
    Right now this only handles ARM emulation.
    """
    # Get registers updated by current instruction
    current_pc = emu["pc"]
    ins = emu.disassemble_single_detailed(current_pc, 4)
    if ins is None:
        raise RuntimeError("Faulting an invalid instruction")
    _, regs_written = ins.regs_access()
    regs_written = map(ins.reg_name, regs_written)

    # We're stopped before executing the target instruction
    # so we step once and then inject the fault
    thumb_bit = (emu["cpsr"] >> 5) & 1
    if emu.start(current_pc | thumb_bit, 0, count=1):
        return RuntimeError("Emulation crashed")

    # Inject the fault
    for reg_name in regs_written:
        if reg_name.lower() in ["cpsr", "pc", "lr"]:
            continue  # ignore

        emu[reg_name] = value
        break  # only fault one register, this could be improved later
