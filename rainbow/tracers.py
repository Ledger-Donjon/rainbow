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
# Copyright 2020 Victor Servant, Ledger SAS

import functools
from typing import List, Tuple
import capstone as cs

from .utils import hw


# Least-recently used cache for register access extraction
@functools.lru_cache(maxsize=4096)
def registers_accessed_by_instruction(insn: cs.CsInsn) -> Tuple[List[int], List[int]]:
    """Return read and written registers by a single instruction

    Registers are represented with Capstone identifiers which mostly maps to
    Unicorn identifiers.
    """
    return insn.regs_access()


def regs_hw_sum_trace(rbw, address: int, size: int, _data):
    """Trace written registers Hamming weight

    For each instruction, this tracer sums the Hamming weight of all written
    registers.

    This tracer is hooked by default if sca_mode=True and sca_HD=False.
    You may hook it with Unicorn as an `uc.UC_HOOK_CODE` hook.
    """
    ins = rbw.reg_leak
    if ins is not None:
        _, regs_written = registers_accessed_by_instruction(ins)
        v = sum(hw(rbw.emu.reg_read(r)) for r in regs_written)

        rbw.sca_address_trace.append(f"{ins.address:8X} {ins.mnemonic:<6}  {ins.op_str}")
        rbw.sca_values_trace.append(v)

    rbw.reg_leak = rbw.disassemble_single_detailed(address, size)


def wb_regs_trace(rbw, address, size, data):
    """One point per register value, and filter out uninteresting register accesses"""
    if rbw.reg_leak:
      ins = rbw.reg_leak[0]
      for reg in map(ins.reg_name, rbw.reg_leak[1]):
          if reg not in rbw.TRACE_DISCARD:
            rbw.sca_address_trace.append(ins)
            rbw.sca_values_trace.append(rbw.emu.reg_read(rbw.reg_map[reg]))

    rbw.reg_leak = None

    ins = rbw.disassemble_single_detailed(address, size)
    _regs_read, regs_written = registers_accessed_by_instruction(ins)
    if len(regs_written) > 0:
        rbw.reg_leak = (ins, regs_written)
