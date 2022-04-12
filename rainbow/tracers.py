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
import unicorn as uc

from .utils import hw


# Least-recently used cache for register access extraction
@functools.lru_cache(maxsize=4096)
def registers_accessed_by_instruction(insn: cs.CsInsn) -> Tuple[List[int], List[int]]:
    """Return read and written registers by a single instruction

    Registers are represented with Capstone identifiers which mostly maps to
    Unicorn identifiers.
    """
    return insn.regs_access()


def regs_hw_sum_trace(uci: uc.Uc, address: int, size: int, rbw):
    """Trace written registers Hamming weight

    For each instruction, this tracer sums the Hamming weight of all written
    registers.

    This tracer is hooked by default if sca_mode=True and sca_HD=False.
    You may hook it with Unicorn as an `uc.UC_HOOK_CODE` hook.
    """
    ins = rbw.reg_leak
    if ins is not None:
        # Find out which registers are modified
        _, regs_written = registers_accessed_by_instruction(ins)
        v = sum(hw(uci.reg_read(r)) for r in regs_written)

        rbw.sca_address_trace.append(f"{ins.address:8X} {ins.mnemonic:<6}  {ins.op_str}")
        rbw.sca_values_trace.append(v)

    # Information is stored to be used at the next instruction,
    # once the unicorn engine actually performed the current instruction.
    rbw.reg_leak = rbw.disassemble_single_detailed(address, size)


def regs_hd_sum_trace(uci: uc.Uc, address: int, size: int, rbw):
    """Trace written registers Hamming distance

    For each instruction, this tracer sums the Hamming distance of all written
    registers with their last value.

    You may filter out uninteresting register accesses using TRACE_DISCARD
    attribute.

    This tracer is hooked by default if sca_mode=True and sca_HD=True.
    You may hook it with Unicorn as an `uc.UC_HOOK_CODE` hook.
    """
    ins = rbw.reg_leak
    if ins is not None:
        # Find out which registers are modified
        _, regs_written = registers_accessed_by_instruction(ins)

        v = 0
        for r in regs_written:
            if r in rbw.TRACE_DISCARD:
                continue
            v += hw(rbw.RegistersBackup[r] ^ uci.reg_read(r))
            rbw.RegistersBackup[r] = uci.reg_read(r)

        rbw.sca_address_trace.append(f"{ins.address:8X} {ins.mnemonic:<6}  {ins.op_str}")
        rbw.sca_values_trace.append(v)

    # Information is stored to be used at the next instruction,
    # once the unicorn engine actually performed the current instruction.
    rbw.reg_leak = rbw.disassemble_single_detailed(address, size)


def wb_regs_trace(uci: uc.Uc, address: int, size: int, rbw):
    """Trace written registers value

    For each instruction, output one point per written register value.

    You may filter out uninteresting register accesses using TRACE_DISCARD
    attribute.
    """
    ins = rbw.reg_leak
    if ins is not None:
        # Find out which registers are modified
        _, regs_written = registers_accessed_by_instruction(ins)

        for r in regs_written:
            if r in rbw.TRACE_DISCARD:
                continue

            rbw.sca_address_trace.append(ins)
            rbw.sca_values_trace.append(uci.reg_read(r))

    # Information is stored to be used at the next instruction,
    # once the unicorn engine actually performed the current instruction.
    rbw.reg_leak = rbw.disassemble_single_detailed(address, size)
