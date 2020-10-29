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


import math
import os

import capstone as cs
import colorama
import lief
import unicorn as uc
from pygments import highlight
from pygments.formatters import TerminalFormatter as formatter
from pygments.lexers import NasmLexer

from rainbow.color_functions import color
from rainbow.loaders import load_selector


class rainbowBase:

    """ Emulation base class """

    def __init__(self, trace=True, sca_mode=False,sca_HD=False):
        self.breakpoints = []
        self.skips = []
        self.emu = None
        self.disasm = None
        self.uc_reg = None
        self.mapped_regions = []
        self.page_size = 0
        self.functions = {}
        self.function_names = {}
        self.profile_counter = 0

        self.OTHER_REGS = {}
        self.OTHER_REGS_NAMES = {}

        # Tracing properties
        self.trace = trace
        self.mem_trace = False
        self.function_calls = False
        self.trace_regs = False
        self.stubbed_functions = {}

        self.sca_mode = sca_mode

        ## Prepare a live disassembler
        self.asm_hl = NasmLexer()
        self.asm_fmt = formatter(outencoding="utf-8")

        colorama.init()

        self.trace_reset()

        # Take into account another leakage model
        self.sca_HD = sca_HD

    def trace_reset(self):
        self.reg_leak = None
        self.sca_address_trace = []
        self.sca_values_trace = []

    # convenience function
    def map_space(self, a, b, verbose=False):
        """ Maps area into the unicorn emulator between a and b, or nothing if it was already mapped.
        Only completes missing portions if there is overlapping with a previously-mapped segment """
        if any(map(lambda x: a >= x[0] and b <= x[1], self.mapped_regions)):
            if verbose:
                print(f"Did not map {a:x} {b-a:x} as it is already mapped.")
            return

        if a == b:
            return

        overlap = 0
        for r_start, r_end in self.mapped_regions:
            # check for overlaps
            if a < r_start and r_start < b <= r_end:
                overlap = 1
                aa = a
                bb = r_start
                break
            elif r_end > a >= r_start and b > r_end:
                overlap = 1
                aa = r_end
                bb = b
                break

        if overlap == 0:
            aa = a
            bb = b

        base = aa
        if base & (self.page_size - 1):
            base = (base >> self.page_shift) << self.page_shift
        remainder = aa - base
        size = bb - aa + remainder
        if size & (self.page_size - 1):
            size = ((size >> self.page_shift) << self.page_shift) + self.page_size

        if verbose:
            print(f"Mapping : {base:x} {size:x}")

        ret = self.emu.mem_map(base, size)
        if ret is not None:
            print(ret)
        self.mapped_regions.append((base, base + size))

    def __setitem__(self, inp, val):
        """ Sets a register, memory address or memory range to a value. Handles writing ints or bytes. 

        Examples :

         - Write 0x1234 to register r0

          emulator['r0'] = 0x1234  
          
         - Zero-out addresses 0x4000 to 0x4300
         
          emulator[0x4000:0x4300] = 0
         """

        ## convert value
        if isinstance(val, int):
            if val==0:
                length = 1
                value = bytes(1)
            else:
                length = math.ceil(val.bit_length() / 8)
                value = val.to_bytes(length, self.endianness)
        elif isinstance(val, bytes):
            length = len(val)
            value = val
        else:
            raise Exception("Unhandled value type", type(val))

        ret = None 
        if isinstance(inp, str):  # regname
            v = self.OTHER_REGS_NAMES.get(inp, None)
            if v is not None:
                ret = self.emu.mem_write(v, val.to_bytes(self.word_size, self.endianness))
            else:
                ret = self.emu.reg_write(self.reg_map[inp], val)
        elif isinstance(inp, int):
            self.map_space(inp, inp + length)
            ret = self.emu.mem_write(inp, value)
        elif isinstance(inp, slice):
            if inp.step is not None:
                return NotImplementedError
            self.map_space(inp.start, inp.stop)
            v = val.to_bytes(length, self.endianness)
            ret = self.emu.mem_write(inp.start, v*(inp.stop-inp.start))
        else:
            raise Exception("Invalid range type for write : ", type(inp), inp)

    def __getitem__(self, s):
        """ Reads from a register using its shortname, or from a memory address/region. """
        if isinstance(s, str):  # regname
            v = self.OTHER_REGS_NAMES.get(s, None)
            if v is not None:
                return self.emu[v]
            else:
                return self.emu.reg_read(self.reg_map[s])
        elif isinstance(s, int):
            if s & 3:
                size = 1
            else:
                size = self.word_size
            return self.emu.mem_read(s, size)
        if isinstance(s, slice):
            return self.emu.mem_read(s.start, s.stop - s.start)

    def load(self, filename, typ=None, verbose=False):
        """ Load a file into the emulator's memory """
        return load_selector(filename, self, typ, verbose=verbose)

    def _start(self, begin, end, timeout=None, count=None):
        """ Begin emulation """
        ret = 0
        try:
            # Copy the original registers into the backup before starting the process
            # This is for the Hamming Distance leakage model
            self.RegistersBackup = [0]*len(self.reg_map)
            ret = self.emu.emu_start(begin, end, timeout=timeout, count=count)
        except Exception as e:
            self.emu.emu_stop()
            return True
        return False

    def setup(self, sca_mode):
        """ Sets up a stack and adds base hooks to the engine """
        ## Add a stack
        self.map_space(*self.STACK)

        ## Add hooks
        self.mem_unmapped_hook = self.emu.hook_add(uc.UC_HOOK_MEM_UNMAPPED, self.unmapped_hook)
        self.block_hook = self.emu.hook_add(uc.UC_HOOK_BLOCK, self.block_handler)
        if sca_mode:
            if (self.sca_HD):
                self.ct_hook = self.emu.hook_add(uc.UC_HOOK_CODE, self.sca_code_traceHD)
            else:
                self.ct_hook = self.emu.hook_add(uc.UC_HOOK_CODE, self.sca_code_trace)
            self.tm_hook = self.emu.hook_add(
                uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, self.sca_trace_mem
            )
        else:
            self.code_hook = self.emu.hook_add(uc.UC_HOOK_CODE, self.code_trace)
            self.mem_access_hook = self.emu.hook_add( uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, self.trace_mem)

    def remove_hooks(self):
        self.emu.hook_del(self.mem_access_hook)
        self.emu.hook_del(self.code_hook)
        self.emu.hook_del(self.mem_unmapped_hook)
        self.emu.hook_del(self.block_hook)

    def add_bkpt(self, address):
        if address not in self.breakpoints:
            self.breakpoints += [address]

    def bkpt_dump(self):
        """ Dumps all regs when a breakpoint is hit """
        for reg in self.INTERNAL_REGS:
            print(f"{reg} : {self[reg]:x}")

    def reset(self):
        """ Reset side-channel trace, zeroize registers and reset stack """
        if self.sca_mode:
            self.trace_reset()
        for r in self.INTERNAL_REGS:
            self[r] = 0
        self.reset_stack()

    def sca_trace_mem(self, uci, access, address, size, value, user_data):
        """ Hook that stores memory accesses in side-channel mode. Stores read and written values """
        if self.mem_trace:
            if access == uc.UC_MEM_WRITE:
                self.sca_values_trace.append(value)
            else:
                self.sca_values_trace.append( int.from_bytes( uci.mem_read(address, size), self.endianness, signed=False))

    def trace_mem(self, uci, access, address, size, value, user_data):
        """ Hook that shows a visual trace of memory accesses in the form '[address written to] <- value written' or 'value read <- [address read]' """
        if self.mem_trace:
            if address in self.OTHER_REGS_NAMES.keys():
                addr = self.OTHER_REGS_NAMES[address]
            else:
                addr = color("BLUE", f"0x{address:08x}")
            if access == uc.UC_MEM_WRITE:
                val = color("CYAN", f"{value:x}")
                print(f"  [{addr}] <- {val} ", end=" ")
            else:
                val = int.from_bytes(uci.mem_read(address, size), self.endianness)
                val = color("CYAN", f"{val:8x}")
                print(f"  {val} <- [{addr}]", end=" ")

    def skip(self, address):
        """ Add an instruction to skip (unused) """
        if address not in self.skips:
            self.skips += [address]

    def disassemble_single(self, addr, size):
        """ Disassemble a single instruction at address """
        instruction = self.emu.mem_read(addr, size)
        return next(self.disasm.disasm_lite(bytes(instruction), addr, 1))

    def disassemble_single_detailed(self, addr, size):
        """ Disassemble a single instruction at addr """
        instruction = self.emu.mem_read(addr, 2 * size)
        return next(self.disasm.disasm(bytes(instruction), addr, 1))

    def print_asmline(self, adr, ins, op_str):
        """ Pretty-print assembly using pygments syntax highlighting """
        line = (
            highlight(f"{ins:<6}  {op_str:<20}", self.asm_hl, self.asm_fmt)
            .decode()
            .strip("\n")
        )
        print("\n" + color("YELLOW", f"{adr:8X}  ") + line, end=";")

    def sca_code_trace(self, uci, address, size, data):
        from .tracers import regs_hw_sum_trace
        regs_hw_sum_trace(self, address, size, data)
          
    def sca_code_traceHD(self, uci, address, size, data):
        """
        Hook that traces modified register values in side-channel mode.

        Capstone 4's 'regs_access' method is used to find out which registers are explicitly modified by an instruction.
        Once found, the information is stored in self.reg_leak to be stored at the next instruction, once the unicorn engine actually performed the current instruction.
        """
        if self.trace:
            if self.reg_leak is not None:
                for x in self.reg_leak[1]:
                    if x not in self.TRACE_DISCARD:
                        self.sca_address_trace.append(self.reg_leak[0])
                        self.sca_values_trace.append(self.RegistersBackup[self.reg_map[x]] ^ uci.reg_read(self.reg_map[x]))
                        self.RegistersBackup[self.reg_map[x]] = uci.reg_read(self.reg_map[x])

            self.reg_leak = None

            ins = self.disassemble_single_detailed(address, size)
            _regs_read, regs_written = ins.regs_access()
            if len(regs_written) > 0:
                self.reg_leak = (f"{address:8X} {ins.mnemonic:<6}  {ins.op_str}",list(map(ins.reg_name, regs_written))
                )

    def code_trace(self, uci, address, size, data):
        """ 
        Hook that traces modified register values in side-channel mode. 
        
        Capstone 4's 'regs_access' method is used to find out which registers are explicitly modified by an instruction. 
        Once found, the information is stored in self.reg_leak to be stored at the next instruction, once the unicorn engine actually performed the current instruction. 
        """
        self.profile_counter += 1
        if address in self.breakpoints:
            print(f"\n*** Breakpoint hit at 0x{address:x} ***")
            self.bkpt_dump()

            while True:
                s = input("Press Enter to continue, or Input an address and a size to display an address: ")

                if s is '':
                    break
                try:
                    address = eval("0x"+s.split(" ")[0])
                    size = eval(s.split(" ")[1])
                    print("Addr=%s, size=%d"%(hex(address), size), bytes(self[address:address+size]))
                except Exception as e:
                    print("Error:", e)
                    print("Usage: type \"DEAD0000 32\" for instance")
                    continue
        

        if self.trace:
            if self.reg_leak is not None:
                for x in self.reg_leak[1]:
                    print(f" {x} = {self[x]:08x} ", end="")

            if self.trace_regs:
                ins = self.disassemble_single_detailed(address, size)
                regs_read, regs_written = ins.regs_access()
                if len(regs_written) > 0:
                    self.reg_leak = (address, list(map(ins.reg_name, regs_written)))
                else:
                    self.reg_leak = None
                self.print_asmline(address, ins.mnemonic, ins.op_str)
            else:
                adr, size, ins, op_str = self.disassemble_single(address, size)
                self.print_asmline(adr, ins, op_str)

    def unmapped_hook(self, uci, access, address, size, value, user_data):
        """ Warns where the unicorn engine stopped on an unmapped access """
        uci.emu_stop()
        raise Exception(f"Unmapped fetch at 0x{address:x} (Emu stopped in {uci.reg_read(self.pc):x})")

    def return_force(self):
        """ Performs a simulated function return """
        raise NotImplementedError

    def block_handler(self, uci, address, size, user_data):
        """ Hook on every basic block """
        raise NotImplementedError

    def base_block_handler(self, address):
        """ 
        Hook called on every jump to a basic block that checks if a known address+function is redefined in the user's python script and if so, calls that instead 
        """
        if address in self.function_names.keys():
            f = self.function_names[address]
            if self.function_calls:
                print(f"\n[{self.profile_counter:>8} ins]   {color('MAGENTA',f)}(...) @ 0x{address:x}", end=" ")
                self.profile_counter = 0

            if f in self.stubbed_functions:
                r = self.stubbed_functions[f](self)
                if r:
                    self.return_force()

    def load_other_regs_from_pickle(self, filename):
        """
        Load OTHER_REGS and OTHER_REGS_NAMES from a dictionary in a pickle file.
        :param filename: pickle file path.
        """
        import pickle
        with open(filename, 'rb') as f:
            self.OTHER_REGS_NAMES = pickle.load(f)
        self.OTHER_REGS = {
            self.OTHER_REGS_NAMES[x]: x for x in self.OTHER_REGS_NAMES.keys()
        }
