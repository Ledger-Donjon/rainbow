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


import functools
import math
import weakref
from typing import Callable, Tuple
import capstone as cs
import colorama
import unicorn as uc
from pygments import highlight
from pygments.formatters import TerminalFormatter as formatter
from pygments.lexers import NasmLexer

from .color_functions import color
from .loaders import load_selector
from .tracers import regs_hd_sum_trace, regs_hw_sum_trace


class HookWeakMethod:
    """
    Class to pass instance method callbacks to unicorn with weak referencing to
    prevent circular dependencies.

    Circular dependencies blocks the GC to clean the rainbowBase at the correct
    time, and this causes memory troubles...

    We cannot use directly weakref.WeakMethod since __call__ does not execute
    the method, but returns it. This class does call the method when __call__
    is executed.
    """
    def __init__(self, method):
        self.method = weakref.WeakMethod(method)

    def __call__(self, *args, **kwargs):
        self.method()(*args, **kwargs)


class rainbowBase:

    """ Emulation base class """

    def __init__(self, trace=True, sca_mode=False,sca_HD=False):
        self.breakpoints = []
        self.skips = []
        self.emu = None
        self.disasm = None
        self.uc_reg = None
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

    def __del__(self):
        # Unmap all memory regions.
        for start, end, _ in self.emu.mem_regions():
            self.emu.mem_unmap(start, end - start + 1)

    def trace_reset(self):
        self.reg_leak = None
        self.sca_address_trace = []
        self.sca_values_trace = []

    # convenience function
    def map_space(self, a_, b_, verbose=False):
        """ Maps area into the unicorn emulator between a and b, or nothing if it was already mapped.
        Only completes missing portions if there is overlapping with a previously-mapped segment """
        regions = list(self.emu.mem_regions())
        if any(map(lambda x: a_ >= x[0] and b_ <= x[1], regions)):
            if verbose:
                print(f"[*] Did not map 0x{a_:X},0x{b_-a_:X} as it is already mapped")
            return

        if a_ == b_:
            return

        ## Align start and end addresses
        a = a_
        if a & (self.page_size - 1):
            a = (a >> self.page_shift) << self.page_shift
        remainder = a_ - a 
        b = b_ - a_ + remainder
        if b & (self.page_size - 1):
            b = ((b >> self.page_shift) << self.page_shift) + self.page_size
        b += a

        overlap = 0
        for r_start, r_end, _ in regions:
            # check for overlaps
            if a < r_start and r_start < b <= r_end+1:
                overlap = 1
                aa = a
                bb = r_end
                break
            elif r_end > a >= r_start-1 and b > r_end:
                overlap = 1
                aa = r_start
                bb = b
                break
            elif b == r_start:
                ## prepend
                overlap = 1
                aa = a 
                bb = r_end
                break
            elif a == r_end+1:
                ## append
                overlap = 1
                aa = r_start
                bb = b
                break

        if overlap == 0:
            aa = a
            bb = b

        base = aa
        size = bb - aa
        if size & (self.page_size - 1):
            size = ((size >> self.page_shift) << self.page_shift) + self.page_size

        data = None
        if overlap == 1:
            ## we want to extend an existing memory region
            ## so we unmap the oldest one and remap the
            ## new region
            size += r_end - r_start + 1
            ## need to save data before unmapping
            data = self.emu.mem_read(r_start, r_end-r_start+1)
            ret = self.emu.mem_unmap(r_start, r_end-r_start+1)
            if ret is not None:
                raise Exception(ret)

        if verbose:
            print(f"[*] Mapping 0x{base:X}-0x{base+size:X}")

        ret = self.emu.mem_map(base, size)
        if data is not None:
            self.emu.mem_write(r_start, bytes(data))
        if ret is not None:
            raise Exception(ret)

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
            raise Exception("Invalid range type for write: ", type(inp), inp)

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

    def _start(self, begin, end, timeout=None, count=None, verbose=True):
        """ Begin emulation """
        try:
            # Copy the original registers into the backup before starting the process
            # This is for the Hamming Distance leakage model
            self.RegistersBackup = [0]*len(self.reg_map)
            self.emu.emu_start(begin, end, timeout=timeout, count=count)
        except Exception as e:
            self.emu.emu_stop()
            if verbose:
                pc = self.emu.reg_read(uc.arm_const.UC_ARM_REG_PC)
                print(f"[*] Emulation crashed at 0x{pc:X}: {e}")
            return True
        return False

    def setup(self):
        """ Sets up a stack and adds base hooks to the engine """
        ## Add a stack
        self.map_space(*self.STACK)

        ## Add hooks
        self.block_hook = self.emu.hook_add(uc.UC_HOOK_BLOCK,
            HookWeakMethod(self.block_handler))
        if self.sca_mode:
            if self.sca_HD:
                self.ct_hook = self.emu.hook_add(uc.UC_HOOK_CODE,
                    regs_hd_sum_trace, self)
            else:
                self.ct_hook = self.emu.hook_add(uc.UC_HOOK_CODE,
                    regs_hw_sum_trace, self)
            self.tm_hook = self.emu.hook_add(
                uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                HookWeakMethod(self.sca_trace_mem))
        else:
            self.code_hook = self.emu.hook_add(uc.UC_HOOK_CODE,
                HookWeakMethod(self.code_trace))
            self.mem_access_hook = self.emu.hook_add( uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                HookWeakMethod(self.trace_mem))

    def remove_hooks(self):
        self.emu.hook_del(self.mem_access_hook)
        self.emu.hook_del(self.code_hook)
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

    # Least-recently used cache for Capstone calls to disasm or disasm_lite
    @staticmethod
    @functools.lru_cache(maxsize=4096)
    def _disassemble_cache(call: Callable, instruction: bytes, addr: int):
        return next(call(instruction, addr, 1))

    def disassemble_single(self, addr: int, size: int) -> Tuple[int, int, str, str]:
        """Disassemble a single instruction using Capstone lite

        This returns the address, size, mnemonic, and operands of the
        instruction at the specified address and size (in bytes).

        If you want more information, you should use disassemble_single_detailed
        method, but is 30% slower according to Capstone documentation.
        """
        insn = self.emu.mem_read(addr, size)
        return self._disassemble_cache(self.disasm.disasm_lite, bytes(insn), addr)

    def disassemble_single_detailed(self, addr: int, size: int) -> cs.CsInsn:
        """Disassemble a single instruction using Capstone"""
        insn = self.emu.mem_read(addr, 2 * size)
        return self._disassemble_cache(self.disasm.disasm, bytes(insn), addr)

    def print_asmline(self, adr, ins, op_str):
        """ Pretty-print assembly using pygments syntax highlighting """
        line = (
            highlight(f"{ins:<6}  {op_str:<20}", self.asm_hl, self.asm_fmt)
            .decode()
            .strip("\n")
        )
        print("\n" + color("YELLOW", f"{adr:8X}  ") + line, end=";")

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

                if s == '':
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

    def hook_prolog(self, name, fn):
        """ Add a call to function 'fn' when 'name' is called during execution. After executing 'fn, execution resumes into 'name' """
        if name not in self.functions.keys():
            raise Exception(f"'{name}' could not be found.")

        def to_hook(x):
            fn(x)
            return False 

        self.stubbed_functions[name] = to_hook 

    def hook_bypass(self, name, fn=None):
        """ Add a call to function 'fn' when 'name' is called during execution. After executing 'fn', execution returns to the caller """
        if name not in self.functions.keys():
            raise Exception(f"'{name}' could not be found.")

        if fn is None:
            fn = lambda x:x

        def to_hook(x):
            fn(x)
            return True 

        self.stubbed_functions[name] = to_hook 

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
