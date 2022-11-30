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


# Identity function
def _identity(x):
    return x


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

        # Calling colorama.init too many times without deinit may cause issues
        colorama.deinit()

    def trace_reset(self):
        self.reg_leak = None
        self.sca_address_trace = []
        self.sca_values_trace = []

    def __region_intersects(self, ra: Tuple[int, int], rb: Tuple[int, int]) -> bool:
        """
        :return: True if two given regions have non empty intersection.

        :param ra: First region bounds, both start and end included.
        :param rb: Second region bounds, both start and end included.
        """
        assert (ra[1] >= ra[0]) and (rb[1] >= rb[0])
        u = max(ra[0], rb[0])
        v = min(ra[1], rb[1])
        return v >= u

    def map_space(self, start, end, verbose=False):
        """
        Maps area into the unicorn emulator between start and end, or nothing if it was already mapped.
        Only completes missing portions if there is overlapping with a previously-mapped segment

        The region is defined by `[start, end]`, so the region size is `end - start + 1`.

        :param start: Region start address, included.
        :param end: Region end address, included.
        """
        if end < start:
            raise ValueError("Invalid region")

        regions = list(self.emu.mem_regions())

        # Return if already mapped
        if any(map(lambda x: start >= x[0] and end <= x[1], regions)):
            if verbose:
                print(
                    f"[*] Did not map 0x{start:X},0x{end-start+1:X} as it is already mapped"
                )
            return

        if start == end:
            return

        # Floor align start address
        start = (start >> self.page_shift) << self.page_shift

        # Ceil align end address
        if (end + 1) & (self.page_size - 1):
            end = (
                (((end + 1) >> self.page_shift) << self.page_shift) + self.page_size - 1
            )

        # List of overlapping or adjacent regions which must be merged.
        overlaps: list[Tuple[int, bytes]] = []
        for r_start, r_end, _ in regions:
            # Region [start, end] is augmented for intersection test to detect adjacency.
            if self.__region_intersects((start - 1, end + 1), (r_start, r_end)):
                r_size = r_end - r_start + 1
                data = self.emu.mem_read(r_start, r_size)
                self.emu.mem_unmap(r_start, r_size)
                overlaps.append((r_start, data))
                start = min(start, r_start)
                end = max(end, r_end)

        assert start & (self.page_size - 1) == 0
        assert (end + 1) & (self.page_size - 1) == 0

        if verbose:
            print(f"[*] Mapping 0x{start:X}-0x{end:X}")
        ret = self.emu.mem_map(start, end - start + 1)
        if ret is not None:
            raise Exception(ret)

        # Restore data of merged regions which have been unmapped
        for r_start, data in overlaps:
            self.emu.mem_write(r_start, bytes(data))

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

    def load(self, filename, *args, **kwargs):
        """ Load a file into the emulator's memory """
        return load_selector(filename, self, *args, **kwargs)

    def start(self, begin, end, timeout=0, count=0) -> None:
        """ Begin emulation """
        try:
            # Copy the original registers into the backup before starting the process
            # This is for the Hamming Distance leakage model
            self.RegistersBackup = [0]*len(self.reg_map)
            self.emu.emu_start(begin, end, timeout=timeout, count=count)
        except Exception as e:
            self.emu.emu_stop()
            pc = self.emu.reg_read(uc.arm_const.UC_ARM_REG_PC)
            raise RuntimeError(f"Emulation crashed at 0x{pc:X}") from e

    def start_and_fault(self, fault_model, fault_index: int, begin: int, end: int, *args, **kwargs) -> int:
        """Begin emulation but inject a fault at specified index

        This method takes the fault model and index, then the same arguments as
        rainbow.start(). It returns the memory address at which the fault was
        applied.

        Injection faults can often led to invalid instructions which are raised
        as exceptions during emulation.

        Example:
            Let's consider that we have a function that we can run with::

                emu.start(0x01010101, 0xAAAAAAAA)

            To fault the written register at the 3rd instruction to 0xFFFFFFFF::

                emu.start_and_fault(fault_stuck_at(0xFFFFFFFF), 2, 0x01010101, 0xAAAAAAAA)
        """
        kwargs_before = {**kwargs, "count": fault_index}
        if "count" in kwargs:
            kwargs["count"] -= fault_index
            if kwargs["count"] <= 0:
                raise IndexError("fault_index must be smaller than count")

        # Emulation before fault
        self.start(begin, end, *args, **kwargs_before)
        pc_fault = self['pc']
        if pc_fault // 2 == end // 2:
            raise IndexError("reached end of function before faulting")

        # PewPew!
        fault_model(self)
        if self.trace:
            print(color("YELLOW", f" /!\\ {fault_model.__name__} /!\\ "), end="")

        # Emulation after fault
        self.start(self["pc"], end, *args, **kwargs)
        return pc_fault

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

    def hook_prolog(self, id, fn: Callable) -> None:
        """Insert Python function `fn` before all functions identified by `id`

        `id` can be an address or a function name.
        """

        def to_hook(x):
            fn(x)
            return False

        if isinstance(id, str):
            addrs = [a for a, n in self.function_names.items() if n == id]
            if not addrs:
                raise IndexError(f"'{id}' could not be found.")
            for addr in addrs:
                self.stubbed_functions[addr] = to_hook
        elif isinstance(id, int):
            self.stubbed_functions[id] = to_hook
        else:
            raise TypeError("id should be function name or address")

    def hook_bypass(self, id, fn: Callable = _identity) -> None:
        """Replace all functions identified by `id` with Python function 'fn'

        Return to caller after 'fn'.
        `id` can be an address or a function name.
        `fn` can be None to skip function execution.
        """

        def to_hook(x):
            fn(x)
            return True

        if isinstance(id, str):
            addrs = [a for a, n in self.function_names.items() if n == id]
            if not addrs:
                raise IndexError(f"'{id}' could not be found.")
            for addr in addrs:
                self.stubbed_functions[addr] = to_hook
        elif isinstance(id, int):
            self.stubbed_functions[id] = to_hook
        else:
            raise TypeError("id should be function name or address")

    def return_force(self) -> None:
        """Performs a simulated function return"""
        raise NotImplementedError

    def block_handler(self, _uci, address: int, _size, _user_data) -> None:
        """Hook called on every jump to a basic block

        Print called function name if self.function_calls is True.
        Handle hooked functions.
        """
        # Print function calls
        if self.function_calls and address in self.function_names:
            f = self.function_names[address]
            print(
                f"\n[{self.profile_counter:>8} ins]   {color('MAGENTA',f)}(...) @ 0x{address:x}",
                end=" ",
            )
            self.profile_counter = 0

        # If stub is set at this address, run it
        stub_func = self.stubbed_functions.get(address)
        if stub_func is not None:
            if stub_func(self):
                # If stub returns True, then make the function return early
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
