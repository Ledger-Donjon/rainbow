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
import abc
import functools
import math
from enum import auto, Flag
from typing import Callable, Tuple, Optional, List, Dict, Set
import capstone as cs
import unicorn as uc
from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.asm import NasmLexer
# TODO: Add note about colorama use. Call init in example code.
from unicorn import UcError

from .utils import region_intersects, HookWeakMethod
from .utils.color_functions import color
from .loaders import load_selector
from .tracers import regs_hd_sum_trace, regs_hw_sum_trace


class Print(Flag):
    Functions = auto()
    Registers = auto()
    Memory = auto()
    Code = auto()


class Trace(Flag):
    Addresses = auto()
    Registers = auto()
    Memory = auto()


class Rainbow(abc.ABC):
    """ Emulation base class """

    # Attrs
    breakpoints: Set[int]
    emu: Optional[uc.Uc]
    disasm: Optional[cs.Cs]
    reg_backup: List[int]
    functions: Dict[str, int]
    function_names: Dict[int, str]
    hooks: List[int]

    # Arch. constants
    UC_ARCH: int
    UC_MODE: int
    CS_ARCH: int
    CS_MODE: int
    WORD_SIZE: int
    REGS: Dict[str, int]
    OTHER_REGS: Dict[str, int]
    INTERNAL_REGS: List[str]
    STACK_ADDR: int
    STACK: Tuple[int, int]
    ENDIANNESS: str
    PC: int
    # TODO: Trace discard handling. Class attr vs dynamic stuff.

    reg_leak: Optional[Tuple[int, List[int]]]  # TODO: Consider changing.
    sca_address_trace: List[int]
    sca_values_trace: List[int]

    block_hook: Optional[int]
    ct_hook: Optional[int]

    def __init__(self, trace=True, sca_mode=False, sca_HD=False,
                 print_config: Print = Print(0), trace_config: Trace = Trace(0)):
        self.breakpoints = set()
        self.emu = None
        self.disasm = None
        self.reg_backup = []
        self.functions = {}
        self.function_names = {}
        self.stubbed_functions = {}
        self.hooks = []

        # Tracing properties
        self.print_config = print_config
        self.trace_config = trace_config
        self.trace = trace
        self.mem_trace = False
        self.function_calls = False
        self.trace_regs = False

        # Leak storage
        self.reg_leak = None
        self.sca_address_trace = []
        self.sca_values_trace = []

        # Take into account another leakage model
        self.sca_HD = sca_HD
        self.sca_mode = sca_mode

        # Prepare the formatters
        self.asm_hl = NasmLexer()
        self.asm_fmt = TerminalFormatter(outencoding="utf-8")

        # Prepare the emulator and disassembler
        self.emu = uc.Uc(self.UC_ARCH, self.UC_MODE)
        self.disasm = cs.Cs(self.CS_ARCH, self.CS_MODE)
        self.disasm.detail = True

        self.setup()

        self.reset_stack()

    def __del__(self):
        # Unmap all memory regions.
        for start, end, _ in self.emu.mem_regions():
            self.emu.mem_unmap(start, end - start + 1)

    @functools.cached_property
    def PAGE_SIZE(self) -> int:  # noqa
        return self.emu.query(uc.UC_QUERY_PAGE_SIZE)

    @property
    def PAGE_SHIFT(self) -> int:  # noqa
        return self.PAGE_SIZE.bit_length() - 1

    def map_space(self, start: int, end: int, verbose: bool = False):
        """
        Maps area into the unicorn emulator between start and end, or nothing if it was already mapped.
        Only completes missing portions if there is overlapping with a previously-mapped segment

        The region is defined by `[start, end]`, so the region size is `end - start + 1`.

        :param start: Region start address, included.
        :param end: Region end address, included.
        :param verbose: Whether to print mapping info.
        """
        if end < start:
            raise ValueError("Invalid region")

        regions = list(self.emu.mem_regions())

        # Return if already mapped
        if any(map(lambda x: start >= x[0] and end <= x[1], regions)):
            if verbose:
                print(
                    f"[*] Did not map 0x{start:X},0x{end - start + 1:X} as it is already mapped"
                )
            return

        if start == end:
            return

        # Floor align start address
        start = (start >> self.PAGE_SHIFT) << self.PAGE_SHIFT

        # Ceil align end address
        if (end + 1) & (self.PAGE_SIZE - 1):
            end = (
                    (((end + 1) >> self.PAGE_SHIFT) << self.PAGE_SHIFT) + self.PAGE_SIZE - 1
            )

        # List of overlapping or adjacent regions which must be merged.
        overlaps: list[Tuple[int, bytes]] = []
        for r_start, r_end, _ in regions:
            # Region [start, end] is augmented for intersection test to detect adjacency.
            if region_intersects((start - 1, end + 1), (r_start, r_end)):
                r_size = r_end - r_start + 1
                data = self.emu.mem_read(r_start, r_size)
                self.emu.mem_unmap(r_start, r_size)
                overlaps.append((r_start, data))
                start = min(start, r_start)
                end = max(end, r_end)

        if start & (self.PAGE_SIZE - 1) != 0:
            raise ValueError("Invalid region start.")
        if (end + 1) & (self.PAGE_SIZE - 1) != 0:
            raise ValueError("Invalid region end.")

        if verbose:
            print(f"[*] Mapping 0x{start:X}-0x{end:X}")

        try:
            self.emu.mem_map(start, end - start + 1)
        except UcError as e:
            raise ValueError from e

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

        # convert value
        if isinstance(val, int):
            if val == 0:
                length = 1
                value = bytes(1)
            else:
                length = math.ceil(val.bit_length() / 8)
                value = val.to_bytes(length, self.ENDIANNESS)
        elif isinstance(val, bytes):
            length = len(val)
            value = val
        else:
            raise Exception("Unhandled value type", type(val))

        if isinstance(inp, str):  # regname
            v = self.OTHER_REGS.get(inp, None)
            if v is not None:
                self.emu.mem_write(v, val.to_bytes(self.WORD_SIZE, self.ENDIANNESS))
            else:
                self.emu.reg_write(self.REGS[inp], val)
        elif isinstance(inp, int):
            self.map_space(inp, inp + length)
            self.emu.mem_write(inp, value)
        elif isinstance(inp, slice):
            if inp.step is not None:
                return NotImplementedError
            self.map_space(inp.start, inp.stop)
            v = val.to_bytes(length, self.ENDIANNESS)
            self.emu.mem_write(inp.start, v * (inp.stop - inp.start))
        else:
            raise Exception("Invalid range type for write: ", type(inp), inp)

    def __getitem__(self, s):
        """ Reads from a register using its shortname, or from a memory address/region. """
        if isinstance(s, str):  # regname
            v = self.OTHER_REGS.get(s, None)
            if v is not None:
                return self.emu[v]
            else:
                return self.emu.reg_read(self.REGS[s])
        elif isinstance(s, int):
            if s & 3:
                size = 1
            else:
                size = self.WORD_SIZE
            return self.emu.mem_read(s, size)
        if isinstance(s, slice):
            return self.emu.mem_read(s.start, s.stop - s.start)

    def load(self, filename, *args, **kwargs) -> Optional[int]:
        """ Load a file into the emulator's memory """
        return load_selector(filename, self, *args, **kwargs)

    def start(self, begin, end, timeout=0, count=0) -> None:
        """ Begin emulation """
        try:
            # Copy the original registers into the backup before starting the process
            # This is for the Hamming Distance leakage model
            self.reg_backup = [0] * len(self.REGS)
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
        # Add a stack
        self.map_space(*self.STACK)

        # Add hooks
        self.block_hook = self.emu.hook_add(uc.UC_HOOK_BLOCK,
                                            HookWeakMethod(self._block_trace))
        self.hooks.append(self.block_hook)

        if self.sca_mode:
            if self.sca_HD:
                self.ct_hook = self.emu.hook_add(uc.UC_HOOK_CODE,
                                                 regs_hd_sum_trace, self)

            else:
                self.ct_hook = self.emu.hook_add(uc.UC_HOOK_CODE,
                                                 regs_hw_sum_trace, self)
            self.hooks.append(self.ct_hook)
            if self.mem_trace:
                self.hooks.append(self.emu.hook_add(
                    uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                    HookWeakMethod(self._sca_trace_mem)))
        else:
            self.hooks.append(self.emu.hook_add(uc.UC_HOOK_CODE,
                                                HookWeakMethod(self._code_trace)))
            if self.mem_trace:
                self.hooks.append(self.emu.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                                                    HookWeakMethod(self._trace_mem)))

    def remove_bkpt(self, address):
        self.breakpoints.remove(address)

    def add_bkpt(self, address):
        self.breakpoints.add(address)

    @abc.abstractmethod
    def reset_stack(self):
        raise NotImplementedError

    def reset_regs(self):
        for r in self.INTERNAL_REGS:
            self[r] = 0

    def reset_trace(self):
        self.reg_leak = None
        self.sca_address_trace = []
        self.sca_values_trace = []

    @abc.abstractmethod
    def return_force(self):
        """ Performs a simulated function return """
        raise NotImplementedError

    def reset(self):
        """ Reset side-channel trace, zeroize registers and reset stack """
        self.reset_trace()
        self.reset_regs()
        self.reset_stack()

    def _sca_trace_mem(self, uci, access, address, size, value, _):
        """
        Hook that stores memory accesses in side-channel mode. Stores read and written values.
        """
        if access == uc.UC_MEM_WRITE:
            self.sca_values_trace.append(value)
        else:
            self.sca_values_trace.append(int.from_bytes(uci.mem_read(address, size), self.ENDIANNESS, signed=False))

    def _trace_mem(self, uci, access, address, size, value, _):
        """
        Hook that shows a visual trace of memory accesses in the form
        '[address written to] <- value written' or 'value read <- [address read]'
        """
        if address in self.OTHER_REGS:
            addr = self.OTHER_REGS[address]
        else:
            addr = color("BLUE", f"0x{address:08x}")
        if access == uc.UC_MEM_WRITE:
            val = color("CYAN", f"{value:x}")
            print(f"  [{addr}] <- {val} ", end=" ")
        else:
            val = int.from_bytes(uci.mem_read(address, size), self.ENDIANNESS)
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

    def _code_trace(self, _uci, address, size, _data):
        """
        Hook that traces modified register values in side-channel mode. 
        
        Capstone 4's 'regs_access' method is used to find out which registers
        are explicitly modified by an instruction. Once found, the information
        is stored in self.reg_leak to be stored at the next instruction, once
        the unicorn engine actually performed the current instruction.
        """
        if address in self.breakpoints:
            print(f"\n*** Breakpoint hit at 0x{address:x} ***")
            for reg in self.INTERNAL_REGS:
                print(f"{reg} : {self[reg]:x}")

            while True:
                s = input("Press Enter to continue, or Input an address and a size to display an address: ")

                if s == '':
                    break
                try:
                    address = eval("0x" + s.split(" ")[0])
                    size = eval(s.split(" ")[1])
                    print("Addr=%s, size=%d" % (hex(address), size), bytes(self[address:address + size]))
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
        """
        Add a call to function 'fn' when 'name' is called during execution.
        After executing 'fn, execution resumes into 'name'.
        """
        if name not in self.functions.keys():
            raise IndexError(f"'{name}' could not be found.")

        def to_hook(x):
            if fn is not None:
                fn(x)
            return False

        self.stubbed_functions[name] = to_hook

    def hook_bypass(self, name, fn=None):
        """
        Add a call to function 'fn' when 'name' is called during execution.
        After executing 'fn', execution returns to the caller.
        """
        if name not in self.functions.keys():
            raise IndexError(f"'{name}' could not be found.")

        def to_hook(x):
            if fn is not None:
                fn(x)
            return True

        self.stubbed_functions[name] = to_hook

    def remove_hook(self, name):
        """Remove the hook."""
        del self.stubbed_functions[name]

    def remove_hooks(self):
        """Remove the hooked functions."""
        self.stubbed_functions = {}

    def _block_trace(self, _uci, address: int, _size, _user_data):
        """
        Hook called on every jump to a basic block that checks if a known
        address+function is redefined in the user's python script and if so,
        calls that instead
        """
        if address in self.function_names.keys():
            f = self.function_names[address]
            if self.function_calls:
                print(f"\n {color('MAGENTA', f)}(...) @ 0x{address:x}", end=" ")

            if f in self.stubbed_functions:
                r = self.stubbed_functions[f](self)
                if r:
                    self.return_force()
