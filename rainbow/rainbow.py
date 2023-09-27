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

import abc
import functools
import math
from enum import auto, Flag
from typing import Callable, Tuple, Optional, List, Dict, Set, Any
import capstone as cs
import unicorn as uc
from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.asm import NasmLexer
# TODO: Add note about colorama use. Call init in example code.
from unicorn import UcError

from .leakage_models import LeakageModel
from .utils import region_intersects, HookWeakMethod
from .utils.color_functions import color
from .loaders import load_selector


class Print(Flag):
    """Printing configuration."""
    Functions = auto()
    Registers = auto()
    Memory = auto()
    Code = auto()
    Faults = auto()


class TraceConfig:
    """Tracing configuration."""

    def __init__(self,
                 mem_address: Optional[LeakageModel] = None,
                 mem_value: Optional[LeakageModel] = None,
                 register: Optional[LeakageModel] = None,
                 instruction: bool = False,
                 ignored_registers: Optional[Set[str]] = None):
        self.mem_address = mem_address
        self.mem_value = mem_value
        self.register = register
        self.instructions = instruction
        self.ignored_registers = ignored_registers


class Rainbow(abc.ABC):
    """ Emulation base class """

    # Attrs
    breakpoints: Set[int]
    emu: Optional[uc.Uc]
    disasm: Optional[cs.Cs]
    reg_backup: List[int]
    functions: Dict[str, int]
    function_names: Dict[int, str]

    # Arch. constants
    UC_ARCH: int
    UC_MODE: int
    CS_ARCH: int
    CS_MODE: int
    WORD_SIZE: int
    REGS: Dict[str, int]
    OTHER_REGS: Dict[str, int]
    INTERNAL_REGS: List[str]
    IGNORED_REGS: List[str]
    STACK_ADDR: int
    STACK: Tuple[int, int]
    ENDIANNESS: str
    PC: int

    last_regs: Optional[List[str]]
    last_reg_values: Optional[Dict[str, int]]
    last_address: Optional[int]
    last_value: Optional[int]
    trace: List[Any]

    block_hook: Optional[int]
    mem_hook: Optional[int]
    code_hook: Optional[int]

    def __init__(self, print_config: Print = Print(0), trace_config: TraceConfig = TraceConfig(),
                 allow_breakpoints: bool = False, allow_stubs: bool = False):
        self.breakpoints = set()
        self.functions = {}
        self.function_names = {}
        self.stubbed_functions = {}

        # Tracing properties
        self.print_config = print_config
        self.trace_config = trace_config
        self.allow_breakpoints = allow_breakpoints
        self.allow_stubs = allow_stubs

        # Leak storage
        self.last_reg_values = {}
        self.last_regs = []
        self.last_value = 0
        self.last_address = 0
        self.trace = []

        # Prepare the formatters
        self.asm_hl = NasmLexer()
        self.asm_fmt = TerminalFormatter(outencoding="utf-8")

        # Prepare the emulator and disassembler
        self.emu = uc.Uc(self.UC_ARCH, self.UC_MODE)
        self.disasm = cs.Cs(self.CS_ARCH, self.CS_MODE)
        self.disasm.detail = True
        self.map_space(*self.STACK)

        self.reset_stack()

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
                return self.emu.reg_read(v)
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
            self.emu.emu_start(begin, end, timeout=timeout, count=count)
        except Exception as e:
            self.emu.emu_stop()
            pc = self.emu.reg_read(self.PC)
            raise RuntimeError(f"Emulation crashed at 0x{pc:X}") from e

    def start_and_fault(self, fault_model, fault_index: int, begin: int, end: int, *args, **kwargs) -> int:
        """Begin emulation but inject a fault at specified index

        This method takes the fault model and index, then the same arguments as
        rainbow.start(). It returns the memory address at which the fault was
        applied.

        Injection faults can often led to invalid instruction which are raised
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
        if self.print_config & Print.Faults:
            print(color("YELLOW", f" /!\\ {fault_model.__name__} /!\\ "), end="")

        # Emulation after fault
        self.start(self["pc"], end, *args, **kwargs)
        return pc_fault

    def setup(self):
        """Add base hooks to the engine."""
        # We need the block hook only if we are
        # printing functions or need to handle stubs.
        # if self.print_config & Print.Functions or self.allow_stubs:
        self.block_hook = self.emu.hook_add(uc.UC_HOOK_BLOCK,
                                            HookWeakMethod(self._block_hook))

        # We need the mem hook only if we are
        # printing memory or tracing memory values or addresses.
        if self.print_config & Print.Memory or self.trace_config.mem_value or self.trace_config.mem_address:
            self.mem_hook = self.emu.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                                              HookWeakMethod(self._mem_hook))

        # We need the code hook only if we are
        # printing code or registers, tracing registers or instruction or need to handle breakpoints.
        if self.print_config & (
                Print.Code | Print.Registers) or self.trace_config.register or self.trace_config.instructions or self.allow_breakpoints:
            self.code_hook = self.emu.hook_add(uc.UC_HOOK_CODE,
                                               HookWeakMethod(self._code_hook))

    def remove_bkpt(self, address):
        if not self.allow_breakpoints:
            raise ValueError("Cannot use breakpoints, allow_breakpoints is False.")
        self.breakpoints.remove(address)

    def add_bkpt(self, address):
        if not self.allow_breakpoints:
            raise ValueError("Cannot use breakpoints, allow_breakpoints is False.")
        self.breakpoints.add(address)

    @abc.abstractmethod
    def reset_stack(self):
        """Reset the stack pointer."""
        raise NotImplementedError

    def reset_regs(self):
        """Reset the state of the internal registers to zero."""
        for r in self.INTERNAL_REGS:
            self[r] = 0

    def reset_trace(self):
        """Reset the traced attributes."""
        self.last_reg_values.clear()
        self.last_regs = []
        self.last_value = 0
        self.last_address = 0
        self.trace = []

    @abc.abstractmethod
    def return_force(self):
        """Perform a simulated function return."""
        raise NotImplementedError

    def reset(self):
        """ Reset side-channel trace, zeroize registers and reset stack """
        self.reset_trace()
        self.reset_regs()
        self.reset_stack()

    # Least-recently used cache for Capstone calls to disasm or disasm_lite
    # TODO: Move to separate file with functions.
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

    def hook_prolog(self, name, fn):
        """
        Add a call to function 'fn' when 'name' is called during execution.
        After executing 'fn, execution resumes into 'name'.
        """
        if not self.allow_stubs:
            raise ValueError("Cannot use stubs, allow_stubs is False.")

        def to_hook(x):
            if fn is not None:
                fn(x)
            return False

        if isinstance(name, str):
            # Stub all function addresses matching this name
            addrs = [a for a, n in self.function_names.items() if n == name]
            if not addrs:
                raise IndexError(f"'{name}' could not be found.")
            for addr in addrs:
                self.stubbed_functions[addr] = to_hook
        elif isinstance(name, int):
            # Name is an address
            self.stubbed_functions[name] = to_hook
        else:
            raise TypeError("name should be function name or address")

    def hook_bypass(self, name, fn=None):
        """
        Add a call to function 'fn' when 'name' is called during execution.
        After executing 'fn', execution returns to the caller.
        """
        if not self.allow_stubs:
            raise ValueError("Cannot use stubs, allow_stubs is False.")

        def to_hook(x):
            if fn is not None:
                fn(x)
            return True

        if isinstance(name, str):
            # Stub all function addresses matching this name
            addrs = [a for a, n in self.function_names.items() if n == name]
            if not addrs:
                raise IndexError(f"'{name}' could not be found.")
            for addr in addrs:
                self.stubbed_functions[addr] = to_hook
        elif isinstance(name, int):
            # Name is an address
            self.stubbed_functions[name] = to_hook
        else:
            raise TypeError("name should be function name or address")

    def remove_hook(self, name):
        """Remove the hook."""
        if not self.allow_stubs:
            raise ValueError("Cannot use stubs, allow_stubs is False.")
        del self.stubbed_functions[name]

    def remove_hooks(self):
        """Remove the hooked functions."""
        if not self.allow_stubs:
            raise ValueError("Cannot use stubs, allow_stubs is False.")
        self.stubbed_functions = {}

    def _block_hook(self, _uci, address: int, _size, _):
        """
        Hook called on every jump to a basic block that checks if a known
        address+function is redefined in the user's python script and if so,
        calls that instead.
        """
        # Print function calls
        if address in self.function_names and (self.allow_stubs or self.print_config & Print.Functions):
            # Handle the function call printing
            f = self.function_names[address]
            if self.print_config & Print.Functions:
                print(f"{color('MAGENTA', f)}(...) @ 0x{address:x}")

        # If stub is enabled and set at this address, run it
        if self.allow_stubs:
            stub_func = self.stubbed_functions.get(address)
            if stub_func is not None:
                r = stub_func(self)
                if r:
                    # If stub returns True, then make the function return early
                    self.return_force()

    def _mem_hook(self, uci, access, address, size, value, _):
        # Get the value
        if access == uc.UC_MEM_READ:
            access_type = "mem_read"
            value = int.from_bytes(uci.mem_read(address, size), self.ENDIANNESS, signed=False)
        else:
            access_type = "mem_write"

        # Handle the mem addr/value printing
        if self.print_config & Print.Memory:
            if address in self.OTHER_REGS:
                addr = self.OTHER_REGS[address]
            else:
                addr = color("BLUE", f"0x{address:08x}")
            val = color("CYAN", f"{value:8x}")
            if access == uc.UC_MEM_WRITE:
                print(f"  [{addr}] <- {val} ", end=" ")
            else:
                print(f"  {val} <- [{addr}]", end=" ")

        # Handle the mem addr/value tracing
        ma = self.trace_config.mem_address
        mv = self.trace_config.mem_value
        if ma or mv:
            event = {"type": access_type}
            if ma:
                event["address"] = ma(address, self.last_address)
                self.last_address = address
            if mv:
                event["value"] = mv(value, self.last_value)
                self.last_value = value
            self.trace.append(event)

    def _code_hook(self, uci, address, size, _):
        # Handle the breakpoints
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

        # Handle the register printing
        ins = None
        regs = None
        if self.print_config & Print.Registers:
            if self.last_regs:
                for x in self.last_regs:
                    print(f" {x} = {self[x]:08x} ", end="")
            ins = self.disassemble_single_detailed(address, size)
            _, regs_written = ins.regs_access()
            if regs_written:
                regs = list(map(ins.reg_name, regs_written))  # type: ignore
            else:
                regs = None

        # Handle the code printing
        if self.print_config & Print.Code:
            if ins is None:
                adr, size, _ins, op_str = self.disassemble_single(address, size)
                self.print_asmline(adr, _ins, op_str)
            else:
                self.print_asmline(address, ins.mnemonic, ins.op_str)

        # Handle the register tracing
        event = None
        if self.trace_config.register:
            # This hook gets called before an instruction executes, so
            #  - regs are registers written by this instr, yet their values right now are not changed
            #  - reg_values are register values as they are now (after the previous instruction)
            #  - last_regs are registers written by the previous instruction
            #  - last_reg_values are register values as they were before the previous instruction
            #
            # So we need to go over last_regs, get their prev values from last_reg_values and get their current values.
            if self.last_regs:
                reg_values = {r: uci.reg_read(self.REGS[r]) for r in self.last_regs}
                leak = sum(
                    self.trace_config.register(reg_values[r], self.last_reg_values.get(r, 0)) for r in self.last_regs)
                event = {"type": "code", "register": leak}

                # Store the updated reg values into last_reg_values.
                for r, val in reg_values.items():
                    self.last_reg_values[r] = val

            # If we haven't disassembled the current instruction to store the regs written to last_regs we do it.
            if ins is None:
                ins = self.disassemble_single_detailed(address, size)
                _, regs_written = ins.regs_access()
                if regs_written:
                    regs = list(filter(lambda r: r not in self.IGNORED_REGS and (
                                not self.trace_config.ignored_registers or r not in self.trace_config.ignored_registers),
                                       map(ins.reg_name, regs_written)))  # type: ignore
                else:
                    regs = None

        if self.trace_config.instructions:
            if ins is None:
                ins = self.disassemble_single_detailed(address, size)
            if event is None:
                event = {"type": "code"}
            event["instruction"] = f"{ins.address:8X} {ins.mnemonic:<6}  {ins.op_str}"
        if event is not None:
            self.trace.append(event)
        self.last_regs = regs
