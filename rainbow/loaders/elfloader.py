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

import lief


def elfloader(elf_file, emu, map_virtual_segments=False, verbose=False):
    """Load an .elf file into emu's memory using LIEF

    If `map_virtual_segments` is True, then segments such as `.bss` will be
    mapped even if their physical size are zero.
    """
    elffile = lief.parse(elf_file)
    if verbose:
        print(f"[x] Loading ELF segments...")

    if len(list(elffile.segments)) > 0:
        for segment in elffile.segments:
            # Only consider LOAD segments
            if segment.type != lief.ELF.SEGMENT_TYPES.LOAD:
                continue

            if map_virtual_segments:
                emu.map_space(
                    segment.virtual_address,
                    segment.virtual_address + segment.virtual_size,
                    verbose=verbose,
                )
                emu.emu.mem_write(segment.virtual_address, bytes(segment.content))
            else:
                emu.map_space(
                    segment.physical_address,
                    segment.physical_address + segment.physical_size,
                    verbose=verbose,
                )
                emu.emu.mem_write(segment.physical_address, bytes(segment.content))
    else:
        # if there are no segments, still attempt to map .text area
        section = elffile.get_section(".text")
        emu.map_space(
            section.virtual_address,
            section.virtual_address + section.size,
            verbose=verbose,
        )
        emu.emu.mem_write(section.virtual_address, bytes(section.content))

    # Handle relocations
    for r in elffile.relocations:
        if r.symbol.is_function:
            if r.symbol.value == 0:
                rsv = r.address
            else:
                rsv = r.symbol.value
            emu.functions[r.symbol.name] = rsv
            if verbose:
                print(f"Relocating {r.symbol.name} at {r.address:x} to {rsv:x}")
            emu[r.address] = rsv

    # lief > 0.10
    try:
        for f in elffile.exported_functions:
            tmpn = f.name
            c = 0
            while tmpn in emu.functions:
                c += 1
                tmpn = f.name + str(c)
            emu.functions[tmpn] = f.address
    except:
        pass

    ## TODO: when the ELF has relocated functions exported, LIEF fails on get_function_address
    for i in elffile.symbols:
        if i.type == lief.ELF.SYMBOL_TYPES.FUNC:
            try:
                tmpn = i.name
                addr = i.value
                if tmpn in emu.functions.keys():
                    if emu.functions[tmpn] != addr:
                        c = 0
                        while tmpn in emu.functions.keys():
                            c += 1
                            tmpn = i.name + str(c)
                        emu.functions[tmpn] = addr
                else:
                    emu.functions[tmpn] = addr
            except Exception as exc:
                if verbose:
                    print(exc)

    emu.function_names = {emu.functions[x]: x for x in emu.functions.keys()}
    return elffile.entrypoint
