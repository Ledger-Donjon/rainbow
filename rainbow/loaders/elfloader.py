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


def elfloader(elf_file, emu, verbose=False):
    """ Load an .elf file into emu's memory using LIEF """
    elffile = lief.parse(elf_file)
    if verbose:
        print(f"[x] Loading .elf ...")

    if len(list(elffile.segments)) > 0:
        for segment in elffile.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                for section in segment.sections:
                    if verbose:
                        print(
                            f"[=] Writing {section.name} on {section.virtual_address:x} - {section.virtual_address+section.size:x}"
                        )
                    emu.map_space(
                        section.virtual_address, section.virtual_address + section.size
                    )
                    emu.emu.mem_write(section.virtual_address, bytes(section.content))
    else:
        # if there are no segments, still attempt to map .text area
        section = elffile.get_section(".text")
        if verbose:
            print(
                f"[=] Writing {section.name} on {section.virtual_address:x} - {section.virtual_address+section.size:x}"
            )
        emu.map_space(section.virtual_address, section.virtual_address + section.size)
        emu.emu.mem_write(section.virtual_address, bytes(section.content))

    ## Handle relocations
    for r in elffile.relocations:
        if r.symbol.is_function:
            if r.symbol.value == 0:
                rsv = r.address - (r.address & 1)
            else:
                rsv = r.symbol.value - (r.symbol.value & 1)
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
            emu.functions[tmpn] = (f.address >> 1) << 1
    except:
        pass

    ## TODO: when the ELF has relocated functions exported, LIEF fails on get_function_address
    for i in elffile.symbols:
        if i.type == lief.ELF.SYMBOL_TYPES.FUNC:
            try:
                tmpn = i.name
                addr = (i.value >> 1) << 1 # failsafe for arm thumb
                if emu.functions[tmpn] != addr:
                    c = 0
                    while tmpn in emu.functions.keys():
                        c += 1
                        tmpn = i.name + str(c)
                    emu.functions[tmpn] = addr
            except Exception as e:
                if verbose:
                    print(e, i)

    emu.function_names = {emu.functions[x]: x for x in emu.functions.keys()}
    return elffile.entrypoint
