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


def peloader(exe_file, emu, verbose=False):
    """Load a .exe file into emu's memory using LIEF"""
    pefile = lief.parse(exe_file)
    if verbose:
        print(f"[x] Loading .exe ...")

    imagebase = pefile.optional_header.imagebase
    for section in pefile.sections:
        if verbose:
            print(f"[=] Writing {section.name}")
        emu.map_space(
            imagebase + section.virtual_address,
            imagebase + section.virtual_address + section.size,
            verbose=verbose,
        )
        emu.emu.mem_write(imagebase + section.virtual_address, bytes(section.content))

    emu.functions = {}

    ## Handle relocations
    for r in pefile.relocations:
        if r.symbol.is_function:
            if r.symbol.value == 0:
                rsv = r.address - (r.address & 1)
            else:
                rsv = r.symbol.value - (r.symbol.value & 1)
            emu.functions[r.symbol.name] = rsv
            if verbose:
                print(f"Relocating {r.symbol.name} at {r.address:x} to {rsv:x}")
            emu[r.address] = rsv

    emu.function_names = {emu.functions[x]: x for x in emu.functions.keys()}
    return pefile.entrypoint
