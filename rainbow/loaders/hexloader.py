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

from intelhex import IntelHex


def hexloader(hex_file, emu, verbose=False) -> None:
    """Load a intel hex file into emu's memory using IntelHex"""
    itx = IntelHex(hex_file)

    if verbose:
        print("[x] Loading HEX segments...")

    for s_start, s_end in itx.segments():
        data = itx.tobinstr(s_start, s_end - 1)
        emu.map_space(s_start, s_start + len(data), verbose=verbose)
        emu.emu.mem_write(s_start, data)

    return None
