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
# Copyright 2022 A Iooss, ANSSI

import cle


def cleloader(path: str, emu, arch=None, ld_path=(), verbose=False) -> None:
    """Load binary using CLE

    It will try to load their associated libraries and resolves imports.
    """
    if verbose:
        print(f"[+] Opening {path}")
    ld = cle.Loader(path, except_missing_libs=True, ld_path=ld_path, arch=arch)

    # Map memory
    if verbose:
        for obj in ld.all_objects:
            print(f"[ ] Mapping at 0x{obj.min_addr:08X}: {obj.binary_basename}")
    emu.map_space(ld.min_addr, ld.max_addr, verbose=verbose)
    for start_addr, backer in ld.memory.backers():
        emu.emu.mem_write(start_addr, bytes(backer))

    # Load symbols
    func_symbols = [s for s in ld.symbols if s.is_function]
    if verbose:
        print(f"[+] Loading {len(func_symbols)} functions symbol")
    for symbol in func_symbols:
        emu.functions[symbol.name] = symbol.rebased_addr
        emu.function_names.update({symbol.rebased_addr: symbol.name})
