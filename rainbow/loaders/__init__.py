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

import os
from .elfloader import elfloader
from .hexloader import hexloader
from .peloader import peloader

LOADERS = {".hex": hexloader, ".elf": elfloader, ".so": elfloader, ".exe": peloader}


def load_selector(filename, rainbow_instance, typ=None, entrypoint=None, verbose=False):
    if typ is None:
        ext = os.path.splitext(filename)[1]
        loader = LOADERS[ext]
    else:
        loader = LOADERS[typ]
    return loader(filename, rainbow_instance, verbose=verbose)
