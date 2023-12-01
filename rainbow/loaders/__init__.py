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
from typing import Optional

from .cleloader import cleloader
from .hexloader import hexloader

LOADERS = {".hex": hexloader, ".elf": cleloader, ".so": cleloader, ".exe": cleloader}


def load_selector(filename, rainbow_instance, typ=None, *args, **kwargs) -> Optional[int]:
    """Select the appropriate loader.

    Default to CLE loader if unknown as it has the most chance of succeeding.
    """
    typ = typ if typ is not None else os.path.splitext(filename)[1]
    loader = LOADERS.get(typ, cleloader)
    return loader(filename, rainbow_instance, *args, **kwargs)
