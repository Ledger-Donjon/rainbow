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

from typing import List

from .interface import Interface, setup_qt


def viewer(instructions: List[str], *args, **kwargs) -> int:
    """Visplot with instruction list

    Build a Qt application showing the instruction list next to visplot.
    Clicking an instruction zooms on the corresponding point in the side-channel
    traces, and conversely.
    """
    app = setup_qt()
    _gui = Interface(instructions, *args, **kwargs)
    return app.exec_()
