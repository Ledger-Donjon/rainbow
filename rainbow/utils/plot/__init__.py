# This file is part of rainbow 
#
# PyPDM is free software: you can redistribute it and/or modify
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

from rainbow.utils.plot.interface import Interface


def viewer(disassembly, traces, highlight=None):
    """ A Viewer that synchronizes a view of an instruction trace with a view of side-channel traces. Clicking an instruction zooms on the corresponding point in the side-channel traces, and conversely. """

    from PyQt5 import QtWidgets as qt

    app_ = qt.QApplication([])

    gui = Interface(disassembly, traces, highlight)
    gui.show()

    return app_.exec_()
