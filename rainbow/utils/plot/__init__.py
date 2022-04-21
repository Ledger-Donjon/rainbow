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

from PyQt5 import QtWidgets as qt
from PyQt5 import QtGui as qtg

from .interface import Interface


def viewer(instructions: List[str], *args, **kwargs) -> int:
    """Visplot with instructions list

    Build a Qt application showing the instructions list next to visplot.
    Clicking an instruction zooms on the corresponding point in the side-channel
    traces, and conversely.
    """
    app = qt.QApplication([])

    # Dark theme
    app.setStyle(qt.QStyleFactory.create('Fusion'))
    palette = qtg.QPalette()
    palette.setColor(qtg.QPalette.Window, qtg.QColor(25, 25, 25))
    palette.setColor(qtg.QPalette.WindowText, qtg.QColor(240, 240, 240))
    palette.setColor(qtg.QPalette.Base, qtg.QColor(40, 40, 40))
    palette.setColor(qtg.QPalette.Text, qtg.QColor(200, 200, 200))
    palette.setColor(qtg.QPalette.Button, qtg.QColor(40, 40, 40))
    palette.setColor(qtg.QPalette.ButtonText, qtg.QColor(200, 200, 200))
    app.setPalette(palette)

    _gui = Interface(instructions, *args, **kwargs)
    return app.exec_()
