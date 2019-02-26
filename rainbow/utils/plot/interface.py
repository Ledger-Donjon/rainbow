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

from PyQt5 import QtWidgets as qt
import PyQt5.QtCore as qtc
import numpy as np
from vispy import scene, color
from .plot import plot

import pkg_resources


class Interface(qt.QMainWindow):
    def __init__(self, instr, etraces, highlight=None):
        super().__init__()
        style_file = pkg_resources.resource_filename(__name__, "/styles.css")
        with open(style_file) as stylesheet:
            self.setStyleSheet(stylesheet.read())
        self.etraces = etraces
        self.instr = instr
        self.index = 0
        self.lim = len(instr)
        self.zone = None
        self.highlight = highlight
        self.color_map = color.get_colormap("viridis")
        self.add_widgets()
        self.place_widgets()

    def add_widgets(self):
        self.plot_ = plot(self.etraces, highlight=self.highlight, parent=self)
        self.instr_list = qt.QListWidget(self)
        self.instr_list.itemClicked.connect(self.instr_change_focus)
        self.instr_list.currentRowChanged.connect(self.rowchange)
        self.instr_list.addItems(self.instr)

    def rowchange(self, event):
        self.instr_change_focus(self.instr_list.currentItem())

    def instr_change_focus(self, item):
        self.index = self.instr_list.row(item)
        self.focus_change(self.index)

    def focus_change(self, r):
        if self.zone is not None:
            self.zone.parent = None
            self.zone = None
        coords = [
            (r - 0.2, self.etraces.max() + 1),
            (r - 0.2, self.etraces.min() - 1),
            (r + 0.2, self.etraces.min() - 1),
            (r + 0.2, self.etraces.max() + 1),
        ]
        self.zone = scene.visuals.Polygon(
            coords, color=color.Color("grey", alpha=0.7), parent=self.plot_.view.scene
        )
        self.plot_.view.camera.set_range(
            x=(r - 20, r + 20), y=(self.etraces.min(), self.etraces.max()), z=(0, 0)
        )

    def place_widgets(self):
        self.frame = qt.QFrame(self)
        self.setCentralWidget(self.frame)

        self.frame_layout = qt.QHBoxLayout(self.frame)

        self.plot_.canvas.connect(self.on_mouse_double_click)

        self.frame_layout.addWidget(self.instr_list)
        self.frame_layout.addWidget(self.plot_.canvas.native)

        self.showMaximized()

    def on_mouse_double_click(self, event):
        t = int(self.plot_.view.scene.transform.imap(event.pos)[0])

        self.instr_list.setCurrentRow(t)
        self.focus_change(t)
