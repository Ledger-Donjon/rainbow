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

from xml.etree import ElementTree


def parse_svd(svdfile):
    """ Parse an .svd file for special register names and addresses into a dictionary """
    tree = ElementTree.parse(svdfile)
    root = tree.getroot()
    names = [e.tag for e in root]
    peripherals = root[names.index("peripherals")]
    r = {}
    for p in peripherals:
        d = {i.tag: i.text for i in p}
        basename = d.get("name")
        addr = d.get("baseAddress")
        names = [e.tag for e in p]
        if "registers" in names:
            registers = p[names.index("registers")]
            for reg in registers:
                dr = {i.tag: i.text for i in reg}
                name = dr.get("name")
                offs = dr.get("addressOffset")
                r[basename + "_" + name] = int(addr, 0) + int(offs, 0)
    return r
