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
import weakref
from typing import Tuple


def region_intersects(ra: Tuple[int, int], rb: Tuple[int, int]) -> bool:
    """
    :return: True if two given regions have non empty intersection.

    :param ra: First region bounds, both start and end included.
    :param rb: Second region bounds, both start and end included.
    """
    if not ((ra[1] >= ra[0]) and (rb[1] >= rb[0])):
        raise ValueError
    u = max(ra[0], rb[0])
    v = min(ra[1], rb[1])
    return v >= u


class HookWeakMethod:
    """
    Class to pass instance method callbacks to unicorn with weak referencing to
    prevent circular dependencies.

    Circular dependencies blocks the GC to clean the Rainbow at the correct
    time, and this causes memory troubles...

    We cannot use directly weakref.WeakMethod since __call__ does not execute
    the method, but returns it. This class does call the method when __call__
    is executed.
    """

    def __init__(self, method):
        self.method = weakref.WeakMethod(method)

    def __call__(self, *args, **kwargs):
        self.method()(*args, **kwargs)
