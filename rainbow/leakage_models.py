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
# Copyright 2023 Jan Jancar

"""
This module implements some common leakage models, which
can be used to trace memory addresses, memory values or registers.
"""
import abc
from typing import ClassVar, Literal


class LeakageModel(abc.ABC):
    """
    A leakage model.
    """
    num_args: ClassVar[int]

    @abc.abstractmethod
    def __call__(self, *args, **kwargs) -> int:
        raise NotImplementedError


class Identity(LeakageModel):
    """
    An identity leakage model, leaks the value fully.
    """
    num_args = 1

    def __call__(self, *args, **kwargs) -> int:
        return int(args[0])


class Bit(LeakageModel):
    """
    A bit leakage model, leaks the selected bit (indexed from lsb).
    """
    num_args = 1

    def __init__(self, which: int):
        if which < 0:
            raise ValueError("which must be >= 0.")
        self.which = which
        self.mask = 1 << which

    def __call__(self, *args, **kwargs) -> Literal[0, 1]:
        return (int(args[0]) & self.mask) >> self.which  # type: ignore


class Slice(LeakageModel):
    """
    A slice leakage model, leaks a slice of the bits (indexed from lsb).
    """
    num_args = 1

    def __init__(self, begin: int, end: int):
        if begin > end:
            raise ValueError("begin must be <= than end.")
        self.begin = begin
        self.end = end
        self.mask = 0
        for i in range(begin, end):
            self.mask |= 1 << i

    def __call__(self, *args, **kwargs) -> int:
        return (int(args[0]) & self.mask) >> self.begin


class HammingWeight(LeakageModel):
    """
    A Hamming weight leakage model.
    """
    num_args = 1

    def __call__(self, *args, **kwargs) -> int:
        return int(args[0]).bit_count()


class HammingDistance(LeakageModel):
    """
    A Hamming distance leakage model, accepts two arguments, the hamming distance
    of which is computed.
    """
    num_args = 2

    def __call__(self, *args, **kwargs) -> int:
        return (int(args[0]) ^ int(args[1])).bit_count()
