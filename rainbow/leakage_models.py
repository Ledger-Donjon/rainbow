import abc
from typing import ClassVar, Literal


class LeakageModel(abc.ABC):
    num_args: ClassVar[int]

    @abc.abstractmethod
    def __call__(self, *args, **kwargs) -> int:
        raise NotImplementedError


class Identity(LeakageModel):
    num_args = 1

    def __call__(self, *args, **kwargs) -> int:
        return int(args[0])


class Bit(LeakageModel):
    num_args = 1

    def __init__(self, which: int):
        if which < 0:
            raise ValueError("which must be >= 0.")
        self.which = which
        self.mask = 1 << which

    def __call__(self, *args, **kwargs) -> Literal[0, 1]:
        return (int(args[0]) & self.mask) >> self.which  # type: ignore


class Slice(LeakageModel):
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
    num_args = 1

    def __call__(self, *args, **kwargs) -> int:
        return int(args[0]).bit_count()


class HammingDistance(LeakageModel):
    num_args = 2

    def __call__(self, *args, **kwargs) -> int:
        return (int(args[0]) ^ int(args[1])).bit_count()