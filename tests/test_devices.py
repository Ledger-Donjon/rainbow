import pytest
import random
from rainbow.devices import (
    rainbow_stm32,
    rainbow_stm32f215,
    rainbow_stm32l431,
)

all_devices = [
    rainbow_stm32,
    rainbow_stm32f215,
    rainbow_stm32l431,
]


@pytest.mark.parametrize("rainbow_class", all_devices)
def test_init_del(rainbow_class):
    """Test creating and destroying a rainbow instance"""
    emu = rainbow_class()
    del emu


@pytest.mark.parametrize("rainbow_class", all_devices)
def test_reset(rainbow_class):
    """Test rainbow instance reset"""
    emu = rainbow_class()
    emu.reset()


@pytest.mark.parametrize("rainbow_class", all_devices)
def test_init_start_del(rainbow_class):
    """Test creating, starting and destroying a rainbow instance"""
    emu = rainbow_class()
    emu.start(0, 2)
    del emu


def test_stm32_rng():
    """Test STM32 device random number generator

    This little program waits for RNG and generate a number in r6:
        00: 4803  ldr r0, [pc, #12]
        02: 4904  ldr r1, [pc, #16]
        04: 2201  movs r2, #1
        06: 46c0  nop
        08: 6806  ldr r6, [r0, #0]
        0a: 4216  tst r6, r2
        0c: d0fc  beq.n 8
        0e: 680e  ldr r6, [r1, #0]
        10: 50060804  // RNG_SR
        14: 50060808  // RNG_DR
    """
    ADDRESS = 0x10000
    CODE = (
        b"\x03\x48\x04\x49\x01\x22\xc0\x46\x06\x68\x16\x42\xfc\xd0\x0e\x68"
        b"\x04\x08\x06\x50\x08\x08\x06\x50"
    )
    random.seed(42)
    emu = rainbow_stm32f215()
    emu.emu.mem_write(ADDRESS, CODE)
    assert not emu.start(ADDRESS | 1, 0, count=8)
    assert emu["r6"] == 0xA3B1799D

    # Try to rerun the same code again with a different seed
    random.seed(64)
    assert not emu.start(ADDRESS | 1, 0, count=8)
    assert emu["r6"] == 0x79E58218
