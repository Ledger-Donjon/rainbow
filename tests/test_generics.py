import pytest
from rainbow.generics import (
    rainbow_aarch64,
    rainbow_arm,
    rainbow_cortexm,
    rainbow_m68k,
    rainbow_x64,
    rainbow_x86,
)

all_generics = [
    rainbow_aarch64,
    rainbow_arm,
    rainbow_cortexm,
    rainbow_m68k,
    rainbow_x64,
    rainbow_x86,
]


@pytest.mark.parametrize("rainbow_class", all_generics)
def test_init_del(rainbow_class):
    """Test creating and destroying a rainbow instance"""
    emu = rainbow_class()
    del emu


@pytest.mark.parametrize("rainbow_class", all_generics)
def test_reset(rainbow_class):
    """Test rainbow instance reset"""
    emu = rainbow_class()
    emu.reset()
