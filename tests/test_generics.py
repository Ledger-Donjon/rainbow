import pytest
import unicorn
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


@pytest.mark.parametrize("rainbow_class", all_generics)
def test_init_start_del(rainbow_class):
    """Test creating, starting and destroying a rainbow instance"""
    if rainbow_class == rainbow_cortexm and unicorn.__version__.startswith("1."):
        pytest.skip("end of memory unmap bug with Unicorn 1")

    emu = rainbow_class()
    emu.start(0, 2)
    del emu
