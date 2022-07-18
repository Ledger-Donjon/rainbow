from rainbow.devices.stm32 import rainbow_stm32f215
from rainbow.fault_models import fault_skip, fault_stuck_at


def test_fault_skip():
    """Test trezor pin verification instruction skip"""
    emu = rainbow_stm32f215()
    emu.load("examples/HW_analysis/trezor.elf")

    # Setup reference pin and attempt
    emu[0x08008110 + 0x189] = b"1874\x00"
    emu[0xCAFECAFE] = b"0000\x00"

    # Skip a branch inside storage_containsPin
    emu["r0"] = 0xCAFECAFE
    emu["lr"] = 0xAAAAAAAA
    begin = emu.functions["storage_containsPin"]
    emu.start_and_fault(fault_skip, {}, 15, begin, 0xAAAAAAAA)

    # Check that the function returned a faulted value
    assert emu["r0"] == 0xCAFECAFE and emu["pc"] == 0xAAAAAAAA


def test_fault_stuck_at_zeros():
    """Test trezor pin verification skip using stuck at zeros model"""
    emu = rainbow_stm32f215()
    emu.load("examples/HW_analysis/trezor.elf")

    # Setup reference pin and attempt
    emu[0x08008110 + 0x189] = b"1874\x00"
    emu[0xCAFECAFE] = b"0000\x00"

    # Skip a branch inside storage_containsPin
    emu["r0"] = 0xCAFECAFE
    emu["lr"] = 0xAAAAAAAA
    begin = emu.functions["storage_containsPin"]
    emu.start_and_fault(fault_stuck_at, {}, 40, begin, 0xAAAAAAAA)

    # Check that the function returned a faulted value
    assert emu["r0"] == 0x1 and emu["pc"] == 0xAAAAAAAA


def test_fault_stuck_at_ones():
    """Test trezor pin verification skip using stuck at ones model"""
    emu = rainbow_stm32f215()
    emu.load("examples/HW_analysis/trezor.elf")

    # Setup reference pin and attempt
    emu[0x08008110 + 0x189] = b"1874\x00"
    emu[0xCAFECAFE] = b"0000\x00"

    # Skip a branch inside storage_containsPin
    emu["r0"] = 0xCAFECAFE
    emu["lr"] = 0xAAAAAAAA
    begin = emu.functions["storage_containsPin"]
    emu.start_and_fault(fault_stuck_at, {"value": 0xFFFFFFFF}, 2, begin, 0xAAAAAAAA)

    # Check that the function returned a faulted value
    assert emu["r0"] == 0x1 and emu["pc"] == 0xAAAAAAAA
