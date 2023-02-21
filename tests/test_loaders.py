from rainbow.generics import rainbow_arm, rainbow_x86


def test_elfloader_cortexm_aes():
    """Test loading CortexM_AES aes.bin

    This firmware does not contain segments.
    """
    emu = rainbow_arm()
    emu.load("examples/CortexM_AES/aes.bin", typ=".elf")


def test_elfloader_trezor():
    """Test loading HW_analysis trezor.elf with virtual segments mapped"""
    emu = rainbow_arm()
    emu.load("examples/HW_analysis/trezor.elf", map_virtual_segments=True)


def test_elfloader_trezor():
    """Test loading HW_analysis trezor.elf"""
    emu = rainbow_arm()
    emu.load("examples/HW_analysis/trezor.elf")


def test_hexloader_trezor():
    """Test loading HW_analysis trezor.hex"""
    emu = rainbow_arm()
    emu.load("examples/HW_analysis/trezor.hex")


def test_elfloader_hexloader_equal():
    """Test that loading HW_analysis trezor.elf and trezor.hex gives the same state"""
    emu1 = rainbow_arm()
    emu1.load("examples/HW_analysis/trezor.elf")
    emu2 = rainbow_arm()
    emu2.load("examples/HW_analysis/trezor.hex")
    assert list(emu1.emu.mem_regions()) == list(emu2.emu.mem_regions())
    for reg_start, reg_end, _ in emu1.emu.mem_regions():
        assert emu1[reg_start:reg_end] == emu2[reg_start:reg_end]


def test_peloader_hacklu2009():
    """Test loading hacklu2009 crackme.exe"""
    emu = rainbow_x86()
    emu.load("examples/hacklu2009/crackme.exe")

    # Load the plaintext into memory, the state is loaded column-wise
    plain = b"Df\xcc\xce\xd8H4\x91]\xa5\xb2\x0c\xc5P\xcc:"
    order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    for i, j in enumerate(order):
        emu[0xDEADBE00 + i] = plain[j]

    # the encryption function is identified at 0x401050
    # it takes its input parameter from stack+4
    emu[emu.STACK_ADDR + 4] = 0xDEADBE00
    emu.start(0x401050, 0, count=1000)
