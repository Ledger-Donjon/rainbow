import pytest
from rainbow.generics import rainbow_x64


def test_hook_bypass_ctf2():
    emu = rainbow_x64()
    emu.load("tests/ledger_ctf2/ctf2", typ=".elf", except_missing_libs=False)
    emu.setup()

    def strtol(e):
        e["rax"] = 0

    emu[0xCAFE1000] = b"test"
    emu["rdx"] = 0xCAFE1000
    emu.hook_bypass("strtol", strtol)
    emu.start(0x00400CA9, 0x00400DC8)


def test_hook_bypass_ctf2_empty():
    emu = rainbow_x64()
    emu.load("tests/ledger_ctf2/ctf2", typ=".elf", except_missing_libs=False)
    emu.setup()

    emu[0xCAFE1000] = b"test"
    emu["rdx"] = 0xCAFE1000
    emu.hook_bypass("strtol")
    emu.start(0x00400CA9, 0x00400DC8)


def test_hook_bypass_missing_name():
    emu = rainbow_x64()
    emu.load("tests/ledger_ctf2/ctf2", typ=".elf", except_missing_libs=False)
    with pytest.raises(IndexError):
        emu.hook_bypass("strtol_blabla")


def test_hook_prolog_missing_name():
    emu = rainbow_x64()
    emu.load("tests/ledger_ctf2/ctf2", typ=".elf", except_missing_libs=False)

    def strtol(e):
        pass

    with pytest.raises(IndexError):
        emu.hook_prolog("strtol_blabla", strtol)


@pytest.mark.skip(reason="'strtol' is not mapped to the same place across platforms")
def test_remove_hooks():
    emu = rainbow_x64()
    emu.load("tests/ledger_ctf2/ctf2", typ=".elf", except_missing_libs=False)
    emu.setup()

    emu.hook_bypass("strtol")
    assert 0x1648c10 in emu.stubbed_functions
    emu.remove_hooks()
    assert 0x1648c10 not in emu.stubbed_functions
