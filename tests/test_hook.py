import pytest
from rainbow.generics import rainbow_x64


def test_hook_bypass_ctf2():
    emu = rainbow_x64(allow_stubs=True)
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")
    emu.setup()

    def strtol(e):
        e["rax"] = 0

    emu[0xCAFE1000] = b"test"
    emu["rdx"] = 0xCAFE1000
    emu.hook_bypass("strtol", strtol)
    emu.start(0x00400CA9, 0x00400DC8)


def test_hook_bypass_ctf2_empty():
    emu = rainbow_x64(allow_stubs=True)
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")
    emu.setup()

    emu[0xCAFE1000] = b"test"
    emu["rdx"] = 0xCAFE1000
    emu.hook_bypass("strtol")
    emu.start(0x00400CA9, 0x00400DC8)


def test_hook_bypass_missing_name():
    emu = rainbow_x64(allow_stubs=True)
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")
    with pytest.raises(IndexError):
        emu.hook_bypass("strtol_blabla")


def test_hook_prolog_missing_name():
    emu = rainbow_x64(allow_stubs=True)
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")

    def strtol(e):
        pass

    with pytest.raises(IndexError):
        emu.hook_prolog("strtol_blabla", strtol)


def test_remove_hooks():
    emu = rainbow_x64(allow_stubs=True)
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")
    emu.setup()

    emu.hook_bypass("strtol")
    assert 0x1648c10 in emu.stubbed_functions
    emu.remove_hooks()
    assert 0x1648c10 not in emu.stubbed_functions
